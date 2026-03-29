package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"aegis/internal/policy"
)

type VMInstance struct {
	UUID           string
	FirecrackerPID int
	SocketPath     string
	VsockPath      string
	ScratchPath    string
	GuestCID       uint32
	IsPersistent   bool
	Network        *NetworkConfig
}

const scratchDir = "/tmp/aegis"

func resolveHomeDir() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

func NewVM(uuid string, workspaceID string, pol *policy.Policy, profile policy.ComputeProfile, assetsDir string) (*VMInstance, error) {
	var baseDir string
	if assetsDir != "" {
		baseDir = assetsDir
	} else {
		homeDir, err := resolveHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(homeDir, "aegis", "assets")
	}

	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}

	baseImage := filepath.Join(baseDir, "alpine-base.ext4")
	isPersistent := false
	var scratchPath string
	var err error
	if workspaceID != "" {
		scratchPath, err = GetOrCreateWorkspace(workspaceID, 256)
		if err != nil {
			return nil, fmt.Errorf("get workspace disk: %w", err)
		}
		isPersistent = true
	} else {
		scratchPath, err = CreateScratchDisk(uuid)
		if err != nil {
			return nil, fmt.Errorf("create scratch disk: %w", err)
		}
	}

	var networkCfg *NetworkConfig
	if pol != nil {
		networkCfg, err = SetupNetwork(uuid, pol.Network)
		if err != nil {
			return nil, fmt.Errorf("setup network: %w", err)
		}
	}

	socketPath := fmt.Sprintf("%s/fc-%s.sock", scratchDir, uuid)
	vsockPath := fmt.Sprintf("%s/vsock-%s.sock", scratchDir, uuid)
	kernelPath := filepath.Join(baseDir, "vmlinux")

	cmd := exec.Command("firecracker", "--api-sock", socketPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		if networkCfg != nil {
			_ = teardownNetwork(networkCfg)
		}
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	pid := cmd.Process.Pid

	vm := &VMInstance{
		UUID:           uuid,
		FirecrackerPID: pid,
		SocketPath:     socketPath,
		VsockPath:      vsockPath,
		ScratchPath:    scratchPath,
		IsPersistent:   isPersistent,
		Network:        networkCfg,
	}

	client := unixClient(socketPath)
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
		if i == 19 {
			return nil, fmt.Errorf("firecracker socket never appeared")
		}
	}

	if err := fcPUT(client, "http://localhost/machine-config", map[string]any{
		"vcpu_count":   profile.VCPUCount,
		"mem_size_mib": profile.MemoryMB,
	}); err != nil {
		return nil, fmt.Errorf("machine-config: %w", err)
	}

	bootArgs := "console=ttyS0 reboot=k panic=1 pci=off"
	if err := fcPUT(client, "http://localhost/boot-source", map[string]any{
		"kernel_image_path": kernelPath,
		"boot_args":         bootArgs,
	}); err != nil {
		return nil, fmt.Errorf("boot-source: %w", err)
	}

	if err := fcPUT(client, "http://localhost/drives/rootfs", map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   baseImage,
		"is_root_device": true,
		"is_read_only":   true,
	}); err != nil {
		return nil, fmt.Errorf("drives/rootfs: %w", err)
	}

	if err := fcPUT(client, "http://localhost/drives/scratch", map[string]any{
		"drive_id":       "scratch",
		"path_on_host":   scratchPath,
		"is_root_device": false,
		"is_read_only":   false,
	}); err != nil {
		return nil, fmt.Errorf("drives/scratch: %w", err)
	}

	if networkCfg != nil {
		if err := fcPUT(client, "http://localhost/network-interfaces/eth0", map[string]any{
			"iface_id":      "eth0",
			"guest_mac":     networkCfg.GuestMAC,
			"host_dev_name": networkCfg.TapName,
		}); err != nil {
			return nil, fmt.Errorf("network-interfaces/eth0: %w", err)
		}
	}

	const guestCID uint32 = 3
	if err := fcPUT(client, "http://localhost/vsock", map[string]any{
		"guest_cid": guestCID,
		"uds_path":  vsockPath,
	}); err != nil {
		return nil, fmt.Errorf("vsock: %w", err)
	}

	if err := fcPUT(client, "http://localhost/entropy", map[string]any{}); err != nil {
		log.Printf("[%s] warning: failed to attach entropy device: %v", uuid, err)
	}

	if err := fcPUT(client, "http://localhost/actions", map[string]any{
		"action_type": "InstanceStart",
	}); err != nil {
		return nil, fmt.Errorf("InstanceStart: %w", err)
	}

	vm.GuestCID = guestCID
	return vm, nil
}

func (vm *VMInstance) Kill() error {
	proc, err := os.FindProcess(vm.FirecrackerPID)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGKILL)
}

func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func fcPUT(client *http.Client, url string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return nil
}

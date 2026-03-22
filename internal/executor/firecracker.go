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
	"syscall"
	"time"
)

type VMInstance struct {
	UUID           string
	FirecrackerPID int
	SocketPath     string
	VsockPath      string
	ScratchPath    string
	GuestCID       uint32
}

const scratchDir = "/tmp/aegis"

// resolveHomeDir returns the home directory of the invoking user.
// When running under sudo, os.UserHomeDir() returns /root. This checks
// SUDO_USER first so asset paths resolve to the original user's home.
func resolveHomeDir() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

func NewVM(uuid string) (*VMInstance, error) {
	homeDir, err := resolveHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}

	baseImage := fmt.Sprintf("%s/aegis/assets/alpine-base.ext4", homeDir)
	scratchPath, err := CreateScratchDisk(uuid)
	if err != nil {
		return nil, fmt.Errorf("create scratch disk: %w", err)
	}

	socketPath := fmt.Sprintf("%s/fc-%s.sock", scratchDir, uuid)
	vsockPath := fmt.Sprintf("%s/vsock-%s.sock", scratchDir, uuid)
	kernelPath := fmt.Sprintf("%s/aegis/assets/vmlinux", homeDir)

	cmd := exec.Command("firecracker", "--api-sock", socketPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	pid := cmd.Process.Pid

	vm := &VMInstance{
		UUID:           uuid,
		FirecrackerPID: pid,
		SocketPath:     socketPath,
		VsockPath:      vsockPath,
		ScratchPath:    scratchPath,
	}

	client := unixClient(socketPath)

	// Wait for socket to appear
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
		if i == 19 {
			return nil, fmt.Errorf("firecracker socket never appeared")
		}
	}

	// PUT /machine-config
	if err := fcPUT(client, "http://localhost/machine-config", map[string]any{
		"vcpu_count":   1,
		"mem_size_mib": 128,
	}); err != nil {
		return nil, fmt.Errorf("machine-config: %w", err)
	}

	// PUT /boot-source
	if err := fcPUT(client, "http://localhost/boot-source", map[string]any{
		"kernel_image_path": kernelPath,
		"boot_args":         "console=ttyS0 reboot=k panic=1 pci=off",
	}); err != nil {
		return nil, fmt.Errorf("boot-source: %w", err)
	}

	// PUT /drives/rootfs
	if err := fcPUT(client, "http://localhost/drives/rootfs", map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   baseImage,
		"is_root_device": true,
		"is_read_only":   true,
	}); err != nil {
		return nil, fmt.Errorf("drives/rootfs: %w", err)
	}

	// PUT /drives/scratch
	if err := fcPUT(client, "http://localhost/drives/scratch", map[string]any{
		"drive_id":       "scratch",
		"path_on_host":   scratchPath,
		"is_root_device": false,
		"is_read_only":   false,
	}); err != nil {
		return nil, fmt.Errorf("drives/scratch: %w", err)
	}

	// PUT /vsock - Firecracker has no GET /vsock endpoint; use the CID we configure.
	const guestCID uint32 = 3
	if err := fcPUT(client, "http://localhost/vsock", map[string]any{
		"guest_cid": guestCID,
		"uds_path":  vsockPath,
	}); err != nil {
		return nil, fmt.Errorf("vsock: %w", err)
	}

	// PUT /entropy - virtio-rng device feeds host entropy into guest pool.
	if err := fcPUT(client, "http://localhost/entropy", map[string]any{}); err != nil {
		log.Printf("[%s] warning: failed to attach entropy device: %v", uuid, err)
	}

	// PUT /actions - InstanceStart
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

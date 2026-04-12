package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aegis/internal/observability"
	"aegis/internal/policy"
	"aegis/internal/telemetry"
)

type VMInstance struct {
	UUID           string
	CgroupID       string
	FirecrackerPID int
	SocketPath     string
	VsockPath      string
	ScratchPath    string
	SerialLogPath  string
	GuestCID       uint32
	IsPersistent   bool
	Network        *NetworkConfig
	Cleanup        telemetry.CleanupDoneData
}

const scratchDir = "/tmp/aegis"

func resolveFirecrackerBinary() string {
	if bin := strings.TrimSpace(os.Getenv("AEGIS_FIRECRACKER_BIN")); bin != "" {
		return bin
	}
	return "firecracker"
}

func resolveRootfsImage(baseDir string, explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("stat rootfs image %s: %w", explicit, err)
		}
		return explicit, nil
	}
	if envPath := os.Getenv("AEGIS_ROOTFS_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err != nil {
			return "", fmt.Errorf("stat rootfs image %s: %w", envPath, err)
		}
		return envPath, nil
	}
	defaultPath := filepath.Join(baseDir, "alpine-base.ext4")
	if _, err := os.Stat(defaultPath); err != nil {
		return "", fmt.Errorf("stat rootfs image %s: %w", defaultPath, err)
	}
	return defaultPath, nil
}

func resolveHomeDir() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

func resolveAssetsDir(assetsDir string) (string, error) {
	if assetsDir != "" {
		return assetsDir, nil
	}
	homeDir, err := resolveHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(homeDir, "aegis", "assets"), nil
}

func emitIfBus(bus *telemetry.Bus, kind string, data interface{}) {
	if bus != nil {
		bus.Emit(kind, data)
	}
}

func resolveMemoryMB(profile policy.ComputeProfile) int {
	if raw := strings.TrimSpace(os.Getenv("AEGIS_VM_MEMORY_MB")); raw != "" {
		if memoryMB, err := strconv.Atoi(raw); err == nil && memoryMB > 0 {
			return memoryMB
		}
	}
	return profile.MemoryMB
}

func NewVM(uuid string, workspaceID string, pol *policy.Policy, profile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*VMInstance, error) {
	baseDir, err := resolveAssetsDir(assetsDir)
	if err != nil {
		return nil, err
	}
	emitIfBus(bus, telemetry.KindVMBootStart, map[string]string{})

	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}
	if err := os.Chmod(scratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod scratch dir: %w", err)
	}

	rootfsPath, err = resolveRootfsImage(baseDir, rootfsPath)
	if err != nil {
		return nil, err
	}
	isPersistent := false
	var scratchPath string
	if workspaceID != "" {
		scratchPath, err = GetWorkspace(workspaceID)
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
		networkCfg, err = SetupNetwork(uuid, pol.Network, bus)
		if err != nil {
			return nil, fmt.Errorf("setup network: %w", err)
		}
	}

	socketPath := fmt.Sprintf("%s/fc-%s.sock", scratchDir, uuid)
	vsockPath := fmt.Sprintf("%s/vsock-%s.sock", scratchDir, uuid)
	kernelPath := filepath.Join(baseDir, "vmlinux")

	cmd := exec.Command(resolveFirecrackerBinary(), "--api-sock", socketPath)
	cmd.Env = []string{}
	serialLogPath := fmt.Sprintf("%s/serial-%s.log", scratchDir, uuid)
	serialLog, _ := os.OpenFile(serialLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	cmd.Stdout = serialLog
	cmd.Stderr = serialLog
	if err := cmd.Start(); err != nil {
		if networkCfg != nil {
			_ = teardownNetwork(networkCfg)
		}
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	pid := cmd.Process.Pid

	observability.Info("rootfs_selected", observability.Fields{"execution_id": uuid, "rootfs_path": rootfsPath})

	vm := &VMInstance{
		UUID:           uuid,
		CgroupID:       uuid,
		FirecrackerPID: pid,
		SocketPath:     socketPath,
		VsockPath:      vsockPath,
		ScratchPath:    scratchPath,
		SerialLogPath:  serialLogPath,
		IsPersistent:   isPersistent,
		Network:        networkCfg,
	}

	memoryMB := resolveMemoryMB(profile)
	if memoryMB != profile.MemoryMB {
		observability.Info("vm_memory_override", observability.Fields{"execution_id": uuid, "profile_memory_mb": profile.MemoryMB, "effective_memory_mb": memoryMB})
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
		"mem_size_mib": memoryMB,
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
		"path_on_host":   rootfsPath,
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
		observability.Warn("entropy_device_attach_failed", observability.Fields{"execution_id": uuid, "error": err.Error()})
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
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

func PauseVM(ctx context.Context, vm *VMInstance) error {
	return fcPatchVM(ctx, vm.SocketPath, "Paused")
}

func ResumeVM(ctx context.Context, vm *VMInstance) error {
	return fcPatchVM(ctx, vm.SocketPath, "Resumed")
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

func fcPatchVM(ctx context.Context, socketPath string, state string) error {
	b, err := json.Marshal(map[string]string{"state": state})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, "http://localhost/vm", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := unixClient(socketPath).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from /vm state=%s", resp.StatusCode, state)
	}
	return nil
}

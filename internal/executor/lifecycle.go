package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	cgroupRoot   = "/sys/fs/cgroup"
	cgroupParent = "/sys/fs/cgroup/aegis"
)

func SetupCgroup(uuid string, pid int) error {
	// Ensure controllers are delegated from root → aegis → child.
	// In cgroup v2, controllers must be listed in the parent's
	// cgroup.subtree_control before child cgroups can use them.
	// Ignore errors here — the controller may already be enabled.
	_ = os.WriteFile(cgroupRoot+"/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0o644)

	if err := os.MkdirAll(cgroupParent, 0o755); err != nil {
		return fmt.Errorf("create aegis cgroup parent: %w", err)
	}
	if err := os.WriteFile(cgroupParent+"/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0o644); err != nil {
		return fmt.Errorf("enable controllers in aegis parent: %w", err)
	}

	cgPath := fmt.Sprintf("%s/%s", cgroupParent, uuid)
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		return fmt.Errorf("create cgroup dir: %w", err)
	}

	// Set resource limits BEFORE assigning the PID.
	limits := []struct {
		file  string
		value string
	}{
		{"memory.max", "128M"},
		{"memory.high", "64M"},
		{"pids.max", "100"},
		{"cpu.max", "50000 100000"},
		{"memory.swap.max", "0"},
	}
	for _, w := range limits {
		path := filepath.Join(cgPath, w.file)
		if err := os.WriteFile(path, []byte(w.value), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", w.file, err)
		}
	}

	// Assign PID last — process now runs under the limits.
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write cgroup.procs: %w", err)
	}
	return nil
}

func Teardown(vm *VMInstance) error {
	var errs []error

	// 1. Kill VM
	if err := vm.Kill(); err != nil {
		log.Printf("teardown [%s]: kill: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: killed firecracker pid %d", vm.UUID, vm.FirecrackerPID)
	}

	// 2. Remove scratch ext4
	if err := os.Remove(vm.ScratchPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove scratch: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed scratch image", vm.UUID)
	}

	// 3. Remove firecracker socket
	if err := os.Remove(vm.SocketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove fc socket: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed fc socket", vm.UUID)
	}

	// 4. Remove vsock socket
	if err := os.Remove(vm.VsockPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove vsock socket: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed vsock socket", vm.UUID)
	}

	// 5. Retry rmdir cgroup — kernel removes the PID from cgroup.procs when the
	// process exits, but SIGKILL delivery and process reaping take a few ms.
	// Retry for up to 500ms before giving up.
	cgPath := fmt.Sprintf("%s/%s", cgroupParent, vm.UUID)
	cgRemoved := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := os.Remove(cgPath); err == nil || os.IsNotExist(err) {
			log.Printf("teardown [%s]: removed cgroup", vm.UUID)
			cgRemoved = true
			break
		}
	}
	if !cgRemoved {
		err := fmt.Errorf("cgroup dir still busy after retries: %s", cgPath)
		log.Printf("teardown [%s]: %v", vm.UUID, err)
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown had %d error(s), first: %w", len(errs), errs[0])
	}
	return nil
}

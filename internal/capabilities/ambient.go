//go:build linux

package capabilities

import (
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

var capabilityNumbers = map[string]int{
	"cap_net_bind_service": unix.CAP_NET_BIND_SERVICE,
	"cap_net_admin":        unix.CAP_NET_ADMIN,
	"cap_net_raw":          unix.CAP_NET_RAW,
}

// RaiseAmbient raises the specified Linux capabilities into the ambient
// capability set for the current process. Ambient capabilities are inherited by
// child processes across execve, unlike file capabilities which do not
// propagate.
//
// This must be called before any child process is spawned.
// It is a no-op on non-Linux platforms and returns nil in that case.
//
// Requires that the calling process already has the capabilities in its
// permitted and inheritable sets — typically via file capabilities set with
// `setcap`.
func RaiseAmbient(caps []string) error {
	// Linux capabilities are thread-scoped. Keep this goroutine pinned so the
	// thread that populates inheritable+ambient caps remains available for the
	// process lifetime; subsequent exec.Command calls need those thread caps.
	runtime.LockOSThread()

	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	for _, capName := range caps {
		capNum, err := capabilityNumber(capName)
		if err != nil {
			return err
		}
		index := capNum / 32
		bit := uint32(1) << uint(capNum%32)
		if data[index].Permitted&bit == 0 {
			return fmt.Errorf("capability %s not in permitted set; run `make setcap` on the binary", capName)
		}
		data[index].Inheritable |= bit
	}

	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset inheritable: %w", err)
	}

	for _, capName := range caps {
		capNum, err := capabilityNumber(capName)
		if err != nil {
			return err
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(capNum), 0, 0); err != nil {
			return fmt.Errorf("raise ambient %s: %w", capName, err)
		}
	}
	return nil
}

func capabilityNumber(capName string) (int, error) {
	normalized := strings.ToLower(strings.TrimSpace(capName))
	capNum, ok := capabilityNumbers[normalized]
	if !ok {
		return 0, fmt.Errorf("unsupported capability %q", capName)
	}
	return capNum, nil
}

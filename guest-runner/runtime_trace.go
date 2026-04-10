//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const runtimeTraceOptions = unix.PTRACE_O_TRACESYSGOOD |
	unix.PTRACE_O_TRACEFORK |
	unix.PTRACE_O_TRACEVFORK |
	unix.PTRACE_O_TRACEEXEC |
	unix.PTRACE_O_TRACEEXIT

const (
	traceCStringChunk   = 64
	traceCStringMax     = 4096
	traceOpenHowMinSize = 8
)

type runtimeTraceResult struct {
	ExitCode int
	Err      error
}

type runtimeSockaddr struct {
	IP   string
	Port uint16
}

type runtimeTraceOpenCall struct {
	Path    string
	Flags   uint64
	Syscall string
}

func (s *runtimeSensor) AttachTraceRoot() error {
	if s.traceDone != nil {
		return nil
	}
	s.traceDone = make(chan runtimeTraceResult, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := s.runTraceRoot(); err != nil {
			s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: "trace-attach-error: " + truncateStatusDetail(err.Error())})
			s.publishTraceResult(runtimeTraceResult{ExitCode: 1, Err: err})
		}
	}()
	return nil
}

func (s *runtimeSensor) runTraceRoot() error {
	if err := unix.PtraceAttach(s.rootPID); err != nil {
		return fmt.Errorf("ptrace attach: %w", err)
	}
	var status unix.WaitStatus
	pid, err := unix.Wait4(s.rootPID, &status, 0, nil)
	if err != nil {
		return fmt.Errorf("wait traced root: %w", err)
	}
	if pid != s.rootPID || !status.Stopped() {
		return fmt.Errorf("unexpected traced root stop: pid=%d status=%#x", pid, int(status))
	}
	if err := unix.PtraceSetOptions(s.rootPID, runtimeTraceOptions); err != nil {
		return fmt.Errorf("ptrace set options: %w", err)
	}
	identity := readTraceIdentity(s.rootPID)
	s.enqueue(runtimeSensorEvent{
		TsUnixNano: time.Now().UnixNano(),
		Type:       "process.exec",
		PID:        s.rootPID,
		PPID:       os.Getpid(),
		Comm:       identity.Comm,
		Exe:        identity.Exe,
		Metadata:   map[string]string{"source": "ptrace"},
	})
	s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: fmt.Sprintf("trace-root-attached pid=%d", s.rootPID)})
	if err := unix.PtraceSyscall(s.rootPID, 0); err != nil {
		return fmt.Errorf("resume traced root: %w", err)
	}
	s.runTracerLoop()
	return nil
}

func (s *runtimeSensor) WaitRootExit() (runtimeTraceResult, error) {
	if s.traceDone == nil {
		return runtimeTraceResult{}, errors.New("runtime trace not started")
	}
	result, ok := <-s.traceDone
	if !ok {
		return runtimeTraceResult{}, errors.New("runtime trace closed without result")
	}
	return result, nil
}

func (s *runtimeSensor) publishTraceResult(result runtimeTraceResult) {
	s.traceOnce.Do(func() {
		if s.traceDone != nil {
			s.traceDone <- result
			close(s.traceDone)
		}
	})
}

func (s *runtimeSensor) runTracerLoop() {
	ppids := map[int]int{s.rootPID: os.Getpid()}
	inSyscall := make(map[int]bool)
	active := map[int]struct{}{s.rootPID: {}}
	firstConnect := atomic.Bool{}

	for len(active) > 0 {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, 0, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ECHILD) {
				break
			}
			s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: "trace-error: " + truncateStatusDetail(err.Error())})
			s.publishTraceResult(runtimeTraceResult{ExitCode: 1, Err: err})
			return
		}
		if pid <= 0 {
			continue
		}

		if status.Exited() || status.Signaled() {
			exitCode := status.ExitStatus()
			metadata := map[string]string{"source": "ptrace"}
			if status.Signaled() {
				exitCode = 128 + int(status.Signal())
				metadata["signal"] = status.Signal().String()
			}
			identity := readTraceIdentity(pid)
			s.enqueue(runtimeSensorEvent{
				TsUnixNano: time.Now().UnixNano(),
				Type:       "process.exit",
				PID:        pid,
				PPID:       ppids[pid],
				Comm:       identity.Comm,
				Exe:        identity.Exe,
				ExitCode:   intPtr(exitCode),
				Metadata:   metadata,
			})
			delete(active, pid)
			delete(ppids, pid)
			delete(inSyscall, pid)
			if pid == s.rootPID {
				s.publishTraceResult(runtimeTraceResult{ExitCode: exitCode})
			}
			continue
		}

		if !status.Stopped() {
			continue
		}

		sig := status.StopSignal()
		if sig == syscall.Signal(int(syscall.SIGTRAP)|0x80) {
			if !inSyscall[pid] {
				if err := s.handleTraceSyscall(pid, ppids[pid], &firstConnect); err != nil {
					s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: "trace-syscall-error: " + truncateStatusDetail(err.Error())})
				}
			}
			inSyscall[pid] = !inSyscall[pid]
			_ = unix.PtraceSyscall(pid, 0)
			continue
		}

		if sig == syscall.SIGTRAP {
			cause := int(status >> 16)
			if cause == 0 {
				if !inSyscall[pid] {
					if err := s.handleTraceSyscall(pid, ppids[pid], &firstConnect); err != nil {
						s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: "trace-syscall-error: " + truncateStatusDetail(err.Error())})
					}
				}
				inSyscall[pid] = !inSyscall[pid]
				_ = unix.PtraceSyscall(pid, 0)
				continue
			}
			s.handleTraceEvent(pid, cause, ppids, active)
			_ = unix.PtraceSyscall(pid, 0)
			continue
		}

		_ = unix.PtraceSyscall(pid, int(sig))
	}

	s.publishTraceResult(runtimeTraceResult{ExitCode: 0})
}

func (s *runtimeSensor) handleTraceEvent(pid int, cause int, ppids map[int]int, active map[int]struct{}) {
	now := time.Now().UnixNano()
	switch cause {
	case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
		msg, err := unix.PtraceGetEventMsg(pid)
		if err != nil {
			return
		}
		childPID := int(msg)
		ppids[childPID] = pid
		active[childPID] = struct{}{}
		_ = unix.PtraceSetOptions(childPID, runtimeTraceOptions)
		identity := readTraceIdentity(childPID)
		s.enqueue(runtimeSensorEvent{TsUnixNano: now, Type: "process.fork", PID: childPID, PPID: pid, Comm: identity.Comm, Exe: identity.Exe, Metadata: map[string]string{"source": "ptrace"}})
		_ = unix.PtraceSyscall(childPID, 0)
	case unix.PTRACE_EVENT_EXEC:
		identity := readTraceIdentity(pid)
		s.enqueue(runtimeSensorEvent{TsUnixNano: now, Type: "process.exec", PID: pid, PPID: ppids[pid], Comm: identity.Comm, Exe: identity.Exe, Metadata: map[string]string{"source": "ptrace"}})
	case unix.PTRACE_EVENT_EXIT:
		return
	}
}

func (s *runtimeSensor) handleTraceSyscall(pid int, ppid int, firstConnect *atomic.Bool) error {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	if openCall, ok, err := readTraceOpenCall(pid, regs); err != nil {
		return err
	} else if ok {
		rawPath := openCall.Path
		resolvedPath, symlinkViolation, err := inspectTraceOpenPath(pid, openCall.Path, traceDirFD(regs))
		if err != nil {
			return err
		}
		if strings.TrimSpace(resolvedPath) != "" {
			openCall.Path = resolvedPath
		}
		identity := readTraceIdentity(pid)
		metadata := map[string]string{"source": "ptrace", "phase": "enter", "syscall": openCall.Syscall}
		if symlinkViolation {
			metadata["raw_path"] = rawPath
			metadata["resolved_path"] = openCall.Path
			metadata["symlink_violation"] = "true"
		}
		s.enqueue(runtimeSensorEvent{TsUnixNano: time.Now().UnixNano(), Type: "file.open", PID: pid, PPID: ppid, Comm: identity.Comm, Exe: identity.Exe, Path: openCall.Path, Flags: openCall.Flags, Metadata: metadata})
		if symlinkViolation {
			s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: fmt.Sprintf("blocked-symlink-open pid=%d raw=%s resolved=%s", pid, truncateStatusDetail(rawPath), truncateStatusDetail(openCall.Path))})
			_ = syscall.Kill(-s.rootPID, syscall.SIGKILL)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		return nil
	}

	if regs.Orig_rax != uint64(unix.SYS_CONNECT) {
		return nil
	}
	addr, err := readTraceSockaddr(pid, uintptr(regs.Rsi), int(regs.Rdx))
	if err != nil {
		if strings.Contains(err.Error(), "unsupported sockaddr family") {
			return nil
		}
		return err
	}
	identity := readTraceIdentity(pid)
	metadata := map[string]string{"source": "ptrace", "phase": "enter"}
	if firstConnect.CompareAndSwap(false, true) {
		s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-trace", Detail: fmt.Sprintf("first-connect pid=%d dst=%s:%d", pid, addr.IP, addr.Port)})
	}
	s.enqueue(runtimeSensorEvent{TsUnixNano: time.Now().UnixNano(), Type: "net.connect", PID: pid, PPID: ppid, Comm: identity.Comm, Exe: identity.Exe, DstIP: addr.IP, DstPort: addr.Port, Metadata: metadata})
	return nil
}

func readTraceOpenCall(pid int, regs unix.PtraceRegs) (runtimeTraceOpenCall, bool, error) {
	call, ok, err := parseTraceOpenCall(regs, func(addr uintptr) (string, error) {
		return readTraceCString(pid, addr, traceCStringMax)
	}, func(addr uintptr, size uint64) (uint64, error) {
		return readTraceOpenHowFlags(pid, addr, size)
	})
	if err != nil || !ok {
		return runtimeTraceOpenCall{}, ok, err
	}
	call.Path = resolveTracePath(pid, call.Path, traceDirFD(regs))
	if strings.TrimSpace(call.Path) == "" {
		return runtimeTraceOpenCall{}, false, nil
	}
	return call, true, nil
}

func parseTraceOpenCall(regs unix.PtraceRegs, readCString func(uintptr) (string, error), readOpenHow func(uintptr, uint64) (uint64, error)) (runtimeTraceOpenCall, bool, error) {
	switch regs.Orig_rax {
	case uint64(unix.SYS_OPEN):
		path, err := readCString(uintptr(regs.Rdi))
		if err != nil {
			return runtimeTraceOpenCall{}, true, err
		}
		return runtimeTraceOpenCall{Path: path, Flags: uint64(regs.Rsi), Syscall: "open"}, true, nil
	case uint64(unix.SYS_OPENAT):
		path, err := readCString(uintptr(regs.Rsi))
		if err != nil {
			return runtimeTraceOpenCall{}, true, err
		}
		return runtimeTraceOpenCall{Path: path, Flags: uint64(regs.Rdx), Syscall: "openat"}, true, nil
	case uint64(unix.SYS_OPENAT2):
		path, err := readCString(uintptr(regs.Rsi))
		if err != nil {
			return runtimeTraceOpenCall{}, true, err
		}
		flags, err := readOpenHow(uintptr(regs.Rdx), uint64(regs.R10))
		if err != nil {
			return runtimeTraceOpenCall{}, true, err
		}
		return runtimeTraceOpenCall{Path: path, Flags: flags, Syscall: "openat2"}, true, nil
	default:
		return runtimeTraceOpenCall{}, false, nil
	}
}

func traceDirFD(regs unix.PtraceRegs) int {
	if regs.Orig_rax == uint64(unix.SYS_OPENAT) || regs.Orig_rax == uint64(unix.SYS_OPENAT2) {
		return int(int64(regs.Rdi))
	}
	return unix.AT_FDCWD
}

func readTraceCString(pid int, addr uintptr, maxLen int) (string, error) {
	if addr == 0 {
		return "", errors.New("invalid string pointer")
	}
	if maxLen <= 0 {
		maxLen = traceCStringMax
	}
	buf := make([]byte, 0, maxLen)
	scratch := make([]byte, traceCStringChunk)
	for len(buf) < maxLen {
		n, err := unix.PtracePeekData(pid, addr+uintptr(len(buf)), scratch)
		if err != nil && n == 0 {
			return "", err
		}
		chunk := scratch[:n]
		if idx := bytes.IndexByte(chunk, 0); idx >= 0 {
			buf = append(buf, chunk[:idx]...)
			return string(buf), nil
		}
		buf = append(buf, chunk...)
		if err != nil || n < len(scratch) {
			return string(buf), nil
		}
	}
	return string(buf), nil
}

func readTraceOpenHowFlags(pid int, addr uintptr, size uint64) (uint64, error) {
	if addr == 0 {
		return 0, errors.New("invalid open_how pointer")
	}
	if size < traceOpenHowMinSize {
		return 0, fmt.Errorf("short open_how size: %d", size)
	}
	buf := make([]byte, traceOpenHowMinSize)
	if _, err := unix.PtracePeekData(pid, addr, buf); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func resolveTracePath(pid int, rawPath string, dirfd int) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return ""
	}
	if filepath.IsAbs(rawPath) {
		return filepath.Clean(rawPath)
	}
	base := traceDirPath(pid, dirfd)
	if base == "" {
		return rawPath
	}
	return filepath.Clean(filepath.Join(base, rawPath))
}

func inspectTraceOpenPath(pid int, rawPath string, dirfd int) (string, bool, error) {
	resolved := resolveTracePath(pid, rawPath, dirfd)
	if !tracePathUsesWritableMount(resolved) {
		return resolved, false, nil
	}
	evaluated, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return resolved, false, nil
		}
		return resolved, false, nil
	}
	evaluated = filepath.Clean(evaluated)
	if evaluated != resolved {
		return evaluated, true, nil
	}
	return resolved, false, nil
}

func tracePathUsesWritableMount(path string) bool {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return true
	}
	if path == "/workspace" || strings.HasPrefix(path, "/workspace/") {
		return true
	}
	return false
}

func traceDirPath(pid int, dirfd int) string {
	switch dirfd {
	case unix.AT_FDCWD:
		path, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return ""
		}
		return path
	default:
		if dirfd < 0 {
			return ""
		}
		path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
		if err != nil {
			return ""
		}
		if !filepath.IsAbs(path) {
			return ""
		}
		return path
	}
}

type traceIdentity struct {
	Comm string
	Exe  string
}

func readTraceIdentity(pid int) traceIdentity {
	identity := traceIdentity{}
	if commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		identity.Comm = string(bytesTrimSpace(commBytes))
	}
	if exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		identity.Exe = exePath
	}
	return identity
}

func readTraceSockaddr(pid int, addr uintptr, addrLen int) (runtimeSockaddr, error) {
	if addr == 0 || addrLen < 2 {
		return runtimeSockaddr{}, errors.New("invalid sockaddr")
	}
	if addrLen > 128 {
		addrLen = 128
	}
	buf := make([]byte, addrLen)
	if _, err := unix.PtracePeekData(pid, addr, buf); err != nil {
		return runtimeSockaddr{}, err
	}
	return parseTraceSockaddr(buf)
}

func parseTraceSockaddr(buf []byte) (runtimeSockaddr, error) {
	if len(buf) < 4 {
		return runtimeSockaddr{}, errors.New("short sockaddr")
	}
	family := binary.LittleEndian.Uint16(buf[:2])
	switch family {
	case unix.AF_INET:
		if len(buf) < 8 {
			return runtimeSockaddr{}, errors.New("short sockaddr_in")
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		ip := net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		return runtimeSockaddr{IP: ip, Port: port}, nil
	case unix.AF_INET6:
		if len(buf) < 24 {
			return runtimeSockaddr{}, errors.New("short sockaddr_in6")
		}
		port := binary.BigEndian.Uint16(buf[2:4])
		ip := net.IP(buf[8:24]).String()
		return runtimeSockaddr{IP: ip, Port: port}, nil
	default:
		return runtimeSockaddr{}, fmt.Errorf("unsupported sockaddr family: %d", family)
	}
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const traceATFDCWDReg = ^uint64(99)

func TestParseTraceOpenCallOpenAT(t *testing.T) {
	regs := unix.PtraceRegs{
		Orig_rax: uint64(unix.SYS_OPENAT),
		Rdi:      traceATFDCWDReg,
		Rsi:      0x1234,
		Rdx:      unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
	}
	call, ok, err := parseTraceOpenCall(regs, func(addr uintptr) (string, error) {
		if addr != 0x1234 {
			t.Fatalf("unexpected string address: %#x", addr)
		}
		return "result.txt", nil
	}, func(addr uintptr, size uint64) (uint64, error) {
		t.Fatalf("unexpected open_how reader call: %#x size=%d", addr, size)
		return 0, nil
	})
	if err != nil {
		t.Fatalf("parseTraceOpenCall: %v", err)
	}
	if !ok {
		t.Fatal("expected openat call to be parsed")
	}
	if call.Path != "result.txt" {
		t.Fatalf("unexpected path: %+v", call)
	}
	wantFlags := uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC)
	if call.Flags != wantFlags {
		t.Fatalf("unexpected flags: got %#x want %#x", call.Flags, wantFlags)
	}
	if call.Syscall != "openat" {
		t.Fatalf("unexpected syscall: %+v", call)
	}
}

func TestParseTraceOpenCallOpenAT2(t *testing.T) {
	regs := unix.PtraceRegs{
		Orig_rax: uint64(unix.SYS_OPENAT2),
		Rdi:      traceATFDCWDReg,
		Rsi:      0x1111,
		Rdx:      0x2222,
		R10:      24,
	}
	call, ok, err := parseTraceOpenCall(regs, func(addr uintptr) (string, error) {
		if addr != 0x1111 {
			t.Fatalf("unexpected string address: %#x", addr)
		}
		return "/workspace/out.txt", nil
	}, func(addr uintptr, size uint64) (uint64, error) {
		if addr != 0x2222 || size != 24 {
			t.Fatalf("unexpected open_how read: addr=%#x size=%d", addr, size)
		}
		return uint64(unix.O_RDWR | unix.O_APPEND), nil
	})
	if err != nil {
		t.Fatalf("parseTraceOpenCall: %v", err)
	}
	if !ok {
		t.Fatal("expected openat2 call to be parsed")
	}
	wantFlags := uint64(unix.O_RDWR | unix.O_APPEND)
	if call.Flags != wantFlags {
		t.Fatalf("unexpected flags: got %#x want %#x", call.Flags, wantFlags)
	}
	if call.Syscall != "openat2" {
		t.Fatalf("unexpected syscall: %+v", call)
	}
}

func TestResolveTracePathUsesTraceeCWD(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(cwd)
	}()

	resolved := resolveTracePath(os.Getpid(), "relative.txt", unix.AT_FDCWD)
	want := filepath.Join(tmp, "relative.txt")
	if resolved != want {
		t.Fatalf("unexpected resolved path: got %q want %q", resolved, want)
	}
}

func TestInspectTraceOpenPathFlagsSymlinkOnWritableMount(t *testing.T) {
	tmp := t.TempDir()
	allowed := filepath.Join(tmp, "allowed.txt")
	if err := os.WriteFile(allowed, []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	got, blocked, err := inspectTraceOpenPath(os.Getpid(), link, unix.AT_FDCWD)
	if err != nil {
		t.Fatalf("inspectTraceOpenPath: %v", err)
	}
	if !blocked {
		t.Fatal("expected symlink path on writable mount to be blocked")
	}
	if got != "/etc/passwd" {
		t.Fatalf("resolved path = %q, want /etc/passwd", got)
	}
}

func TestInspectTraceOpenPathIgnoresRegularWritableFile(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "regular.txt")
	if err := os.WriteFile(target, []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, blocked, err := inspectTraceOpenPath(os.Getpid(), target, unix.AT_FDCWD)
	if err != nil {
		t.Fatalf("inspectTraceOpenPath: %v", err)
	}
	if blocked {
		t.Fatal("regular file should not be blocked")
	}
	if got != target {
		t.Fatalf("resolved path = %q, want %q", got, target)
	}
}

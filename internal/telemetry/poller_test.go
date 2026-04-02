package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCgroupPollerReadsFiles(t *testing.T) {
	t.Parallel()

	basePath := t.TempDir()
	execID := "test-id"
	cgroupPath := filepath.Join(basePath, "aegis", execID)
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeTestFile(t, filepath.Join(cgroupPath, "memory.current"), "14200000")
	writeTestFile(t, filepath.Join(cgroupPath, "memory.max"), "268435456")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.current"), "3")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.max"), "128")

	bus := NewBus(execID)
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := startCgroupPoller(ctx, bus, execID, 100*time.Millisecond, basePath)
	defer stop()

	select {
	case event := <-ch:
		if event.Kind != KindCgroupSample {
			t.Fatalf("unexpected kind: %q", event.Kind)
		}

		drained := bus.Drain()
		if len(drained) == 0 {
			t.Fatal("expected buffered cgroup sample")
		}

		sample, ok := readCgroupSample(basePath, execID)
		if !ok {
			t.Fatal("expected to read cgroup sample directly")
		}
		if sample.MemoryCurrent != 14200000 {
			t.Fatalf("unexpected memory.current: %d", sample.MemoryCurrent)
		}
		if sample.MemoryMax != 268435456 {
			t.Fatalf("unexpected memory.max: %d", sample.MemoryMax)
		}
		if sample.PidsCurrent != 3 {
			t.Fatalf("unexpected pids.current: %d", sample.PidsCurrent)
		}
		if sample.PidsMax != 128 {
			t.Fatalf("unexpected pids.max: %d", sample.PidsMax)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for cgroup sample")
	}
}

func TestCgroupPollerHandlesMaxString(t *testing.T) {
	t.Parallel()

	basePath := t.TempDir()
	execID := "max-id"
	cgroupPath := filepath.Join(basePath, "aegis", execID)
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeTestFile(t, filepath.Join(cgroupPath, "memory.current"), "64")
	writeTestFile(t, filepath.Join(cgroupPath, "memory.max"), "max")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.current"), "2")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.max"), "max")

	sample, ok := readCgroupSample(basePath, execID)
	if !ok {
		t.Fatal("expected sample read to succeed")
	}

	if sample.MemoryMax != 0 {
		t.Fatalf("unexpected memory.max: %d", sample.MemoryMax)
	}
	if sample.PidsMax != 0 {
		t.Fatalf("unexpected pids.max: %d", sample.PidsMax)
	}
	if sample.MemoryPct != 0 {
		t.Fatalf("unexpected memory pct: %f", sample.MemoryPct)
	}
	if sample.PidsPct != 0 {
		t.Fatalf("unexpected pids pct: %f", sample.PidsPct)
	}
}

func TestCgroupPollerStopsOnMissingDir(t *testing.T) {
	t.Parallel()

	basePath := t.TempDir()
	execID := "gone-id"
	cgroupPath := filepath.Join(basePath, "aegis", execID)
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeTestFile(t, filepath.Join(cgroupPath, "memory.current"), "64")
	writeTestFile(t, filepath.Join(cgroupPath, "memory.max"), "128")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.current"), "1")
	writeTestFile(t, filepath.Join(cgroupPath, "pids.max"), "4")

	before := runtime.NumGoroutine()

	bus := NewBus(execID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := startCgroupPoller(ctx, bus, execID, 50*time.Millisecond, basePath)
	defer stop()

	time.Sleep(120 * time.Millisecond)

	if err := os.RemoveAll(cgroupPath); err != nil {
		t.Fatalf("remove cgroup dir: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		after := runtime.NumGoroutine()
		if after <= before+1 {
			return
		}
	}

	t.Fatal("poller goroutine appears to still be running after cgroup removal")
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

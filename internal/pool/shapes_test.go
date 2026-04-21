package pool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis/internal/authority"
	"aegis/internal/executor"
	"aegis/internal/policy"
)

func testShapeAssets(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "alpine-base.ext4")
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	return dir, rootfs
}

func TestDefaultShapesPrioritizesStandardThenNano(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	assetsDir, rootfsPath := testShapeAssets(t)

	gotOne, err := DefaultShapes(1, assetsDir, rootfsPath, pol)
	if err != nil {
		t.Fatalf("DefaultShapes(1): %v", err)
	}
	if len(gotOne) != 1 || gotOne[0].Label != WarmShapeStandard || gotOne[0].Size != 1 {
		t.Fatalf("DefaultShapes(1) = %+v, want standard-only size 1", gotOne)
	}

	gotTwo, err := DefaultShapes(2, assetsDir, rootfsPath, pol)
	if err != nil {
		t.Fatalf("DefaultShapes(2): %v", err)
	}
	if len(gotTwo) != 2 {
		t.Fatalf("DefaultShapes(2) len=%d, want 2", len(gotTwo))
	}
	if gotTwo[0].Label != WarmShapeStandard || gotTwo[0].Size != 1 {
		t.Fatalf("first shape = %+v, want standard size 1", gotTwo[0])
	}
	if gotTwo[1].Label != WarmShapeNano || gotTwo[1].Size != 1 {
		t.Fatalf("second shape = %+v, want nano size 1", gotTwo[1])
	}
}

func TestClaimForUsesPerShapeManagerAndTracksFallbackReason(t *testing.T) {
	t.Parallel()

	standard := NewWithHooks(Config{Size: 1, MaxAge: time.Minute}, Hooks{
		Build: func(context.Context, string) (*executor.VMInstance, error) {
			return &executor.VMInstance{UUID: "std"}, nil
		},
		WaitReady: func(context.Context, *executor.VMInstance) error { return nil },
		Pause:     func(context.Context, *executor.VMInstance) error { return nil },
		Resume:    func(context.Context, *executor.VMInstance) error { return nil },
		Teardown:  func(*executor.VMInstance) error { return nil },
	})
	nano := NewWithHooks(Config{Size: 1, MaxAge: time.Minute}, Hooks{
		Build: func(context.Context, string) (*executor.VMInstance, error) {
			return &executor.VMInstance{UUID: "nano"}, nil
		},
		WaitReady: func(context.Context, *executor.VMInstance) error { return nil },
		Pause:     func(context.Context, *executor.VMInstance) error { return nil },
		Resume:    func(context.Context, *executor.VMInstance) error { return nil },
		Teardown:  func(*executor.VMInstance) error { return nil },
	})
	top := &Manager{
		cfg:             Config{MaxAge: time.Minute},
		shapeManagers:   map[string]*shapeManager{"standard-key": {label: WarmShapeStandard, manager: standard}, "nano-key": {label: WarmShapeNano, manager: nano}},
		shapeOrder:      []string{"standard-key", "nano-key"},
		fallbackReasons: map[string]uint64{},
	}
	standard.Start()
	nano.Start()
	defer top.Close()

	waitFor(t, func() bool {
		status := top.Status()
		return status.AvailableByShape[WarmShapeStandard] == 1 && status.AvailableByShape[WarmShapeNano] == 1
	})

	vm, warm, reason, err := top.ClaimFor(context.Background(), "nano-key")
	if err != nil || !warm || vm == nil || vm.UUID != "nano" || reason != "" {
		t.Fatalf("ClaimFor(nano) vm=%+v warm=%v reason=%q err=%v", vm, warm, reason, err)
	}

	if _, warm, reason, err := top.ClaimFor(context.Background(), "missing"); err != nil || warm || reason != FallbackShapeMissing {
		t.Fatalf("ClaimFor(missing) warm=%v reason=%q err=%v", warm, reason, err)
	}

	status := top.Status()
	if status.ColdFallbackReasons[FallbackShapeMissing] != 1 {
		t.Fatalf("fallback reasons = %+v, want %s count 1", status.ColdFallbackReasons, FallbackShapeMissing)
	}
}

func TestShapeKeyChangesWhenBootAuthorityChanges(t *testing.T) {
	t.Parallel()

	left := ShapeKey("standard", "/assets", authority.BootContext{
		RootfsImage: "rootfs#a",
		NetworkMode: policy.NetworkModeNone,
	})
	right := ShapeKey("standard", "/assets", authority.BootContext{
		RootfsImage: "rootfs#b",
		NetworkMode: policy.NetworkModeNone,
	})
	if left == right {
		t.Fatalf("expected shape key to change when boot authority changes")
	}
}

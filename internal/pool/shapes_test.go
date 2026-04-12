package pool

import (
	"context"
	"testing"
	"time"

	"aegis/internal/executor"
	"aegis/internal/policy"
)

func TestDefaultShapesPrioritizesStandardThenNano(t *testing.T) {
	t.Parallel()

	pol := policy.Default()

	gotOne := DefaultShapes(1, "/assets", "/rootfs.ext4", pol)
	if len(gotOne) != 1 || gotOne[0].Label != WarmShapeStandard || gotOne[0].Size != 1 {
		t.Fatalf("DefaultShapes(1) = %+v, want standard-only size 1", gotOne)
	}

	gotTwo := DefaultShapes(2, "/assets", "/rootfs.ext4", pol)
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

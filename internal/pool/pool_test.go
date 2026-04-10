package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aegis/internal/executor"
)

func TestPoolInitializeAndClaimReplenish(t *testing.T) {
	t.Parallel()

	var builds atomic.Int32
	var tears atomic.Int32
	manager := NewWithHooks(Config{Size: 2, MaxAge: time.Minute}, Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			builds.Add(1)
			return &executor.VMInstance{UUID: id, CgroupID: id, VsockPath: id}, nil
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Pause:     func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Resume:    func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Teardown: func(vm *executor.VMInstance) error {
			tears.Add(1)
			return nil
		},
	})
	manager.Start()
	defer manager.Close()

	waitFor(t, func() bool { return manager.Status().Available == 2 })

	vm, warm, err := manager.Claim(context.Background())
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if !warm || vm == nil {
		t.Fatalf("Claim() warm=%v vm=%v, want warm VM", warm, vm)
	}
	if manager.Status().Available != 1 {
		t.Fatalf("available after claim = %d, want 1", manager.Status().Available)
	}
	waitFor(t, func() bool { return manager.Status().Available == 2 })
	if builds.Load() < 3 {
		t.Fatalf("build count = %d, want replenish build", builds.Load())
	}
}

func TestPoolEmptyFallback(t *testing.T) {
	t.Parallel()

	manager := NewWithHooks(Config{Size: 1, MaxAge: time.Minute}, Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			return &executor.VMInstance{UUID: id}, nil
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Pause:     func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Resume:    func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Teardown:  func(vm *executor.VMInstance) error { return nil },
	})
	manager.Start()
	defer manager.Close()
	waitFor(t, func() bool { return manager.Status().Available == 1 })

	if _, warm, err := manager.Claim(context.Background()); err != nil || !warm {
		t.Fatalf("first claim err=%v warm=%v, want warm success", err, warm)
	}
	if _, warm, err := manager.Claim(context.Background()); err != nil {
		t.Fatalf("second claim err = %v", err)
	} else if warm {
		t.Fatal("second claim unexpectedly served warm VM")
	}
}

func TestPoolRecyclesExpiredEntries(t *testing.T) {
	t.Parallel()

	var builds atomic.Int32
	manager := NewWithHooks(Config{Size: 1, MaxAge: 20 * time.Millisecond}, Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			builds.Add(1)
			return &executor.VMInstance{UUID: id}, nil
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Pause:     func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Resume:    func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Teardown:  func(vm *executor.VMInstance) error { return nil },
	})
	manager.Start()
	defer manager.Close()
	waitFor(t, func() bool { return manager.Status().Available == 1 })
	time.Sleep(40 * time.Millisecond)
	manager.expireStale()
	waitFor(t, func() bool { return manager.Status().Available == 1 })
	if manager.Status().RecycledExpired == 0 {
		t.Fatal("expected expired entry recycle count")
	}
	if builds.Load() < 2 {
		t.Fatalf("build count = %d, want recycled rebuild", builds.Load())
	}
}

func TestPoolConcurrentClaimsDoNotDoubleServe(t *testing.T) {
	t.Parallel()

	var resumed sync.Map
	manager := NewWithHooks(Config{Size: 2, MaxAge: time.Minute}, Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			return &executor.VMInstance{UUID: id}, nil
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Pause:     func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Resume: func(ctx context.Context, vm *executor.VMInstance) error {
			if _, loaded := resumed.LoadOrStore(vm.UUID, struct{}{}); loaded {
				t.Fatalf("vm %s resumed twice", vm.UUID)
			}
			return nil
		},
		Teardown: func(vm *executor.VMInstance) error { return nil },
	})
	manager.Start()
	defer manager.Close()
	waitFor(t, func() bool { return manager.Status().Available == 2 })

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vm, warm, err := manager.Claim(context.Background())
			if err != nil || !warm || vm == nil {
				t.Errorf("Claim err=%v warm=%v vm=%v", err, warm, vm)
			}
		}()
	}
	wg.Wait()
}

func TestPoolCloseStopsAndCleans(t *testing.T) {
	t.Parallel()

	var tears atomic.Int32
	manager := NewWithHooks(Config{Size: 2, MaxAge: time.Minute}, Hooks{
		Build: func(ctx context.Context, id string) (*executor.VMInstance, error) {
			return &executor.VMInstance{UUID: id}, nil
		},
		WaitReady: func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Pause:     func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Resume:    func(ctx context.Context, vm *executor.VMInstance) error { return nil },
		Teardown: func(vm *executor.VMInstance) error {
			tears.Add(1)
			return nil
		},
	})
	manager.Start()
	waitFor(t, func() bool { return manager.Status().Available == 2 })
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if tears.Load() != 2 {
		t.Fatalf("teardown count = %d, want 2", tears.Load())
	}
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

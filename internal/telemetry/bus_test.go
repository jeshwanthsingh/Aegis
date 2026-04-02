package telemetry

import (
	"testing"
	"time"
)

func TestEmitAndSubscribe(t *testing.T) {
	t.Parallel()

	bus := NewBus("exec-123")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	bus.Emit(KindVMBootStart, map[string]string{"step": "boot"})
	bus.Emit(KindVMBootReady, map[string]string{"step": "ready"})
	bus.Emit(KindExecExit, ExecExitData{ExitCode: 0, Reason: "completed"})

	wantKinds := []string{KindVMBootStart, KindVMBootReady, KindExecExit}
	for _, want := range wantKinds {
		select {
		case event := <-ch:
			if event.ExecID != "exec-123" {
				t.Fatalf("unexpected exec id: got %q", event.ExecID)
			}
			if event.Kind != want {
				t.Fatalf("unexpected kind: got %q want %q", event.Kind, want)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timed out waiting for event %q", want)
		}
	}
}

func TestEmitDoesNotBlock(t *testing.T) {
	t.Parallel()

	bus := NewBus("exec-fast")

	done := make(chan struct{})
	start := time.Now()

	go func() {
		for i := 0; i < 300; i++ {
			bus.Emit(KindExecStdout, map[string]int{"i": i})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("emit loop blocked")
	}

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("emit loop took too long: %v", elapsed)
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	t.Parallel()

	bus := NewBus("exec-unsub")
	ch, unsubscribe := bus.Subscribe()

	bus.Emit(KindExecStdout, map[string]string{"msg": "first"})
	select {
	case event := <-ch:
		if event.Kind != KindExecStdout {
			t.Fatalf("unexpected kind: %q", event.Kind)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for first event")
	}

	unsubscribe()
	bus.Emit(KindExecStderr, map[string]string{"msg": "second"})

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected subscriber channel to be closed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for closed subscriber channel")
	}
}

func TestClose(t *testing.T) {
	t.Parallel()

	bus := NewBus("exec-close")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	bus.Close()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed subscriber channel")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for closed subscriber channel")
	}

	bus.Emit(KindExecExit, ExecExitData{ExitCode: 0})
}

func TestDrain(t *testing.T) {
	t.Parallel()

	bus := NewBus("exec-drain")

	wantKinds := []string{
		KindVMBootStart,
		KindCgroupConfigured,
		KindExecStdout,
		KindExecStderr,
		KindExecExit,
	}

	for _, kind := range wantKinds {
		bus.Emit(kind, map[string]string{"kind": kind})
	}

	events := bus.Drain()
	if len(events) != len(wantKinds) {
		t.Fatalf("unexpected drained length: got %d want %d", len(events), len(wantKinds))
	}

	for i, event := range events {
		if event.Kind != wantKinds[i] {
			t.Fatalf("unexpected kind at %d: got %q want %q", i, event.Kind, wantKinds[i])
		}
	}
}

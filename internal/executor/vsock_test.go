package executor

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"aegis/internal/models"
	"aegis/internal/telemetry"
)

func TestReadChunksEmitsGuestProcTelemetry(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bus := telemetry.NewBus("exec-telemetry")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: telemetry.KindGuestProcSample,
			Data: mustJSON(t, telemetry.GuestProcSampleData{PidsCurrent: 8, PidsLimit: 16, PidsPct: 50}),
		})
		_ = enc.Encode(models.GuestChunk{
			Type:     "done",
			ExitCode: 1,
			Reason:   "guest_pids_limit",
		})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.ExitReason != "guest_pids_limit" {
		t.Fatalf("unexpected exit reason: %q", result.ExitReason)
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindGuestProcSample {
				continue
			}
			var data telemetry.GuestProcSampleData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatalf("unmarshal event data: %v", err)
			}
			if data.PidsCurrent != 8 || data.PidsLimit != 16 {
				t.Fatalf("unexpected guest proc sample: %+v", data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for guest proc sample event")
		}
	}
}

func TestReadChunksEmitsRuntimeEvents(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bus := telemetry.NewBus("exec-runtime")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	exitCode := 0
	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Dropped:       2,
				FloodDetected: true,
				QueueCapacity: 256,
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "process.exec", PID: 42, PPID: 1, Comm: "python3", Exe: "/usr/bin/python3"},
					{TsUnixNano: 102, Type: "file.open", PID: 42, Path: "/etc/hostname"},
					{TsUnixNano: 103, Type: "process.exit", PID: 42, ExitCode: &exitCode},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.ExitReason != "completed" {
		t.Fatalf("unexpected exit reason: %q", result.ExitReason)
	}

	var runtimeEvents []models.RuntimeEvent
	var status telemetry.RuntimeSensorStatusData
	deadline := time.After(time.Second)
	for len(runtimeEvents) < 3 || status.DroppedEvents == 0 {
		select {
		case event := <-ch:
			switch event.Kind {
			case telemetry.KindRuntimeEvent:
				var runtimeEvent models.RuntimeEvent
				if err := json.Unmarshal(event.Data, &runtimeEvent); err != nil {
					t.Fatalf("unmarshal runtime event: %v", err)
				}
				runtimeEvents = append(runtimeEvents, runtimeEvent)
			case telemetry.KindRuntimeSensorStatus:
				if err := json.Unmarshal(event.Data, &status); err != nil {
					t.Fatalf("unmarshal runtime sensor status: %v", err)
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for runtime events, got %d", len(runtimeEvents))
		}
	}

	if runtimeEvents[0].Seq != 1 || runtimeEvents[1].Seq != 2 || runtimeEvents[2].Seq != 3 {
		t.Fatalf("unexpected runtime event sequence: %+v", runtimeEvents)
	}
	if runtimeEvents[0].DroppedSinceLast != 2 || runtimeEvents[1].DroppedSinceLast != 0 {
		t.Fatalf("unexpected dropped_since_last values: %+v", runtimeEvents)
	}
	if runtimeEvents[0].Backend != models.BackendFirecracker {
		t.Fatalf("unexpected backend: %q", runtimeEvents[0].Backend)
	}
	if runtimeEvents[1].Type != models.EventFileOpen || runtimeEvents[1].Path != "/etc/hostname" {
		t.Fatalf("unexpected file.open event: %+v", runtimeEvents[1])
	}
	if runtimeEvents[2].ExitCode != 0 {
		t.Fatalf("unexpected process.exit event: %+v", runtimeEvents[2])
	}
	if !status.FloodDetected || status.DroppedEvents != 2 {
		t.Fatalf("unexpected runtime sensor status: %+v", status)
	}
}

func TestReadChunksRejectsUnknownRuntimeEventType(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{{TsUnixNano: 1, Type: "bad.event"}},
			}),
		})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, telemetry.NewBus("exec-runtime")); err == nil || !strings.Contains(err.Error(), "unknown runtime event type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadChunksRejectsOversizedMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		oversized := `{"type":"stdout","chunk":"` + strings.Repeat("A", maxGuestChunkBytes) + `"}`
		_, _ = server.Write([]byte(oversized + "\n"))
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, nil); err == nil || !strings.Contains(err.Error(), "guest message exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadChunksDecodesNormalMessageWithScanner(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{Type: "stdout", Chunk: "ok\n"})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed", DurationMs: 12})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, nil)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.Stdout != "ok\n" {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}
	if result.ExitCode != 0 || result.ExitReason != "completed" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return b
}

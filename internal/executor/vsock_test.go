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

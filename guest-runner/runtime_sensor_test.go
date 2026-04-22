//go:build linux

package main

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestRuntimeSensorRecordRootExitFlushesBatchOnClose(t *testing.T) {
	var (
		mu     sync.Mutex
		chunks []GuestChunk
	)
	send := func(chunk GuestChunk) bool {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, chunk)
		return true
	}

	sensor := startRuntimeSensor(42, send)
	sensor.RecordRootExit(7)
	if err := sensor.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	var foundExit bool
	for _, chunk := range chunks {
		if chunk.Name != guestRuntimeEventBatchKind {
			continue
		}
		var batch runtimeSensorBatch
		if err := json.Unmarshal(chunk.Data, &batch); err != nil {
			t.Fatalf("unmarshal batch: %v", err)
		}
		for _, event := range batch.Events {
			if event.Type == "process.exit" && event.PID == 42 {
				foundExit = true
				if event.ExitCode == nil || *event.ExitCode != 7 {
					t.Fatalf("unexpected exit event payload: %+v", event)
				}
			}
		}
	}
	if !foundExit {
		t.Fatalf("expected process.exit batch event in chunks: %+v", chunks)
	}
}

func TestRuntimeSensorEnqueueTracksDropsAndFlood(t *testing.T) {
	sensor := &runtimeSensor{
		rootPID: 7,
		send:    func(GuestChunk) bool { return true },
		events:  make(chan runtimeSensorEvent, 1),
		stopCh:  make(chan struct{}),
	}

	sensor.enqueue(runtimeSensorEvent{Type: "process.exec", PID: 7})
	for i := uint32(0); i < runtimeSensorFloodThreshold; i++ {
		sensor.enqueue(runtimeSensorEvent{Type: "file.open", PID: 7})
	}

	if got := sensor.dropped.Load(); got != runtimeSensorFloodThreshold {
		t.Fatalf("unexpected dropped count: got %d want %d", got, runtimeSensorFloodThreshold)
	}
	if !sensor.flood.Load() {
		t.Fatal("expected flood detection to be set after threshold is crossed")
	}
}

func TestParseTraceSockaddrIPv4(t *testing.T) {
	buf := []byte{0x02, 0x00, 0x00, 0x50, 127, 0, 0, 1}
	addr, err := parseTraceSockaddr(buf)
	if err != nil {
		t.Fatalf("parseTraceSockaddr: %v", err)
	}
	if addr.IP != "127.0.0.1" || addr.Port != 80 {
		t.Fatalf("unexpected sockaddr: %+v", addr)
	}
}

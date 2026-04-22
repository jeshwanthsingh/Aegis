package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	guestRuntimeEventBatchKind   = "guest.runtime.event.batch.v1"
	guestRuntimeSensorStatusKind = "guest.runtime.sensor.status.v1"
	runtimeSensorPollInterval    = 10 * time.Millisecond
	runtimeSensorFlushInterval   = 25 * time.Millisecond
	runtimeSensorQueueCapacity   = 256
	runtimeSensorMaxBatch        = 16
	runtimeSensorFloodThreshold  = 32
)

type runtimeSensorEvent struct {
	TsUnixNano int64             `json:"ts_unix_nano"`
	Type       string            `json:"type"`
	PID        int               `json:"pid,omitempty"`
	PPID       int               `json:"ppid,omitempty"`
	Comm       string            `json:"comm,omitempty"`
	Exe        string            `json:"exe,omitempty"`
	Path       string            `json:"path,omitempty"`
	Flags      uint64            `json:"flags,omitempty"`
	DstIP      string            `json:"dst_ip,omitempty"`
	DstPort    uint16            `json:"dst_port,omitempty"`
	ExitCode   *int              `json:"exit_code,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type runtimeSensorBatch struct {
	Events        []runtimeSensorEvent `json:"events"`
	Dropped       uint32               `json:"dropped"`
	FloodDetected bool                 `json:"flood_detected,omitempty"`
	QueueCapacity int                  `json:"queue_capacity,omitempty"`
}

type runtimeSensorStatus struct {
	DroppedEvents uint64 `json:"dropped_events"`
	FloodDetected bool   `json:"flood_detected"`
	QueueCapacity int    `json:"queue_capacity,omitempty"`
	BatchEvents   int    `json:"batch_events,omitempty"`
	Source        string `json:"source,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type runtimeSensor struct {
	rootPID          int
	send             func(GuestChunk) bool
	events           chan runtimeSensorEvent
	stopCh           chan struct{}
	wg               sync.WaitGroup
	dropped          atomic.Uint32
	flood            atomic.Bool
	closed           atomic.Bool
	firstEventLogged atomic.Bool
	firstBatchSent   atomic.Bool
	traceDone        chan runtimeTraceResult
	traceOnce        sync.Once
}

func startRuntimeSensor(rootPID int, send func(GuestChunk) bool) *runtimeSensor {
	s := &runtimeSensor{
		rootPID: rootPID,
		send:    send,
		events:  make(chan runtimeSensorEvent, runtimeSensorQueueCapacity),
		stopCh:  make(chan struct{}),
	}
	detail := fmt.Sprintf("started pid=%d file_source=ptrace", rootPID)
	if meta, err := os.ReadFile("/etc/aegis-guest-runner.json"); err == nil {
		detail = detail + " meta=" + truncateStatusDetail(strings.TrimSpace(string(meta)))
	}
	s.sendStatus(runtimeSensorStatus{QueueCapacity: runtimeSensorQueueCapacity, Source: "guest-runtime-sensor", Detail: detail})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runSender()
	}()
	return s
}

func (s *runtimeSensor) RecordRootExit(exitCode int) {
	s.enqueue(runtimeSensorEvent{TsUnixNano: time.Now().UnixNano(), Type: "process.exit", PID: s.rootPID, ExitCode: intPtr(exitCode), Metadata: map[string]string{}})
}

func (s *runtimeSensor) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(s.dropped.Load()), FloodDetected: s.flood.Load(), QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: fmt.Sprintf("stopping pid=%d", s.rootPID)})
	close(s.stopCh)
	close(s.events)
	s.wg.Wait()
	return nil
}

func (s *runtimeSensor) runSender() {
	ticker := time.NewTicker(runtimeSensorFlushInterval)
	defer ticker.Stop()
	batch := make([]runtimeSensorEvent, 0, runtimeSensorMaxBatch)

	flush := func() bool {
		dropped := s.dropped.Swap(0)
		flood := s.flood.Swap(false)
		if len(batch) == 0 {
			if dropped == 0 && !flood {
				return true
			}
			return s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(dropped), FloodDetected: flood, QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: "drop-accounting-only"})
		}

		payload, err := json.Marshal(runtimeSensorBatch{Events: append([]runtimeSensorEvent(nil), batch...), Dropped: dropped, FloodDetected: flood, QueueCapacity: cap(s.events)})
		if err != nil {
			return true
		}
		if s.firstBatchSent.CompareAndSwap(false, true) {
			s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(dropped), FloodDetected: flood, QueueCapacity: cap(s.events), BatchEvents: len(batch), Source: "guest-runtime-sensor", Detail: "first-batch-sent"})
		}
		batch = batch[:0]
		return s.send(GuestChunk{Type: "telemetry", Name: guestRuntimeEventBatchKind, Data: payload})
	}

	for {
		select {
		case event, ok := <-s.events:
			if !ok {
				_ = flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= runtimeSensorMaxBatch {
				if !flush() {
					return
				}
			}
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

func (s *runtimeSensor) enqueue(event runtimeSensorEvent) {
	if s.firstEventLogged.CompareAndSwap(false, true) {
		s.sendStatus(runtimeSensorStatus{QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: fmt.Sprintf("first-event type=%s pid=%d", event.Type, event.PID)})
	}
	select {
	case s.events <- event:
	default:
		dropped := s.dropped.Add(1)
		if dropped >= runtimeSensorFloodThreshold {
			s.flood.Store(true)
		}
	}
}

func (s *runtimeSensor) sendStatus(status runtimeSensorStatus) bool {
	payload, err := json.Marshal(status)
	if err != nil {
		return true
	}
	return s.send(GuestChunk{Type: "telemetry", Name: guestRuntimeSensorStatusKind, Data: payload})
}
func intPtr(v int) *int { return &v }

func truncateStatusDetail(s string) string {
	if len(s) <= 160 {
		return s
	}
	return s[:160]
}

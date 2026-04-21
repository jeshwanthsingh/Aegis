package telemetry

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"aegis/internal/escalation"
)

const (
	// Python startup plus point decisions and divergence updates can exceed the
	// original 256-event buffer before broker/governed-action events arrive.
	// Keep the per-execution buffer comfortably above that so receipts retain
	// late critical evidence instead of silently dropping it.
	busBufferSize        = 4096
	subscriberBufferSize = 256
)

// Bus is a per-execution, in-process telemetry event bus.
type Bus struct {
	execID      string
	events      chan Event
	closeOnce   sync.Once
	mu          sync.RWMutex
	closed      bool
	subscribers []chan Event
	escalation  *escalation.Tracker
	terminate   func(string)
}

// NewBus creates a new per-execution telemetry bus.
func NewBus(execID string) *Bus {
	return &Bus{
		execID: execID,
		events: make(chan Event, busBufferSize),
	}
}

// ExecID returns the execution identifier associated with the bus.
func (b *Bus) ExecID() string {
	return b.execID
}

// Emit publishes an event to the internal buffer and active subscribers without blocking.
func (b *Bus) Emit(kind string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Warn("telemetry event marshal failed", "exec_id", b.execID, "kind", kind, "error", err)
		return
	}

	event := Event{
		ExecID:    b.execID,
		Timestamp: time.Now().UnixMilli(),
		Kind:      kind,
		Data:      json.RawMessage(payload),
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	select {
	case b.events <- event:
	default:
		slog.Warn("telemetry buffer full; dropping event", "exec_id", b.execID, "kind", kind)
	}

	for _, sub := range b.subscribers {
		select {
		case sub <- event:
		default:
		}
	}
}

// Subscribe registers a buffered subscriber channel and returns an unsubscribe function.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBufferSize)

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	b.subscribers = append(b.subscribers, ch)
	b.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()

			for i, sub := range b.subscribers {
				if sub == ch {
					b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
					close(ch)
					return
				}
			}
		})
	}

	return ch, unsubscribe
}

func (b *Bus) ConfigureEscalation(tracker *escalation.Tracker, terminate func(string)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.escalation = tracker
	b.terminate = terminate
}

func (b *Bus) ClassifyEscalation(observation escalation.Observation) *escalation.Evidence {
	b.mu.RLock()
	tracker := b.escalation
	b.mu.RUnlock()
	if tracker == nil {
		return nil
	}
	return tracker.Classify(observation)
}

func (b *Bus) TriggerTermination(reason string) {
	b.mu.RLock()
	terminate := b.terminate
	b.mu.RUnlock()
	if terminate != nil {
		terminate(reason)
	}
}

// Close shuts down the bus and closes all subscriber channels.
func (b *Bus) Close() {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		b.closed = true
		close(b.events)

		for _, sub := range b.subscribers {
			close(sub)
		}
		b.subscribers = nil
	})
}

// Drain returns all events currently buffered on the bus in FIFO order.
func (b *Bus) Drain() []Event {
	drained := make([]Event, 0)

	for {
		select {
		case event, ok := <-b.events:
			if !ok {
				return drained
			}
			drained = append(drained, event)
		default:
			return drained
		}
	}
}

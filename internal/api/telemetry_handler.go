package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"aegis/internal/observability"
	"aegis/internal/telemetry"
)

var (
	telemetryLookupWait          = 5 * time.Second
	telemetryLookupPoll          = 25 * time.Millisecond
	maxTelemetryWaiters    int64 = 64
	activeTelemetryWaiters atomic.Int64
)

// NewTelemetryHandler streams telemetry events for a specific execution ID as SSE.
func NewTelemetryHandler(registry *BusRegistry, allowedOrigins []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		applyAllowedOrigin(w, r, allowedOrigins)

		execID := r.PathValue("exec_id")
		if execID == "" {
			http.Error(w, `{"error":"execution not found"}`, http.StatusNotFound)
			return
		}
		if _, err := chooseExecutionID(execID); err != nil {
			http.Error(w, `{"error":"invalid execution_id"}`, http.StatusBadRequest)
			return
		}

		releaseWaiter, ok := acquireTelemetryWaiter()
		if !ok {
			http.Error(w, `{"error":"too many pending telemetry subscriptions"}`, http.StatusTooManyRequests)
			return
		}
		bus, ok := waitForBus(r.Context(), registry, execID, telemetryLookupWait, telemetryLookupPoll)
		releaseWaiter()
		if !ok {
			http.Error(w, `{"error":"execution not found"}`, http.StatusNotFound)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		ch, unsubscribe := bus.Subscribe()
		defer unsubscribe()

		for {
			select {
			case event, ok := <-ch:
				if !ok {
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					observability.Warn("telemetry_sse_encode_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
					continue
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
					observability.Warn("telemetry_sse_write_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
					return
				}
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

func acquireTelemetryWaiter() (func(), bool) {
	if maxTelemetryWaiters <= 0 {
		return func() {}, true
	}
	for {
		current := activeTelemetryWaiters.Load()
		if current >= maxTelemetryWaiters {
			return nil, false
		}
		if activeTelemetryWaiters.CompareAndSwap(current, current+1) {
			var released atomic.Bool
			return func() {
				if released.CompareAndSwap(false, true) {
					activeTelemetryWaiters.Add(-1)
				}
			}, true
		}
	}
}

func waitForBus(ctx context.Context, registry *BusRegistry, execID string, wait time.Duration, poll time.Duration) (*telemetry.Bus, bool) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		if bus, ok := registry.Get(execID); ok {
			return bus, true
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-deadline.C:
			return nil, false
		case <-ticker.C:
		}
	}
}

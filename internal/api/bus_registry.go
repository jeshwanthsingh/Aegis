package api

import (
	"sync"
	"time"

	"aegis/internal/telemetry"
)

type busEntry struct {
	bus       *telemetry.Bus
	expiresAt time.Time
}

const defaultBusRetention = 15 * time.Second

// BusRegistry maps execution IDs to their telemetry buses.
type BusRegistry struct {
	mu        sync.Mutex
	buses     map[string]busEntry
	retainFor time.Duration
}

// NewBusRegistry creates an empty execution bus registry.
func NewBusRegistry() *BusRegistry {
	return newBusRegistry(defaultBusRetention)
}

func newBusRegistry(retainFor time.Duration) *BusRegistry {
	return &BusRegistry{
		buses:     make(map[string]busEntry),
		retainFor: retainFor,
	}
}

// TryRegister stores the bus for an execution ID if it is not already active or retained.
func (r *BusRegistry) TryRegister(execID string, bus *telemetry.Bus) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.purgeExpiredLocked(time.Now())
	if _, exists := r.buses[execID]; exists {
		return false
	}

	r.buses[execID] = busEntry{bus: bus}
	return true
}

// Get returns the active registered bus for an execution ID.
func (r *BusRegistry) Get(execID string) (*telemetry.Bus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.purgeExpiredLocked(time.Now())
	entry, ok := r.buses[execID]
	if !ok || entry.bus == nil {
		return nil, false
	}
	return entry.bus, true
}

// Complete marks an execution ID as recently completed and retains the claim for a short TTL.
func (r *BusRegistry) Complete(execID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.buses[execID]
	if !ok {
		return
	}
	if r.retainFor <= 0 {
		delete(r.buses, execID)
		return
	}
	entry.bus = nil
	entry.expiresAt = time.Now().Add(r.retainFor)
	r.buses[execID] = entry
}

func (r *BusRegistry) purgeExpiredLocked(now time.Time) {
	for execID, entry := range r.buses {
		if entry.bus == nil && !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			delete(r.buses, execID)
		}
	}
}

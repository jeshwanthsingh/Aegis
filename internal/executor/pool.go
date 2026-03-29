package executor

import (
	"errors"
)

// ErrPoolFull is returned when all VM slots are occupied.
var ErrPoolFull = errors.New("worker pool at capacity")

// Pool is a counting semaphore that bounds concurrent VM executions.
type Pool struct {
	slots    chan struct{}
	capacity int
}

// NewPool creates a pool with capacity concurrent slots.
func NewPool(capacity int) *Pool {
	slots := make(chan struct{}, capacity)
	for i := 0; i < capacity; i++ {
		slots <- struct{}{}
	}
	return &Pool{slots: slots, capacity: capacity}
}

// Acquire claims a slot. Returns ErrPoolFull immediately if none are available.
func (p *Pool) Acquire() error {
	select {
	case <-p.slots:
		return nil
	default:
		return ErrPoolFull
	}
}

// Release returns a slot to the pool.
func (p *Pool) Release() {
	p.slots <- struct{}{}
}

// Available returns the number of free slots.
func (p *Pool) Available() int {
	return len(p.slots)
}

// Capacity returns the total number of slots in the pool.
func (p *Pool) Capacity() int {
	return p.capacity
}

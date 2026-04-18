package api

import (
	"net/http"
	"sync/atomic"

	"aegis/internal/receipt"
)

// Stats tracks aggregate containment statistics.
type Stats struct {
	TotalExecutions int64 `json:"total_executions"`
	TotalCompleted  int64 `json:"total_completed"`
	TotalContained  int64 `json:"total_contained"`
}

// StatsCounter maintains in-memory aggregate execution counters.
type StatsCounter struct {
	total     atomic.Int64
	completed atomic.Int64
	contained atomic.Int64
}

// NewStatsCounter creates a zeroed aggregate stats counter.
func NewStatsCounter() *StatsCounter {
	return &StatsCounter{}
}

// RecordReceipt increments aggregate counters from the signed receipt statement.
func (s *StatsCounter) RecordReceipt(statement receipt.Statement) {
	s.total.Add(1)
	if statement.Predicate.ResultClass == receipt.ResultClassCompleted {
		s.completed.Add(1)
	} else {
		s.contained.Add(1)
	}
}

// Snapshot returns a consistent view of the current counters.
func (s *StatsCounter) Snapshot() Stats {
	return Stats{
		TotalExecutions: s.total.Load(),
		TotalCompleted:  s.completed.Load(),
		TotalContained:  s.contained.Load(),
	}
}

// NewStatsHandler returns an HTTP handler that serves the aggregate stats snapshot.
func NewStatsHandler(counter *StatsCounter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, http.StatusOK, counter.Snapshot())
	}
}

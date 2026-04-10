package api

import (
	"net/http"
	"sync/atomic"

	"aegis/internal/models"
)

// Stats tracks aggregate containment statistics.
type Stats struct {
	TotalExecutions    int64 `json:"total_executions"`
	TotalCompleted     int64 `json:"total_completed"`
	TotalContained     int64 `json:"total_contained"`
	DNSQueriesTotal    int64 `json:"dns_queries_total"`
	DNSQueriesAllowed  int64 `json:"dns_queries_allowed"`
	DNSQueriesDenied   int64 `json:"dns_queries_denied"`
	IptablesRulesAdded int64 `json:"iptables_rules_added"`
	CleanTeardowns     int64 `json:"clean_teardowns"`
	Escapes            int64 `json:"escapes"`
}

// StatsCounter maintains in-memory aggregate execution counters.
type StatsCounter struct {
	total              atomic.Int64
	completed          atomic.Int64
	contained          atomic.Int64
	dnsQueriesTotal    atomic.Int64
	dnsQueriesAllowed  atomic.Int64
	dnsQueriesDenied   atomic.Int64
	iptablesRulesAdded atomic.Int64
	cleanTeardowns     atomic.Int64
	escapes            atomic.Int64
}

// NewStatsCounter creates a zeroed aggregate stats counter.
func NewStatsCounter() *StatsCounter {
	return &StatsCounter{}
}

// RecordReceipt increments aggregate counters from the final containment receipt.
func (s *StatsCounter) RecordReceipt(receipt models.ContainmentReceipt) {
	s.total.Add(1)
	if receipt.Verdict == "completed" {
		s.completed.Add(1)
	} else {
		s.contained.Add(1)
	}
	s.dnsQueriesTotal.Add(int64(receipt.Network.DNSQueriesTotal))
	s.dnsQueriesAllowed.Add(int64(receipt.Network.DNSQueriesAllowed))
	s.dnsQueriesDenied.Add(int64(receipt.Network.DNSQueriesDenied))
	s.iptablesRulesAdded.Add(int64(receipt.Network.IptablesRulesAdded))
	if receipt.Cleanup.AllClean {
		s.cleanTeardowns.Add(1)
	}
}

// Snapshot returns a consistent view of the current counters.
func (s *StatsCounter) Snapshot() Stats {
	return Stats{
		TotalExecutions:    s.total.Load(),
		TotalCompleted:     s.completed.Load(),
		TotalContained:     s.contained.Load(),
		DNSQueriesTotal:    s.dnsQueriesTotal.Load(),
		DNSQueriesAllowed:  s.dnsQueriesAllowed.Load(),
		DNSQueriesDenied:   s.dnsQueriesDenied.Load(),
		IptablesRulesAdded: s.iptablesRulesAdded.Load(),
		CleanTeardowns:     s.cleanTeardowns.Load(),
		Escapes:            s.escapes.Load(),
	}
}

// NewStatsHandler returns an HTTP handler that serves the aggregate stats snapshot.
func NewStatsHandler(counter *StatsCounter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeJSON(w, http.StatusOK, counter.Snapshot())
	}
}

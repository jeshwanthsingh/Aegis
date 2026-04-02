package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/models"
)

func TestStatsCounterAllowReceiptUpdatesCounters(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "completed",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    1,
			DNSQueriesAllowed:  1,
			DNSQueriesDenied:   0,
			IptablesRulesAdded: 2,
		},
		Cleanup: models.ReceiptCleanup{AllClean: true},
	})

	got := counter.Snapshot()
	if got.TotalExecutions != 1 || got.TotalCompleted != 1 || got.TotalContained != 0 {
		t.Fatalf("unexpected execution counters: %#v", got)
	}
	if got.DNSQueriesTotal != 1 || got.DNSQueriesAllowed != 1 || got.DNSQueriesDenied != 0 {
		t.Fatalf("unexpected dns counters: %#v", got)
	}
	if got.IptablesRulesAdded != 2 || got.CleanTeardowns != 1 || got.Escapes != 0 {
		t.Fatalf("unexpected network/cleanup counters: %#v", got)
	}
}

func TestStatsCounterDenyReceiptUpdatesCounters(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "contained",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    1,
			DNSQueriesAllowed:  0,
			DNSQueriesDenied:   1,
			IptablesRulesAdded: 0,
		},
		Cleanup: models.ReceiptCleanup{AllClean: true},
	})

	got := counter.Snapshot()
	if got.TotalExecutions != 1 || got.TotalCompleted != 0 || got.TotalContained != 1 {
		t.Fatalf("unexpected execution counters: %#v", got)
	}
	if got.DNSQueriesTotal != 1 || got.DNSQueriesAllowed != 0 || got.DNSQueriesDenied != 1 {
		t.Fatalf("unexpected dns counters: %#v", got)
	}
	if got.IptablesRulesAdded != 0 || got.CleanTeardowns != 1 {
		t.Fatalf("unexpected network/cleanup counters: %#v", got)
	}
}

func TestStatsCounterNoNetworkReceiptLeavesDNSCountersUnchanged(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "completed",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    0,
			DNSQueriesAllowed:  0,
			DNSQueriesDenied:   0,
			IptablesRulesAdded: 0,
			NetworkMode:        "none",
		},
		Cleanup: models.ReceiptCleanup{AllClean: false},
	})

	got := counter.Snapshot()
	if got.DNSQueriesTotal != 0 || got.DNSQueriesAllowed != 0 || got.DNSQueriesDenied != 0 || got.IptablesRulesAdded != 0 {
		t.Fatalf("unexpected dns/rule counters: %#v", got)
	}
}

func TestStatsHandlerReturnsAggregatesAfterMultipleReceipts(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "completed",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    1,
			DNSQueriesAllowed:  1,
			DNSQueriesDenied:   0,
			IptablesRulesAdded: 2,
		},
		Cleanup: models.ReceiptCleanup{AllClean: true},
	})
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "contained",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    1,
			DNSQueriesAllowed:  0,
			DNSQueriesDenied:   1,
			IptablesRulesAdded: 0,
		},
		Cleanup: models.ReceiptCleanup{AllClean: true},
	})
	counter.RecordReceipt(models.ContainmentReceipt{
		Verdict: "completed",
		Network: models.ReceiptNetwork{
			DNSQueriesTotal:    0,
			DNSQueriesAllowed:  0,
			DNSQueriesDenied:   0,
			IptablesRulesAdded: 0,
			NetworkMode:        "none",
		},
		Cleanup: models.ReceiptCleanup{AllClean: false},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rr := httptest.NewRecorder()
	NewStatsHandler(counter).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusOK)
	}

	var got Stats
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal stats response: %v", err)
	}
	if got.TotalExecutions != 3 || got.TotalCompleted != 2 || got.TotalContained != 1 {
		t.Fatalf("unexpected execution counters: %#v", got)
	}
	if got.DNSQueriesTotal != 2 || got.DNSQueriesAllowed != 1 || got.DNSQueriesDenied != 1 {
		t.Fatalf("unexpected dns counters: %#v", got)
	}
	if got.IptablesRulesAdded != 2 || got.CleanTeardowns != 2 || got.Escapes != 0 {
		t.Fatalf("unexpected network/cleanup counters: %#v", got)
	}
}

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/receipt"
)

func TestStatsCounterCompletedReceiptUpdatesCounters(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{ResultClass: receipt.ResultClassCompleted}})

	got := counter.Snapshot()
	if got.TotalExecutions != 1 || got.TotalCompleted != 1 || got.TotalContained != 0 {
		t.Fatalf("unexpected execution counters: %#v", got)
	}
}

func TestStatsCounterNonCompletedReceiptUpdatesCounters(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{ResultClass: receipt.ResultClassDenied}})

	got := counter.Snapshot()
	if got.TotalExecutions != 1 || got.TotalCompleted != 0 || got.TotalContained != 1 {
		t.Fatalf("unexpected execution counters: %#v", got)
	}
}

func TestStatsHandlerReturnsAggregatesAfterMultipleReceipts(t *testing.T) {
	t.Parallel()

	counter := NewStatsCounter()
	counter.RecordReceipt(receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{ResultClass: receipt.ResultClassCompleted}})
	counter.RecordReceipt(receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{ResultClass: receipt.ResultClassDenied}})
	counter.RecordReceipt(receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{ResultClass: receipt.ResultClassCompleted}})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rr := httptest.NewRecorder()
	NewStatsHandler(counter, nil).ServeHTTP(rr, req)

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
}

func TestStatsHandlerNoWildcardCORSByDefault(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()

	NewStatsHandler(NewStatsCounter(), nil).ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS header: %q", got)
	}
}

func TestStatsHandlerAllowsConfiguredOrigin(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.Header.Set("Origin", "https://app.example")
	rr := httptest.NewRecorder()

	NewStatsHandler(NewStatsCounter(), []string{"https://app.example"}).ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("unexpected CORS header: %q", got)
	}
}

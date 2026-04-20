package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/executor"
)

func TestHealthHandlerOmitsWarmPoolInternals(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()

	HandleHealth(executor.NewPool(5), nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := payload["warm_pool"]; ok {
		t.Fatalf("health payload should not expose warm_pool internals: %s", rr.Body.String())
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected health status: %#v", payload["status"])
	}
}

func TestReadyHandlerOmitsWarmPoolInternals(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	HandleReady(nil, executor.NewPool(1), nil).ServeHTTP(rr, req)

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := payload["warm_pool"]; ok {
		t.Fatalf("ready payload should not expose warm_pool internals: %s", rr.Body.String())
	}
	if payload["status"] != "not_ready" {
		t.Fatalf("unexpected ready status: %#v", payload["status"])
	}
}

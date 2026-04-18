package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTelemetryHandlerNoWildcardCORSByDefault(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/events/not-a-uuid", nil)
	req.SetPathValue("exec_id", "not-a-uuid")
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()

	NewTelemetryHandler(NewBusRegistry(), nil).ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS header: %q", got)
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
}

func TestTelemetryHandlerAllowsConfiguredOrigin(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/events/not-a-uuid", nil)
	req.SetPathValue("exec_id", "not-a-uuid")
	req.Header.Set("Origin", "https://app.example")
	rr := httptest.NewRecorder()

	NewTelemetryHandler(NewBusRegistry(), []string{"https://app.example"}).ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("unexpected CORS header: %q", got)
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
}

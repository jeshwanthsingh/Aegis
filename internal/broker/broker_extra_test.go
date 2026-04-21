package broker

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/governance"
	"aegis/internal/telemetry"
)

func TestBroker_HandleRejectsInvalidURLAndMalformedBody(t *testing.T) {
	bus := telemetry.NewBus("exec-broker")
	b := makeTestBroker(t, []string{"example.com"}, nil, bus)

	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: "://bad-url"})
	if !resp.Denied || resp.DenyReason != "broker.invalid_url" {
		t.Fatalf("invalid URL response = %+v", resp)
	}

	resp = b.Handle(BrokerRequest{
		Method:     http.MethodPost,
		URL:        "http://example.com/data",
		BodyBase64: "%%%bad%%%",
	})
	if resp.Error == "" || !strings.Contains(resp.Error, "decode body") {
		t.Fatalf("malformed body response = %+v", resp)
	}

	events := bus.Drain()
	foundError := false
	for _, event := range events {
		if event.Kind == telemetry.KindCredentialError {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Fatal("expected credential.error telemetry event")
	}
}

func TestBroker_HandleSanitizesGuestAndUpstreamHeaders(t *testing.T) {
	var guestAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guestAuth = r.Header.Get("Authorization")
		w.Header().Set("Authorization", "should-not-leak")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer srv.Close()

	t.Setenv("AEGIS_CRED_TESTTOKEN_TOKEN", "secret-test-value")
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeTestBroker(t, []string{host, "*.example.org", host + ":443"}, []string{"testtoken"}, nil)

	resp := b.Handle(BrokerRequest{
		Method: http.MethodPost,
		URL:    srv.URL + "/path",
		Headers: map[string][]string{
			"Authorization": {"Bearer guest-should-not-pass"},
			"X-Test":        {"forward-me"},
		},
		BodyBase64: base64.StdEncoding.EncodeToString([]byte("payload")),
	})
	if !resp.Allowed || resp.StatusCode != http.StatusCreated {
		t.Fatalf("response = %+v", resp)
	}
	if guestAuth != "Bearer secret-test-value" {
		t.Fatalf("Authorization header = %q", guestAuth)
	}
	if _, ok := resp.Headers["Authorization"]; ok {
		t.Fatalf("unexpected Authorization response header: %+v", resp.Headers)
	}
	if _, ok := resp.Headers["Set-Cookie"]; ok {
		t.Fatalf("unexpected Set-Cookie response header: %+v", resp.Headers)
	}
	if got := resp.Headers["X-Test"]; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("X-Test header = %+v", resp.Headers)
	}
}

func TestBroker_AllowedDomainsAndWildcardMatching(t *testing.T) {
	b := makeTestBroker(t, []string{"api.example.com", "*.example.org", "example.net:443"}, nil, nil)
	if got := b.AllowedDomains(); len(got) != 3 {
		t.Fatalf("AllowedDomains length = %d", len(got))
	}
	for name, allowed := range map[string]bool{
		"api.example.com":    true,
		"sub.example.org":    true,
		"example.net":        true,
		"denied.example.com": false,
	} {
		if got := governance.DomainAllowed(b.AllowedDomains(), name); got != allowed {
			t.Fatalf("domainAllowed(%q) = %v, want %v", name, got, allowed)
		}
	}
}

func TestBroker_DenyErrorUsesForbiddenEnvelope(t *testing.T) {
	b := makeTestBroker(t, []string{"example.com"}, nil, nil)
	resp := b.denyError("", "http_request", "digest", "broker.invalid_url", "invalid URL", nil)
	if !resp.Denied || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denyError response = %+v", resp)
	}
}

package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/governance"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

func makeTestBroker(domains []string, delegations []string, bus *telemetry.Bus) *Broker {
	return New(contract.BrokerScope{
		AllowedDomains:     domains,
		AllowedDelegations: delegations,
	}, "test-exec-id", bus)
}

func makeActionBroker(domains []string, delegations []string, actionTypes []string, bus *telemetry.Bus) *Broker {
	return New(contract.BrokerScope{
		AllowedDomains:     domains,
		AllowedDelegations: delegations,
		AllowedActionTypes: actionTypes,
	}, "test-exec-id", bus)
}

func TestBroker_DomainDenied(t *testing.T) {
	b := makeTestBroker([]string{"allowed.example.com"}, nil, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: "http://denied.example.com/api"})
	if !resp.Denied {
		t.Fatal("expected Denied=true")
	}
	if resp.DenyReason != "broker.domain_denied" {
		t.Fatalf("wrong reason: %s", resp.DenyReason)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestBroker_AllowedDomain_NoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeTestBroker([]string{host}, nil, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/test"})
	if resp.Denied {
		t.Fatalf("expected allowed, denied: %s", resp.DenyReason)
	}
	if !resp.Allowed {
		t.Fatal("expected Allowed=true")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestBroker_MissingConfiguredBindingDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeTestBroker([]string{host}, []string{"missing-binding"}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/api"})
	if !resp.Denied {
		t.Fatal("expected denied response")
	}
	if resp.DenyReason != "broker.binding_unavailable" {
		t.Fatalf("wrong deny reason: %s", resp.DenyReason)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestBroker_AllowedDomain_WithCredential(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("AEGIS_CRED_TESTTOKEN_TOKEN", "secret-test-value")
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeTestBroker([]string{host}, []string{"testtoken"}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/api"})
	if !resp.Allowed {
		t.Fatalf("expected allowed, denied: %s", resp.DenyReason)
	}
	respJSON, _ := json.Marshal(resp)
	if strings.Contains(string(respJSON), "secret-test-value") {
		t.Fatal("raw credential in response")
	}
	if receivedAuth != "Bearer secret-test-value" {
		t.Fatalf("missing auth header: %q", receivedAuth)
	}
}

func TestBroker_ConnectDenied(t *testing.T) {
	b := makeTestBroker([]string{"example.com"}, nil, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodConnect, URL: "example.com:443"})
	if !resp.Denied {
		t.Fatal("expected CONNECT denied")
	}
}

func TestBroker_NoBrokerScope_DeniesAll(t *testing.T) {
	b := makeTestBroker(nil, nil, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: "http://api.example.com/data"})
	if !resp.Denied {
		t.Fatal("expected deny with no domains")
	}
}

func TestBroker_EmitsTelemetryEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	bus := telemetry.NewBus("test-exec-id")
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeTestBroker([]string{host}, nil, bus)
	_ = b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/test"})
	events := bus.Drain()
	foundReq, foundAllowed := false, false
	for _, ev := range events {
		if ev.Kind == telemetry.KindCredentialRequest {
			foundReq = true
		}
		if ev.Kind == telemetry.KindCredentialAllowed {
			foundAllowed = true
		}
	}
	if !foundReq {
		t.Error("credential.request not emitted")
	}
	if !foundAllowed {
		t.Error("credential.allowed not emitted")
	}
}

func TestBroker_DenialEmitsTelemetry(t *testing.T) {
	bus := telemetry.NewBus("test-exec-id")
	b := makeTestBroker([]string{"allowed.example.com"}, nil, bus)
	_ = b.Handle(BrokerRequest{Method: http.MethodGet, URL: "http://denied.example.com/"})
	events := bus.Drain()
	foundDenied := false
	for _, ev := range events {
		if ev.Kind == telemetry.KindCredentialDenied {
			foundDenied = true
		}
	}
	if !foundDenied {
		t.Error("credential.denied not emitted")
	}
}

func TestBroker_DependencyFetchRequiresExplicitGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeActionBroker([]string{host}, nil, []string{governance.ActionHTTPRequest}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/pkg.whl", ActionType: governance.ActionDependencyFetch})
	if !resp.Denied {
		t.Fatal("expected dependency_fetch denied without explicit grant")
	}
	if resp.DenyReason != "governance.action_type_denied" {
		t.Fatalf("wrong deny reason: %s", resp.DenyReason)
	}
}

func TestBroker_DependencyFetchDeniedForUnapprovedSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b := makeActionBroker([]string{"example.invalid"}, nil, []string{governance.ActionDependencyFetch}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/pkg.whl", ActionType: governance.ActionDependencyFetch})
	if !resp.Denied {
		t.Fatal("expected dependency_fetch denied for unapproved source")
	}
	if resp.DenyReason != "broker.domain_denied" {
		t.Fatalf("wrong deny reason: %s", resp.DenyReason)
	}
}

func TestBroker_DependencyFetchAllowsReadOnlyMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("wheel"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeActionBroker([]string{host}, nil, []string{governance.ActionDependencyFetch}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/pkg.whl", ActionType: governance.ActionDependencyFetch})
	if !resp.Allowed {
		t.Fatalf("expected allowed dependency_fetch, got %+v", resp)
	}
}

func TestBroker_HTTPRequestAllowedWithExplicitGrantAndCredential(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	t.Setenv("AEGIS_CRED_TESTTOKEN_TOKEN", "secret-test-value")
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeActionBroker([]string{host}, []string{"testtoken"}, []string{governance.ActionHTTPRequest}, nil)
	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/api", ActionType: governance.ActionHTTPRequest})
	if !resp.Allowed || receivedAuth != "Bearer secret-test-value" {
		t.Fatalf("unexpected explicit http_request allow result: resp=%+v auth=%q", resp, receivedAuth)
	}
}

func TestBroker_GovernedActionTelemetryIncludesDigestAndDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	bus := telemetry.NewBus("test-exec-id")
	host := strings.TrimPrefix(srv.URL, "http://")
	b := makeActionBroker([]string{host}, nil, []string{governance.ActionHTTPRequest}, bus)
	_ = b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/test", ActionType: governance.ActionHTTPRequest})
	events := bus.Drain()
	found := false
	for _, ev := range events {
		if ev.Kind != telemetry.KindGovernedAction {
			continue
		}
		var data telemetry.GovernedActionData
		if err := json.Unmarshal(ev.Data, &data); err != nil {
			t.Fatalf("unmarshal governed action: %v", err)
		}
		found = true
		if data.ActionType != governance.ActionHTTPRequest || data.Decision != "allow" || data.ResponseDigest == "" {
			t.Fatalf("unexpected governed action data: %+v", data)
		}
		if data.CapabilityPath != string(governance.CapabilityPathBroker) || !data.Used {
			t.Fatalf("missing capability boundary evidence: %+v", data)
		}
		if data.BrokeredCredentials {
			t.Fatalf("unexpected governed action data: %+v", data)
		}
	}
	if !found {
		t.Fatal("governed.action.v1 not emitted")
	}
}

func TestLoadBinding_EnvVar(t *testing.T) {
	t.Setenv("AEGIS_CRED_MYGITHUB_TOKEN", "ghp_testtoken123")
	binding, ok := LoadBinding("mygithub")
	if !ok {
		t.Fatal("expected binding loaded")
	}
	if binding.BearerToken() != "Bearer ghp_testtoken123" {
		t.Fatalf("wrong token: %s", binding.BearerToken())
	}
}

func TestLoadBinding_Missing(t *testing.T) {
	binding, ok := LoadBinding("nonexistent-credential")
	if ok {
		t.Fatal("expected missing binding")
	}
	if binding.IsLoaded() {
		t.Fatal("expected IsLoaded=false")
	}
}

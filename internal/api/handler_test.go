package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"aegis/internal/executor"
	"aegis/internal/policy"
	"aegis/internal/telemetry"
)

func TestChooseExecutionIDGeneratedWhenMissing(t *testing.T) {
	t.Parallel()

	id, err := chooseExecutionID("")
	if err != nil {
		t.Fatalf("chooseExecutionID returned error: %v", err)
	}
	if id == "" {
		t.Fatal("expected generated execution id")
	}
}

func TestChooseExecutionIDUsesProvided(t *testing.T) {
	t.Parallel()

	want := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"
	id, err := chooseExecutionID(want)
	if err != nil {
		t.Fatalf("chooseExecutionID returned error: %v", err)
	}
	if id != want {
		t.Fatalf("unexpected execution id: got %q want %q", id, want)
	}
}

func TestChooseExecutionIDRejectsMalformed(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"not-a-uuid", " 30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", "bad/id"} {
		if _, err := chooseExecutionID(raw); err == nil {
			t.Fatalf("expected invalid execution_id error for %q", raw)
		}
	}
}

func TestExecuteHandlerRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":-1}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), "timeout_ms") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestExecuteHandlerZeroTimeoutUsesDefault(t *testing.T) {
	t.Parallel()

	registry := NewBusRegistry()
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad7a"
	if !registry.TryRegister(execID, telemetry.NewBus(execID)) {
		t.Fatal("failed to seed active execution bus")
	}

	handler := NewHandler(nil, executor.NewPool(1), policy.Default(), "", "", registry, NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"`+execID+`","lang":"python","code":"print(1)","timeout_ms":0}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Fatalf("zero timeout unexpectedly rejected: %s", rr.Body.String())
	}
}

func TestExecuteHandlerRejectsInvalidProfile(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"profile":"godmode"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid compute profile") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestDeleteWorkspaceRejectsInvalidWorkspaceID(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete, "/v1/workspaces/../escape", nil)
	req.SetPathValue("id", "../escape")
	rr := httptest.NewRecorder()

	HandleDeleteWorkspace().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), executor.ErrInvalidWorkspaceID.Error()) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestTelemetryHandlerRejectsMalformedExecID(t *testing.T) {
	t.Parallel()

	registry := NewBusRegistry()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/not-a-uuid", nil)
	req.SetPathValue("exec_id", "not-a-uuid")
	rr := httptest.NewRecorder()

	NewTelemetryHandler(registry).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestTelemetryHandlerWaitsForFutureBusAndStreams(t *testing.T) {
	registry := NewBusRegistry()
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"

	telemetryLookupWait = 250 * time.Millisecond
	telemetryLookupPoll = 10 * time.Millisecond
	t.Cleanup(func() {
		telemetryLookupWait = 5 * time.Second
		telemetryLookupPoll = 25 * time.Millisecond
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/events/{exec_id}", NewTelemetryHandler(registry))
	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/events/"+execID, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	type response struct {
		status int
		body   string
	}
	respCh := make(chan response, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			respCh <- response{status: 0, body: err.Error()}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		respCh <- response{status: resp.StatusCode, body: string(body)}
	}()

	time.Sleep(50 * time.Millisecond)
	bus := telemetry.NewBus(execID)
	if !registry.TryRegister(execID, bus) {
		t.Fatal("failed to register future bus")
	}
	time.Sleep(25 * time.Millisecond)
	bus.Emit(telemetry.KindVMBootStart, map[string]string{"phase": "boot"})
	time.Sleep(25 * time.Millisecond)
	bus.Close()
	registry.Complete(execID)

	res := <-respCh
	if res.status != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", res.status, res.body)
	}
	if !strings.Contains(res.body, `"exec_id":"`+execID+`"`) {
		t.Fatalf("expected exec_id in stream body: %s", res.body)
	}
	if !strings.Contains(res.body, `"kind":"`+telemetry.KindVMBootStart+`"`) {
		t.Fatalf("expected vm boot event in stream body: %s", res.body)
	}
}

func TestTelemetryHandlerNotFoundAfterWait(t *testing.T) {
	registry := NewBusRegistry()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", nil)
	req.SetPathValue("exec_id", "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b")
	rr := httptest.NewRecorder()

	telemetryLookupWait = 20 * time.Millisecond
	telemetryLookupPoll = 5 * time.Millisecond
	t.Cleanup(func() {
		telemetryLookupWait = 5 * time.Second
		telemetryLookupPoll = 25 * time.Millisecond
	})

	NewTelemetryHandler(registry).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusNotFound)
	}
}

func TestTelemetryHandlerRejectsWhenTooManyWaiters(t *testing.T) {
	registry := NewBusRegistry()
	maxTelemetryWaiters = 1
	telemetryLookupWait = 250 * time.Millisecond
	telemetryLookupPoll = 10 * time.Millisecond
	activeTelemetryWaiters.Store(0)
	t.Cleanup(func() {
		maxTelemetryWaiters = 64
		telemetryLookupWait = 5 * time.Second
		telemetryLookupPoll = 25 * time.Millisecond
		activeTelemetryWaiters.Store(0)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/events/{exec_id}", NewTelemetryHandler(registry))
	server := httptest.NewServer(mux)
	defer server.Close()

	firstDone := make(chan *http.Response, 1)
	go func() {
		resp, _ := http.Get(server.URL + "/v1/events/30454c31-dfdf-4b5f-ae7c-1bddbf09ad70")
		firstDone <- resp
	}()
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(server.URL + "/v1/events/30454c31-dfdf-4b5f-ae7c-1bddbf09ad71")
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unexpected status: got %d want %d", resp.StatusCode, http.StatusTooManyRequests)
	}

	firstResp := <-firstDone
	if firstResp != nil {
		firstResp.Body.Close()
	}
}

func TestTelemetryHandlerMissingExecutionUsesConfiguredWait(t *testing.T) {
	registry := NewBusRegistry()
	telemetryLookupWait = 40 * time.Millisecond
	telemetryLookupPoll = 5 * time.Millisecond
	maxTelemetryWaiters = 64
	activeTelemetryWaiters.Store(0)
	t.Cleanup(func() {
		telemetryLookupWait = 5 * time.Second
		telemetryLookupPoll = 25 * time.Millisecond
		maxTelemetryWaiters = 64
		activeTelemetryWaiters.Store(0)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/events/30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", nil)
	req.SetPathValue("exec_id", "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b")
	rr := httptest.NewRecorder()

	start := time.Now()
	NewTelemetryHandler(registry).ServeHTTP(rr, req)
	elapsed := time.Since(start)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusNotFound)
	}
	if elapsed < 35*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("unexpected wait duration: %v", elapsed)
	}
}

func TestTelemetrySSEEventDecodesAsJSON(t *testing.T) {
	t.Parallel()

	registry := NewBusRegistry()
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"
	bus := telemetry.NewBus(execID)
	if !registry.TryRegister(execID, bus) {
		t.Fatal("failed to register bus")
	}
	defer registry.Complete(execID)
	defer bus.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/events/"+execID, nil)
	req.SetPathValue("exec_id", execID)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		NewTelemetryHandler(registry).ServeHTTP(rr, req)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: 0, Reason: "completed"})
	bus.Close()
	<-done

	reader := bufio.NewReader(strings.NewReader(rr.Body.String()))
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first sse line: %v", err)
	}
	line = strings.TrimPrefix(strings.TrimSpace(line), "data: ")

	var event telemetry.Event
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("unmarshal sse event: %v", err)
	}
	if event.ExecID != execID {
		t.Fatalf("unexpected exec id: got %q want %q", event.ExecID, execID)
	}
}

func TestTelemetryHandlerPreSubscribeStreamsDNSDeny(t *testing.T) {
	registry := NewBusRegistry()
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6d"

	telemetryLookupWait = 250 * time.Millisecond
	telemetryLookupPoll = 10 * time.Millisecond
	t.Cleanup(func() {
		telemetryLookupWait = 5 * time.Second
		telemetryLookupPoll = 25 * time.Millisecond
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/events/{exec_id}", NewTelemetryHandler(registry))
	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/events/"+execID, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	type response struct {
		status int
		body   string
	}
	respCh := make(chan response, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			respCh <- response{status: 0, body: err.Error()}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		respCh <- response{status: resp.StatusCode, body: string(body)}
	}()

	time.Sleep(50 * time.Millisecond)
	bus := telemetry.NewBus(execID)
	if !registry.TryRegister(execID, bus) {
		t.Fatal("failed to register bus")
	}
	time.Sleep(25 * time.Millisecond)
	bus.Emit(telemetry.KindDNSQuery, telemetry.DNSQueryData{
		Domain: "denied.example",
		Action: "deny",
		Reason: "not in allowlist",
	})
	time.Sleep(25 * time.Millisecond)
	bus.Close()
	registry.Complete(execID)

	res := <-respCh
	if res.status != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", res.status, res.body)
	}
	if !strings.Contains(res.body, `"kind":"dns.query"`) {
		t.Fatalf("expected dns.query event in stream body: %s", res.body)
	}
	if !strings.Contains(res.body, `"action":"deny"`) {
		t.Fatalf("expected deny action in stream body: %s", res.body)
	}
}

func TestWaitForBusRespectsCancellation(t *testing.T) {
	t.Parallel()

	registry := NewBusRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, ok := waitForBus(ctx, registry, "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", time.Second, time.Second); ok {
		t.Fatal("expected canceled waitForBus call to fail")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("waitForBus did not respect cancellation promptly: %v", time.Since(start))
	}
}

func TestExecuteHandlerDuplicateActiveExecutionIDReturnsConflict(t *testing.T) {
	t.Parallel()

	registry := newBusRegistry(time.Minute)
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"
	if !registry.TryRegister(execID, telemetry.NewBus(execID)) {
		t.Fatal("failed to seed active execution bus")
	}

	handler := NewHandler(nil, executor.NewPool(1), policy.Default(), "", "", registry, NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"`+execID+`","lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusConflict)
	}
	if !strings.Contains(rr.Body.String(), "execution_id already in use") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestExecuteHandlerDuplicateCompletedExecutionIDReturnsConflict(t *testing.T) {
	t.Parallel()

	registry := newBusRegistry(time.Minute)
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"
	if !registry.TryRegister(execID, telemetry.NewBus(execID)) {
		t.Fatal("failed to seed completed execution bus")
	}
	registry.Complete(execID)

	handler := NewHandler(nil, executor.NewPool(1), policy.Default(), "", "", registry, NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"`+execID+`","lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusConflict)
	}
	if !strings.Contains(rr.Body.String(), "execution_id already in use") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestClaimExecutionBusAllowsDifferentExecutionIDsInParallel(t *testing.T) {
	t.Parallel()

	registry := newBusRegistry(time.Minute)
	execIDs := []string{
		"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
		"e78a3111-5f31-48f8-b8ae-12031ef9f61d",
	}

	type result struct {
		execID string
		err    error
	}
	results := make(chan result, len(execIDs))

	for _, execID := range execIDs {
		execID := execID
		go func() {
			bus, claimedID, err := claimExecutionBus(registry, execID, true)
			if err == nil {
				defer bus.Close()
				registry.Complete(claimedID)
			}
			results <- result{execID: claimedID, err: err}
		}()
	}

	seen := map[string]struct{}{}
	for range execIDs {
		res := <-results
		if res.err != nil {
			t.Fatalf("unexpected claimExecutionBus error for %s: %v", res.execID, res.err)
		}
		seen[res.execID] = struct{}{}
	}

	if len(seen) != len(execIDs) {
		t.Fatalf("expected %d distinct execution ids, got %d", len(execIDs), len(seen))
	}
}

func TestBuildReceiptNetworkAllowCase(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	pol.Network.Mode = "allowlist"
	pol.Network.Presets = []string{"pypi"}

	summary := buildReceiptNetwork(pol, []telemetry.Event{
		mustTelemetryEvent(t, telemetry.KindNetRuleAdd, telemetry.NetRuleData{Rule: "ACCEPT", Dst: "151.101.128.223", Ports: "80"}),
		mustTelemetryEvent(t, telemetry.KindNetRuleAdd, telemetry.NetRuleData{Rule: "ACCEPT", Dst: "151.101.128.223", Ports: "443"}),
		mustTelemetryEvent(t, telemetry.KindDNSQuery, telemetry.DNSQueryData{
			Domain:   "pypi.org",
			Action:   "allow",
			Resolved: []string{"151.101.128.223"},
		}),
	})

	if summary.DNSQueriesTotal != 1 || summary.DNSQueriesAllowed != 1 || summary.DNSQueriesDenied != 0 {
		t.Fatalf("unexpected dns counts: %#v", summary)
	}
	if summary.IptablesRulesAdded != 2 {
		t.Fatalf("unexpected rule count: %#v", summary)
	}
	if summary.NetworkMode != "allowlist" {
		t.Fatalf("unexpected network mode: %#v", summary)
	}
	if !slices.Equal(summary.AllowedDomains, []string{"files.pythonhosted.org", "pypi.org", "pypi.python.org"}) {
		t.Fatalf("unexpected allowed domains: %#v", summary.AllowedDomains)
	}
}

func TestBuildReceiptNetworkDenyCase(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	pol.Network.Mode = "allowlist"
	pol.Network.Presets = []string{"pypi"}

	summary := buildReceiptNetwork(pol, []telemetry.Event{
		mustTelemetryEvent(t, telemetry.KindDNSQuery, telemetry.DNSQueryData{
			Domain: "example.com",
			Action: "deny",
			Reason: "not in allowlist",
		}),
	})

	if summary.DNSQueriesTotal != 1 || summary.DNSQueriesAllowed != 0 || summary.DNSQueriesDenied != 1 {
		t.Fatalf("unexpected dns counts: %#v", summary)
	}
	if summary.IptablesRulesAdded != 0 {
		t.Fatalf("unexpected rule count: %#v", summary)
	}
}

func TestBuildReceiptNetworkNoNetworkCase(t *testing.T) {
	t.Parallel()

	pol := policy.Default()

	summary := buildReceiptNetwork(pol, nil)

	if summary.DNSQueriesTotal != 0 || summary.DNSQueriesAllowed != 0 || summary.DNSQueriesDenied != 0 || summary.IptablesRulesAdded != 0 {
		t.Fatalf("unexpected counts: %#v", summary)
	}
	if summary.NetworkMode != "none" {
		t.Fatalf("unexpected network mode: %#v", summary)
	}
	if len(summary.AllowedDomains) != 0 {
		t.Fatalf("unexpected allowed domains: %#v", summary.AllowedDomains)
	}
}

func mustTelemetryEvent(t *testing.T, kind string, data any) telemetry.Event {
	t.Helper()

	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal telemetry event: %v", err)
	}
	return telemetry.Event{Kind: kind, Data: raw}
}

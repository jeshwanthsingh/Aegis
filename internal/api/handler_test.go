package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"aegis/internal/broker"
	"aegis/internal/capabilities"
	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/policy"
	policycontract "aegis/internal/policy/contract"
	policydivergence "aegis/internal/policy/divergence"
	policyevaluator "aegis/internal/policy/evaluator"
	warmpool "aegis/internal/pool"
	"aegis/internal/receipt"
	"aegis/internal/store"
	"aegis/internal/telemetry"
)

func TestBuildPointEvaluatorRejectsExecutionIDMismatch(t *testing.T) {
	t.Parallel()

	_, _, err := buildPointEvaluator(&ExecuteRequest{
		ExecutionID: "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
		Lang:        "python",
		Intent:      json.RawMessage(`{"version":"v1","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6c","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":[],"write_paths":[],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`),
	}, policy.Default().DefaultTimeoutMs)
	if err == nil {
		t.Fatal("expected execution_id mismatch error")
	}
}

func TestBuildPointEvaluatorAcceptsValidIntent(t *testing.T) {
	t.Parallel()

	eval, intent, err := buildPointEvaluator(&ExecuteRequest{
		Lang:   "python",
		Intent: json.RawMessage(`{"version":"v1","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`),
	}, policy.Default().DefaultTimeoutMs)
	if err != nil {
		t.Fatalf("buildPointEvaluator returned error: %v", err)
	}
	if eval == nil || intent == nil {
		t.Fatal("expected evaluator and intent")
	}
	if intent.ExecutionID != "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b" {
		t.Fatalf("unexpected execution_id: %q", intent.ExecutionID)
	}
}

func TestBuildPointEvaluatorCompilesCapabilitiesRequest(t *testing.T) {
	t.Parallel()

	req := ExecuteRequest{
		Lang: "python",
		Capabilities: &capabilities.Request{
			NetworkDomains: []string{"api.example.com"},
			Broker: &capabilities.BrokerRequest{
				Delegations:  []capabilities.Delegation{{Name: "github", Resource: "https://api.github.com/user"}},
				HTTPRequests: true,
			},
		},
	}
	eval, intent, err := buildPointEvaluator(&req, policy.Default().DefaultTimeoutMs)
	if err != nil {
		t.Fatalf("buildPointEvaluator returned error: %v", err)
	}
	if eval == nil || intent == nil {
		t.Fatal("expected evaluator and compiled intent")
	}
	if req.ExecutionID == "" || len(req.Intent) == 0 {
		t.Fatalf("expected compiled execution_id and intent, got execution_id=%q intent_len=%d", req.ExecutionID, len(req.Intent))
	}
	if !slices.Contains(intent.BrokerScope.AllowedActionTypes, "http_request") {
		t.Fatalf("unexpected broker action types: %v", intent.BrokerScope.AllowedActionTypes)
	}
}

func TestBuildPointEvaluatorRejectsIntentAndCapabilitiesTogether(t *testing.T) {
	t.Parallel()

	_, _, err := buildPointEvaluator(&ExecuteRequest{
		ExecutionID:  "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
		Lang:         "python",
		Intent:       json.RawMessage(`{"version":"v1","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":[],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`),
		Capabilities: &capabilities.Request{NetworkDomains: []string{"api.example.com"}},
	}, policy.Default().DefaultTimeoutMs)
	if err == nil {
		t.Fatal("expected mixed-form request rejection")
	}
	if !strings.Contains(err.Error(), "intent and capabilities cannot both be provided") {
		t.Fatalf("unexpected error: %v", err)
	}
}

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

func TestWarmShapeDecision(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	warm := warmpool.New(warmpool.Config{
		Size:   2,
		MaxAge: time.Minute,
		Shapes: warmpool.DefaultShapes(2, "", "", pol),
	})
	if key, reason := warmShapeDecision(ExecuteRequest{Profile: "standard"}, warm, pol, "", ""); key == "" || reason != "" {
		t.Fatalf("standard should be warm-eligible, key=%q reason=%q", key, reason)
	}
	if key, reason := warmShapeDecision(ExecuteRequest{Profile: "crunch"}, warm, pol, "", ""); key != "" || reason != warmpool.FallbackProfile {
		t.Fatalf("crunch should fall back with profile reason, key=%q reason=%q", key, reason)
	}
	if key, reason := warmShapeDecision(ExecuteRequest{Profile: "nano", WorkspaceID: "demo"}, warm, pol, "", ""); key != "" || reason != warmpool.FallbackWorkspace {
		t.Fatalf("workspace-backed request should fall back with workspace reason, key=%q reason=%q", key, reason)
	}
}

func TestResolveRequestedProfile(t *testing.T) {
	t.Parallel()

	pol := policy.Default()

	if got := resolveRequestedProfile(ExecuteRequest{Profile: "crunch", Lang: "python"}, pol); got != "crunch" {
		t.Fatalf("explicit profile should win, got %q", got)
	}
	if got := resolveRequestedProfile(ExecuteRequest{Lang: "bash"}, pol); got != "nano" {
		t.Fatalf("bash should prefer nano, got %q", got)
	}
	if got := resolveRequestedProfile(ExecuteRequest{Lang: "python"}, pol); got != "standard" {
		t.Fatalf("python should prefer standard, got %q", got)
	}
	if got := resolveRequestedProfile(ExecuteRequest{Lang: "ruby"}, pol); got != "standard" {
		t.Fatalf("unknown language should prefer standard, got %q", got)
	}
	if got := resolveRequestedProfile(ExecuteRequest{}, pol); got != "standard" {
		t.Fatalf("empty language should prefer standard, got %q", got)
	}
}

func TestExecuteHandlerReportsDispatchPathAndFallbackReason(t *testing.T) {
	installHandlerRuntimeStubs(t)

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"dispatch_path":"cold"`) || !strings.Contains(body, `"cold_fallback_reason":"pool_disabled"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestResourcesForProfileUsesProfileMemoryPlusOverhead(t *testing.T) {
	t.Parallel()

	base := policy.ResourcePolicy{MemoryMaxMB: 128, CPUPercent: 50, PidsMax: 100, TimeoutMs: 10000}
	profile := policy.ComputeProfile{VCPUCount: 2, MemoryMB: 512}

	got := resourcesForProfile(base, profile)

	want := profile.MemoryMB + vmmOverheadMB
	if got.MemoryMaxMB != want {
		t.Fatalf("unexpected memory max: got %d want %d", got.MemoryMaxMB, want)
	}
	if got.CPUPercent != base.CPUPercent || got.PidsMax != base.PidsMax || got.TimeoutMs != base.TimeoutMs {
		t.Fatalf("non-memory resources changed unexpectedly: %+v", got)
	}
}

func TestClassifyExecutionResultSecurityDenied(t *testing.T) {
	t.Parallel()

	outcome, status, metric := classifyExecutionResult(137, "security_denied_symlink_open")
	if outcome != "contained" || status != "security_denied" || metric != "contained" {
		t.Fatalf("unexpected classification: outcome=%q status=%q metric=%q", outcome, status, metric)
	}
}

func TestExecuteHandlerRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
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

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"`+execID+`","lang":"python","code":"print(1)","timeout_ms":0}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Fatalf("zero timeout unexpectedly rejected: %s", rr.Body.String())
	}
}

func TestExecuteHandlerRejectsInvalidProfile(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
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

func TestExecuteHandlerAcceptsCapabilitiesRequest(t *testing.T) {
	installHandlerRuntimeStubs(t)

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"capabilities":{"network_domains":["api.example.com"],"broker":{"delegations":[{"name":"github","resource":"https://api.github.com/user"}],"http_requests":true}}}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"execution_id":"`) || !strings.Contains(body, `"receipt_path":"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestExecuteHandlerRejectsIntentAndCapabilitiesTogether(t *testing.T) {
	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","lang":"python","code":"print(1)","timeout_ms":1000,"intent":{"version":"v1","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":[],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}},"capabilities":{"network_domains":["api.example.com"]}}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"invalid_request"`) || !strings.Contains(rr.Body.String(), "intent and capabilities cannot both be provided") {
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

func TestCreateWorkspaceRejectsInvalidWorkspaceID(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/../escape", nil)
	req.SetPathValue("id", "../escape")
	rr := httptest.NewRecorder()

	HandleCreateWorkspace().ServeHTTP(rr, req)

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
		if resp != nil {
			defer resp.Body.Close()
		}
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

type stubConn struct {
	readErr     error
	writeErr    error
	deadlineErr error
}

func (c stubConn) Read(_ []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c stubConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (stubConn) Close() error         { return nil }
func (stubConn) LocalAddr() net.Addr  { return stubAddr("local") }
func (stubConn) RemoteAddr() net.Addr { return stubAddr("remote") }
func (c stubConn) SetDeadline(_ time.Time) error {
	return c.deadlineErr
}
func (stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(_ time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }

type nonFlushingResponseWriter struct {
	header http.Header
	body   strings.Builder
	status int
}

func (w *nonFlushingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *nonFlushingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *nonFlushingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func installHandlerRuntimeStubs(t *testing.T) {
	t.Helper()

	origAcquire := acquireExecutionVMFunc
	origSetup := setupCgroupFunc
	origTeardown := teardownVMFunc
	origStartBroker := startBrokerListenerFunc
	origDial := dialWithRetryFunc
	origWaitReady := waitForGuestReadyFunc
	origSend := sendPayloadFunc
	origRead := readChunksFunc
	origPoller := startCgroupPollerFunc
	origEmit := emitSignedReceiptFunc
	origWrite := writeExecutionRecordFunc

	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return &executor.VMInstance{FirecrackerPID: 77, VsockPath: "/tmp/vsock"}, "cold", warmpool.FallbackPoolDisabled, nil
	}
	setupCgroupFunc = func(string, int, policy.ResourcePolicy, *telemetry.Bus) error { return nil }
	teardownVMFunc = func(*executor.VMInstance, *telemetry.Bus) error { return nil }
	startBrokerListenerFunc = func(context.Context, string, *broker.Broker, *policydivergence.Evaluator) error { return nil }
	dialWithRetryFunc = func(string, uint32, time.Duration) (net.Conn, error) { return stubConn{}, nil }
	waitForGuestReadyFunc = func(string, time.Duration) error { return nil }
	sendPayloadFunc = func(net.Conn, models.Payload, time.Time, *telemetry.Bus, *policyevaluator.Evaluator, *policydivergence.Evaluator, func(models.PolicyDivergenceResult) error) (models.Result, error) {
		return models.Result{Stdout: "ok\n", ExitCode: 0, ExitReason: "completed", DurationMs: 7, StdoutBytes: 3}, nil
	}
	readChunksFunc = func(net.Conn, time.Time, func(string, string), *telemetry.Bus, *policyevaluator.Evaluator, *policydivergence.Evaluator, func(models.PolicyDivergenceResult) error) (*models.Result, error) {
		return &models.Result{Stdout: "ok\n", ExitCode: 0, ExitReason: "completed", DurationMs: 7, StdoutBytes: 3}, nil
	}
	startCgroupPollerFunc = func(context.Context, *telemetry.Bus, string, time.Duration) func() { return func() {} }
	emitSignedReceiptFunc = func(string, time.Time, time.Time, ExecuteRequest, *policycontract.IntentContract, *executor.VMInstance, *policy.Policy, models.ReceiptPolicy, string, int, string, bool, string, string, string, *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
		return models.ContainmentReceipt{Verdict: "completed"}, receipt.BundlePaths{
			ProofDir:      "/tmp/aegis/proofs/exec",
			ReceiptPath:   "/tmp/aegis/proofs/exec/receipt.dsse.json",
			PublicKeyPath: "/tmp/aegis/proofs/exec/receipt.pub",
			SummaryPath:   "/tmp/aegis/proofs/exec/receipt.summary.txt",
		}, nil
	}

	t.Cleanup(func() {
		acquireExecutionVMFunc = origAcquire
		setupCgroupFunc = origSetup
		teardownVMFunc = origTeardown
		startBrokerListenerFunc = origStartBroker
		dialWithRetryFunc = origDial
		waitForGuestReadyFunc = origWaitReady
		sendPayloadFunc = origSend
		readChunksFunc = origRead
		startCgroupPollerFunc = origPoller
		emitSignedReceiptFunc = origEmit
		writeExecutionRecordFunc = origWrite
	})
}

func TestExecuteHandlerSuccessResponseIncludesProof(t *testing.T) {
	installHandlerRuntimeStubs(t)

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"stdout":"ok\n"`) || !strings.Contains(rr.Body.String(), `"receipt_path":"`) {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestExecuteHandlerLifecycleStateTransitions(t *testing.T) {
	installHandlerRuntimeStubs(t)
	var statuses []string
	writeExecutionRecordFunc = func(_ *store.Store, rec store.ExecutionRecord) error {
		statuses = append(statuses, rec.Status)
		return nil
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	want := []string{store.StatusRequested, store.StatusBooting, store.StatusGuestReady, store.StatusRunning, store.StatusFinalizing, store.StatusCompleted}
	if !slices.Equal(statuses, want) {
		t.Fatalf("lifecycle statuses = %v, want %v", statuses, want)
	}
}

func TestExecuteHandlerBootTimeoutLifecycleState(t *testing.T) {
	installHandlerRuntimeStubs(t)
	acquireExecutionVMFunc = func(ctx context.Context, _ *warmpool.Manager, _ string, _ ExecuteRequest, _ *policy.Policy, _ policy.ComputeProfile, _ string, _ string, _ *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return nil, "cold", warmpool.FallbackPoolDisabled, context.DeadlineExceeded
	}
	var statuses []string
	writeExecutionRecordFunc = func(_ *store.Store, rec store.ExecutionRecord) error {
		statuses = append(statuses, rec.Status)
		return nil
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"error":"timeout"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := []string{store.StatusRequested, store.StatusBooting, store.StatusTimedOut}
	if !slices.Equal(statuses, want) {
		t.Fatalf("lifecycle statuses = %v, want %v", statuses, want)
	}
}

func TestExecuteHandlerGuestReadyTimeoutLifecycleState(t *testing.T) {
	installHandlerRuntimeStubs(t)
	waitForGuestReadyFunc = func(string, time.Duration) error { return context.DeadlineExceeded }
	var statuses []string
	writeExecutionRecordFunc = func(_ *store.Store, rec store.ExecutionRecord) error {
		statuses = append(statuses, rec.Status)
		return nil
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"error":"timeout"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
	want := []string{store.StatusRequested, store.StatusBooting, store.StatusFinalizing, store.StatusTimedOut}
	if !slices.Equal(statuses, want) {
		t.Fatalf("lifecycle statuses = %v, want %v", statuses, want)
	}
}

func TestExecuteHandlerInvalidBody(t *testing.T) {
	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python"`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerAuthFailure(t *testing.T) {
	handler := WithAuth("secret", NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test"))
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), `"code":"auth_required"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerReceiptSigningFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	emitSignedReceiptFunc = func(string, time.Time, time.Time, ExecuteRequest, *policycontract.IntentContract, *executor.VMInstance, *policy.Policy, models.ReceiptPolicy, string, int, string, bool, string, string, string, *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
		return models.ContainmentReceipt{}, receipt.BundlePaths{}, errors.New("sign failed")
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"code":"receipt_signing_failed"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerSandboxErrorMapping(t *testing.T) {
	installHandlerRuntimeStubs(t)
	sendPayloadFunc = func(net.Conn, models.Payload, time.Time, *telemetry.Bus, *policyevaluator.Evaluator, *policydivergence.Evaluator, func(models.PolicyDivergenceResult) error) (models.Result, error) {
		return models.Result{}, errors.New("guest link lost")
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"error":"error"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerSecurityDeniedResult(t *testing.T) {
	installHandlerRuntimeStubs(t)
	sendPayloadFunc = func(net.Conn, models.Payload, time.Time, *telemetry.Bus, *policyevaluator.Evaluator, *policydivergence.Evaluator, func(models.PolicyDivergenceResult) error) (models.Result, error) {
		return models.Result{ExitCode: 137, ExitReason: "security_denied_open", DurationMs: 9}, nil
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"exit_reason":"security_denied_open"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerTooManyRequests(t *testing.T) {
	pool := executor.NewPool(1)
	if err := pool.Acquire(); err != nil {
		t.Fatalf("seed pool acquire: %v", err)
	}
	defer pool.Release()

	handler := NewHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), `"code":"too_many_requests"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerRequestTooLarge(t *testing.T) {
	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	body := `{"lang":"python","code":"` + strings.Repeat("a", 128*1024) + `","timeout_ms":1000}`
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rr.Body.String(), `"code":"request_too_large"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerInvalidIntentContract(t *testing.T) {
	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"intent":{"version":"v1"}}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_intent_contract"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerInvalidExecutionID(t *testing.T) {
	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"execution_id":"bad/id","lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"field":"execution_id"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerWorkspaceValidationError(t *testing.T) {
	installHandlerRuntimeStubs(t)

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"../escape"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_workspace_id"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerWorkspaceNotFound(t *testing.T) {
	installHandlerRuntimeStubs(t)
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return nil, "cold", warmpool.FallbackWorkspace, os.ErrNotExist
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"ws-demo"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `workspace_not_found: ws-demo`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerAcquireSandboxFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return nil, "cold", warmpool.FallbackClaimError, errors.New("vm start failed")
	}

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `vm start failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerSetupCgroupError(t *testing.T) {
	installHandlerRuntimeStubs(t)
	setupCgroupFunc = func(string, int, policy.ResourcePolicy, *telemetry.Bus) error { return errors.New("cgroup failed") }

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `cgroup failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExecuteHandlerDialFailureMapsSandboxError(t *testing.T) {
	installHandlerRuntimeStubs(t)
	dialWithRetryFunc = func(string, uint32, time.Duration) (net.Conn, error) { return nil, errors.New("dial failed") }

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"error":"error"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerSuccessResponseIncludesDoneAndProof(t *testing.T) {
	installHandlerRuntimeStubs(t)
	readChunksFunc = func(_ net.Conn, _ time.Time, onChunk func(string, string), _ *telemetry.Bus, _ *policyevaluator.Evaluator, _ *policydivergence.Evaluator, _ func(models.PolicyDivergenceResult) error) (*models.Result, error) {
		onChunk("stdout", "hello\n")
		return &models.Result{Stdout: "hello\n", ExitCode: 0, ExitReason: "completed", DurationMs: 12, StdoutBytes: 6}, nil
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, body)
	}
	if !strings.Contains(body, `"type":"stdout"`) || !strings.Contains(body, `"type":"proof"`) || !strings.Contains(body, `"type":"done"`) {
		t.Fatalf("unexpected stream body: %s", body)
	}
}

func TestStreamHandlerInvalidBody(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerReceiptSigningFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	emitSignedReceiptFunc = func(string, time.Time, time.Time, ExecuteRequest, *policycontract.IntentContract, *executor.VMInstance, *policy.Policy, models.ReceiptPolicy, string, int, string, bool, string, string, string, *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
		return models.ContainmentReceipt{}, receipt.BundlePaths{}, errors.New("sign failed")
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `receipt signing failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerAuthFailure(t *testing.T) {
	handler := WithAuth("secret", NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test"))
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), `"code":"auth_required"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerStreamingUnsupported(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := &nonFlushingResponseWriter{}

	handler.ServeHTTP(rr, req)

	if rr.status != http.StatusInternalServerError || !strings.Contains(rr.body.String(), `"code":"streaming_unsupported"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.status, rr.body.String())
	}
}

func TestStreamHandlerTooManyRequests(t *testing.T) {
	pool := executor.NewPool(1)
	if err := pool.Acquire(); err != nil {
		t.Fatalf("seed pool acquire: %v", err)
	}
	defer pool.Release()

	handler := NewStreamHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), `"code":"too_many_requests"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerRequestTooLarge(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	body := `{"lang":"python","code":"` + strings.Repeat("a", 128*1024) + `","timeout_ms":1000}`
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rr.Body.String(), `"code":"request_too_large"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerInvalidIntentContract(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"intent":{"version":"v1"}}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_intent_contract"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerInvalidExecutionID(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"execution_id":"bad/id","lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"field":"execution_id"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerInvalidProfile(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"profile":"godmode"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_profile"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerValidationError(t *testing.T) {
	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":-1}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"validation_error"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerDuplicateExecutionIDConflict(t *testing.T) {
	execID := "30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b"
	registry := NewBusRegistry()
	if !registry.TryRegister(execID, telemetry.NewBus(execID)) {
		t.Fatal("failed to seed active execution bus")
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"execution_id":"`+execID+`","lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"code":"execution_conflict"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerRejectsBusyWorkspaceBeforeAdmission(t *testing.T) {
	installHandlerRuntimeStubs(t)
	workspaceRegistry := NewWorkspaceRegistry()
	if !workspaceRegistry.TryClaim("ws-busy", "held-exec") {
		t.Fatal("failed to seed active workspace claim")
	}

	acquireCalled := false
	receiptCalled := false
	recordCount := 0
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		acquireCalled = true
		return nil, "", "", errors.New("unexpected vm acquire")
	}
	emitSignedReceiptFunc = func(string, time.Time, time.Time, ExecuteRequest, *policycontract.IntentContract, *executor.VMInstance, *policy.Policy, models.ReceiptPolicy, string, int, string, bool, string, string, string, *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
		receiptCalled = true
		return models.ContainmentReceipt{}, receipt.BundlePaths{}, nil
	}
	writeExecutionRecordFunc = func(_ *store.Store, _ store.ExecutionRecord) error {
		recordCount++
		return nil
	}

	pool := executor.NewPool(1)
	handler := NewStreamHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test", workspaceRegistry)
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"ws-busy"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"code":"workspace_busy"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"execution_id"`) || strings.Contains(rr.Body.String(), `"proof_dir"`) {
		t.Fatalf("workspace rejection should not include execution proof fields: %s", rr.Body.String())
	}
	if acquireCalled {
		t.Fatal("vm acquire should not run for pre-admission workspace conflict")
	}
	if receiptCalled {
		t.Fatal("receipt signing should not run for pre-admission workspace conflict")
	}
	if recordCount != 0 {
		t.Fatalf("writeExecutionRecordFunc called %d times, want 0", recordCount)
	}
	if got := pool.Available(); got != 1 {
		t.Fatalf("pool available = %d, want 1", got)
	}
}

func TestStreamHandlerWorkspaceValidationError(t *testing.T) {
	installHandlerRuntimeStubs(t)

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"../escape"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), `"code":"invalid_workspace_id"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerWorkspaceNotFound(t *testing.T) {
	installHandlerRuntimeStubs(t)
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return nil, "cold", warmpool.FallbackWorkspace, os.ErrNotExist
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"ws-demo"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `workspace_not_found: ws-demo`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}
func TestStreamHandlerAcquireSandboxFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		return nil, "cold", warmpool.FallbackClaimError, errors.New("vm start failed")
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `vm start failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerSetupCgroupError(t *testing.T) {
	installHandlerRuntimeStubs(t)
	setupCgroupFunc = func(string, int, policy.ResourcePolicy, *telemetry.Bus) error { return errors.New("cgroup failed") }

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `cgroup failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerDialFailureMapsSandboxError(t *testing.T) {
	installHandlerRuntimeStubs(t)
	dialWithRetryFunc = func(string, uint32, time.Duration) (net.Conn, error) { return nil, errors.New("dial failed") }

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"error":"error"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerSetDeadlineFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	dialWithRetryFunc = func(string, uint32, time.Duration) (net.Conn, error) {
		return stubConn{deadlineErr: errors.New("deadline failed")}, nil
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `deadline failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerPayloadEncodeFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	dialWithRetryFunc = func(string, uint32, time.Duration) (net.Conn, error) {
		return stubConn{writeErr: errors.New("write failed")}, nil
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `write failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestStreamHandlerReadChunksFailure(t *testing.T) {
	installHandlerRuntimeStubs(t)
	readChunksFunc = func(net.Conn, time.Time, func(string, string), *telemetry.Bus, *policyevaluator.Evaluator, *policydivergence.Evaluator, func(models.PolicyDivergenceResult) error) (*models.Result, error) {
		return nil, errors.New("chunk decode failed")
	}

	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute/stream", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `chunk decode failed`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
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

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
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

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
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

func TestExecuteHandlerRejectsBusyWorkspaceBeforeAdmission(t *testing.T) {
	installHandlerRuntimeStubs(t)
	workspaceRegistry := NewWorkspaceRegistry()
	if !workspaceRegistry.TryClaim("ws-busy", "held-exec") {
		t.Fatal("failed to seed active workspace claim")
	}

	acquireCalled := false
	receiptCalled := false
	recordCount := 0
	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
		acquireCalled = true
		return nil, "", "", errors.New("unexpected vm acquire")
	}
	emitSignedReceiptFunc = func(string, time.Time, time.Time, ExecuteRequest, *policycontract.IntentContract, *executor.VMInstance, *policy.Policy, models.ReceiptPolicy, string, int, string, bool, string, string, string, *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
		receiptCalled = true
		return models.ContainmentReceipt{}, receipt.BundlePaths{}, nil
	}
	writeExecutionRecordFunc = func(_ *store.Store, _ store.ExecutionRecord) error {
		recordCount++
		return nil
	}

	pool := executor.NewPool(1)
	handler := NewHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test", workspaceRegistry)
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"workspace_id":"ws-busy"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"code":"workspace_busy"`) {
		t.Fatalf("unexpected response: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"execution_id"`) || strings.Contains(rr.Body.String(), `"proof_dir"`) {
		t.Fatalf("workspace rejection should not include execution proof fields: %s", rr.Body.String())
	}
	if acquireCalled {
		t.Fatal("vm acquire should not run for pre-admission workspace conflict")
	}
	if receiptCalled {
		t.Fatal("receipt signing should not run for pre-admission workspace conflict")
	}
	if recordCount != 0 {
		t.Fatalf("writeExecutionRecordFunc called %d times, want 0", recordCount)
	}
	if got := pool.Available(); got != 1 {
		t.Fatalf("pool available = %d, want 1", got)
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

func TestWithAuthMissingHeaderUsesErrorEnvelope(t *testing.T) {
	t.Parallel()

	handler := WithAuth("test-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.Error.Code != "auth_required" {
		t.Fatalf("error code = %q", env.Error.Code)
	}
}

func TestExecuteHandlerRejectsUnknownFieldWithErrorEnvelope(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","bogus":true}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.Error.Code != "invalid_request" {
		t.Fatalf("error code = %q", env.Error.Code)
	}
}

func TestExecuteHandlerInvalidProfileUsesErrorEnvelope(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"lang":"python","code":"print(1)","timeout_ms":1000,"profile":"godmode"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d want %d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.Error.Code != "invalid_profile" {
		t.Fatalf("error code = %q", env.Error.Code)
	}
}

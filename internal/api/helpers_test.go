package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/policy"
	policycontract "aegis/internal/policy/contract"
	"aegis/internal/receipt"
)

func TestErrorHelpersAndDecodeJSONBody(t *testing.T) {
	if got := errorDetails("code", "x", 7, "bad", "", "skip"); len(got) != 1 || got["code"] != "x" {
		t.Fatalf("errorDetails = %+v", got)
	}
	if got := errorDetails(); got != nil {
		t.Fatalf("expected nil details, got %+v", got)
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBody(strings.NewReader(`{"name":"ok"}`), &payload); err != nil {
		t.Fatalf("decodeJSONBody(valid): %v", err)
	}
	if payload.Name != "ok" {
		t.Fatalf("payload.Name = %q", payload.Name)
	}
	if err := decodeJSONBody(strings.NewReader(`{"name":"ok"}{"extra":true}`), &payload); err == nil {
		t.Fatal("expected trailing content error")
	}
	if err := decodeJSONBody(strings.NewReader(`{"name":"ok","extra":true}`), &payload); err == nil {
		t.Fatal("expected unknown field error")
	}

	rec := httptest.NewRecorder()
	writeAPIError(rec, http.StatusUnauthorized, "auth_required", "missing", errorDetails("header", "Authorization"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"auth_required"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestWithAuthAndBuildPointEvaluator(t *testing.T) {
	nextCalled := false
	handler := WithAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	handler(rec, req)
	if !nextCalled || rec.Code != http.StatusNoContent {
		t.Fatalf("authorized response = %d nextCalled=%v", rec.Code, nextCalled)
	}

	intentJSON := json.RawMessage(`{"version":"v1","execution_id":"11111111-1111-4111-8111-111111111111","workflow_id":"wf-1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`)
	reqBody := ExecuteRequest{ExecutionID: "11111111-1111-4111-8111-111111111111", Lang: "python", Intent: intentJSON}
	eval, intent, err := buildPointEvaluator(&reqBody, policy.Default().DefaultTimeoutMs)
	if err != nil || eval == nil || intent == nil {
		t.Fatalf("buildPointEvaluator(valid) err=%v eval=%v intent=%v", err, eval, intent)
	}
	if _, _, err := buildPointEvaluator(&ExecuteRequest{ExecutionID: "other", Lang: "python", Intent: intentJSON}, policy.Default().DefaultTimeoutMs); err == nil {
		t.Fatal("expected execution_id mismatch error")
	}
	if _, _, err := buildPointEvaluator(&ExecuteRequest{ExecutionID: "11111111-1111-4111-8111-111111111111", Lang: "bash", Intent: intentJSON}, policy.Default().DefaultTimeoutMs); err == nil {
		t.Fatal("expected language mismatch error")
	}
}

func TestReceiptAndExecutionHelpers(t *testing.T) {
	resp := withReceiptProof(ExecuteResponse{ExecutionID: "exec-1"}, receipt.BundlePaths{})
	if resp.ReceiptPath != "" {
		t.Fatalf("unexpected receipt path: %+v", resp)
	}

	proof := receipt.BundlePaths{
		ProofDir:          "/tmp/proofs/exec-1",
		ReceiptPath:       "/tmp/proofs/exec-1/receipt.dsse.json",
		PublicKeyPath:     "/tmp/proofs/exec-1/receipt.pub",
		SummaryPath:       "/tmp/proofs/exec-1/receipt.summary.txt",
		ArtifactCount:     2,
		DivergenceVerdict: "allow",
	}
	resp = withReceiptProof(ExecuteResponse{ExecutionID: "exec-1"}, proof)
	if resp.ReceiptPath == "" || resp.ReceiptPublicKeyPath == "" || resp.ReceiptSummaryPath == "" {
		t.Fatalf("withReceiptProof = %+v", resp)
	}

	chunk := proofChunk("exec-1", proof)
	if chunk.Type != "proof" || chunk.ArtifactCount != 2 || chunk.DivergenceVerdict != "allow" {
		t.Fatalf("proofChunk = %+v", chunk)
	}

	intent := &policycontract.IntentContract{
		WorkflowID:      "wf-1",
		TaskClass:       "summarize",
		DeclaredPurpose: "summarize report",
		Attributes:      map[string]string{"mode": "strict"},
	}
	if workflowID(nil) != "" || taskClass(nil) != "" || declaredPurpose(nil) != "" {
		t.Fatal("expected nil intent helpers to return empty strings")
	}
	attrs := receiptAttributes(ExecuteRequest{}, intent)
	attrs["mode"] = "changed"
	if intent.Attributes["mode"] != "strict" {
		t.Fatalf("receiptAttributes should copy input map: %+v", intent.Attributes)
	}

	raw := json.RawMessage(`{"key":"value"}`)
	cloned := cloneRawJSON(raw)
	cloned[0] = '['
	if string(raw) != `{"key":"value"}` {
		t.Fatalf("cloneRawJSON mutated source: %s", string(raw))
	}

	if containmentVerdictForOutcome(0, "completed") != "completed" || containmentVerdictForOutcome(1, "failed") != "contained" {
		t.Fatal("unexpected containmentVerdictForOutcome results")
	}
	if outcome, reason, verdict := classifyExecutionResult(0, "divergence_terminated"); outcome != "contained" || reason != "terminated_on_divergence" || verdict != "contained" {
		t.Fatalf("unexpected divergence classification: %s %s %s", outcome, reason, verdict)
	}
	if outcome, reason, verdict := classifyExecutionResult(1, "security_denied:file"); outcome != "contained" || reason != "security_denied" || verdict != "contained" {
		t.Fatalf("unexpected security classification: %s %s %s", outcome, reason, verdict)
	}
	if outcome, reason, verdict := classifyExecutionResult(23, "completed"); outcome != "completed_nonzero" || reason != "completed" || verdict != "completed_nonzero" {
		t.Fatalf("unexpected nonzero classification: %s %s %s", outcome, reason, verdict)
	}
}

func TestEnforcementCallbackNilVM(t *testing.T) {
	if enforcementCallback("exec-1", nil, nil) != nil {
		t.Fatal("expected nil callback for nil VM")
	}
}

func TestGuestPidsLimit(t *testing.T) {
	intent := &policycontract.IntentContract{ProcessScope: policycontract.ProcessScope{AllowShell: false}}
	if got := guestPidsLimit("python", nil, 32); got != 8 {
		t.Fatalf("guestPidsLimit(python,nil) = %d, want 8", got)
	}
	if got := guestPidsLimit("node", nil, 32); got != 8 {
		t.Fatalf("guestPidsLimit(node,nil) = %d, want 8", got)
	}
	if got := guestPidsLimit("python", intent, 32); got != 0 {
		t.Fatalf("guestPidsLimit(python) = %d, want 0", got)
	}
	if got := guestPidsLimit("node", intent, 32); got != 0 {
		t.Fatalf("guestPidsLimit(node) = %d, want 0", got)
	}
	if got := guestPidsLimit("bash", intent, 32); got != 32 {
		t.Fatalf("guestPidsLimit(bash) = %d, want 32", got)
	}
	intent.ProcessScope.AllowShell = true
	if got := guestPidsLimit("python", intent, 32); got != 32 {
		t.Fatalf("guestPidsLimit(allowShell) = %d, want 32", got)
	}
	if got := guestPidsLimit("python", nil, 100); got != 8 {
		t.Fatalf("guestPidsLimit(python,nil,100) = %d, want 8", got)
	}
	if got := guestPidsLimit("node", nil, 100); got != 8 {
		t.Fatalf("guestPidsLimit(node,nil,100) = %d, want 8", got)
	}
	if got := guestPidsLimit("bash", nil, 100); got != 100 {
		t.Fatalf("guestPidsLimit(bash,nil,100) = %d, want 100", got)
	}
}

func TestChooseExecutionIDAndClaimExecutionBus(t *testing.T) {
	if _, err := chooseExecutionID(" bad "); err == nil {
		t.Fatal("expected invalid execution_id error")
	}
	if _, err := chooseExecutionID("not-a-uuid"); err == nil {
		t.Fatal("expected parse failure")
	}
	if got, err := chooseExecutionID("11111111-1111-4111-8111-111111111111"); err != nil || got != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("chooseExecutionID(valid) = %q err=%v", got, err)
	}

	registry := NewBusRegistry()
	bus, execID, err := claimExecutionBus(registry, "11111111-1111-4111-8111-111111111111", true)
	if err != nil || bus == nil || execID == "" {
		t.Fatalf("claimExecutionBus(first) bus=%v execID=%q err=%v", bus, execID, err)
	}
	if _, _, err := claimExecutionBus(registry, execID, true); err == nil {
		t.Fatal("expected duplicate execution_id error")
	}
}

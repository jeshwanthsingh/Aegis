package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"aegis/internal/api"
	"aegis/internal/capabilities"
	"aegis/internal/models"
	"aegis/internal/receipt"
)

func TestBuildDefaultIntentSafeDefaults(t *testing.T) {
	intent, err := BuildDefaultIntent("11111111-1111-4111-8111-111111111111", "python", 30, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildDefaultIntent() error = %v", err)
	}
	if intent.NetworkScope.AllowNetwork {
		t.Fatalf("expected network disabled by default")
	}
	if len(intent.ResourceScope.WritePaths) != 0 {
		t.Fatalf("expected no write paths by default, got %v", intent.ResourceScope.WritePaths)
	}
	if !equalStrings(intent.ResourceScope.ReadPaths, []string{"/workspace", "/tmp"}) {
		t.Fatalf("unexpected read paths: %v", intent.ResourceScope.ReadPaths)
	}
	if !slices.Contains(intent.ResourceScope.ReadPaths, "/tmp") {
		t.Fatalf("expected python MCP intent to include /tmp in read paths, got %v", intent.ResourceScope.ReadPaths)
	}
	if intent.ProcessScope.AllowShell {
		t.Fatalf("expected allow_shell false for python")
	}
	if len(intent.BrokerScope.AllowedDelegations) != 0 {
		t.Fatalf("expected no broker delegation by default")
	}
}

func TestBuildDefaultIntentWithBrokerAndWrites(t *testing.T) {
	intent, err := BuildDefaultIntent("11111111-1111-4111-8111-111111111111", "bash", 10, []string{"api.example.com"}, []string{"/workspace/out"}, []BrokerDelegation{{Name: "github", Resource: "https://api.github.com/user"}})
	if err != nil {
		t.Fatalf("BuildDefaultIntent() error = %v", err)
	}
	if !intent.NetworkScope.AllowNetwork || !equalStrings(intent.NetworkScope.AllowedDomains, []string{"api.example.com"}) {
		t.Fatalf("unexpected network scope: %+v", intent.NetworkScope)
	}
	if !intent.ProcessScope.AllowShell {
		t.Fatalf("expected allow_shell true for bash")
	}
	if !equalStrings(intent.BrokerScope.AllowedDelegations, []string{"github"}) {
		t.Fatalf("unexpected delegations: %v", intent.BrokerScope.AllowedDelegations)
	}
	if !equalStrings(intent.BrokerScope.AllowedDomains, []string{"api.github.com"}) {
		t.Fatalf("unexpected broker domains: %v", intent.BrokerScope.AllowedDomains)
	}
	if !equalStrings(intent.BrokerScope.AllowedActionTypes, []string{"http_request"}) {
		t.Fatalf("unexpected broker action types: %v", intent.BrokerScope.AllowedActionTypes)
	}
	if len(intent.NetworkScope.AllowedIPs) != 0 {
		t.Fatalf("unexpected broker proxy allowed IPs: %v", intent.NetworkScope.AllowedIPs)
	}
}

func TestBuildDefaultIntentRejectsBrokerDelegationWithoutResource(t *testing.T) {
	_, err := BuildDefaultIntent("11111111-1111-4111-8111-111111111111", "python", 10, nil, nil, []BrokerDelegation{{Name: "github"}})
	if err == nil {
		t.Fatal("expected error for missing broker delegation resource")
	}
}

func TestEnrichVerifyResultIncludesBrokerEvents(t *testing.T) {
	statement := receipt.Statement{Predicate: receipt.ExecutionReceiptPredicate{
		ExecutionID: "exec-1",
		ResultClass: receipt.ResultClassCompleted,
		Divergence:  receipt.DivergenceSummary{Verdict: models.DivergenceAllow},
		Trust:       receipt.TrustPosture{SigningMode: receipt.SigningModeStrict, KeySource: receipt.KeySourceConfiguredSeed},
		Outcome:     receipt.Outcome{Reason: "completed", ExitCode: 0},
		BrokerSummary: &receipt.BrokerSummary{
			RequestCount: 1,
			AllowedCount: 1,
		},
	}}
	var result VerifyToolResult
	enrichVerifyResult(&result, statement)
	if result.ResultClass != "completed" || result.DivergenceVerdict != "allow" || result.OutcomeReason != "completed" {
		t.Fatalf("unexpected top-level verify fields: %+v", result)
	}
	broker, ok := result.Diagnostics["broker"].(map[string]any)
	if !ok {
		t.Fatalf("missing broker diagnostics: %+v", result.Diagnostics)
	}
	if broker["outcome"] != "allowed" {
		t.Fatalf("unexpected broker outcome: %+v", broker)
	}
	events, ok := broker["events"].([]string)
	if !ok || len(events) != 2 || events[0] != "credential.request" || events[1] != "credential.allowed" {
		t.Fatalf("unexpected broker events: %#v", broker["events"])
	}
}

func TestToolHandlerExecuteAllocatesWorkspaceOnlyForWorkspaceWrites(t *testing.T) {
	tests := []struct {
		name          string
		writePaths    []string
		wantWorkspace bool
	}{
		{name: "workspace path", writePaths: []string{"/workspace/output.json"}, wantWorkspace: true},
		{name: "tmp file", writePaths: []string{"/tmp/output.json"}, wantWorkspace: false},
		{name: "tmp dir", writePaths: []string{"/tmp"}, wantWorkspace: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/health":
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "warm_pool": map[string]any{"enabled": true}})
					return
				case "/v1/execute":
					var req api.ExecuteRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatalf("decode execute request: %v", err)
					}
					gotWorkspace := req.WorkspaceID != ""
					if gotWorkspace != tt.wantWorkspace {
						t.Fatalf("workspace requested = %v, want %v (workspace_id=%q)", gotWorkspace, tt.wantWorkspace, req.WorkspaceID)
					}
					_ = json.NewEncoder(w).Encode(api.ExecuteResponse{ExecutionID: req.ExecutionID, ExitCode: 0, ExitReason: "completed"})
					return
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer apiServer.Close()
			t.Setenv("AEGIS_BASE_URL", apiServer.URL)
			handler := NewToolHandler("dev")
			_, err := handler.Execute(context.Background(), ExecuteArgs{Code: "print(1)", Language: "python", AllowWritePaths: tt.writePaths})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
		})
	}
}

func TestCapabilityRequestFromExecuteArgsRejectsMixedForms(t *testing.T) {
	_, err := capabilityRequestFromExecuteArgs(ExecuteArgs{
		Capabilities:        &capabilities.Request{NetworkDomains: []string{"api.example.com"}},
		AllowNetworkDomains: []string{"legacy.example.com"},
	})
	if err == nil {
		t.Fatal("expected mixed-form rejection")
	}
}

func TestToolHandlerExecuteUsesCapabilitiesSurface(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "warm_pool": map[string]any{"enabled": true}})
			return
		case "/v1/execute":
			var req api.ExecuteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode execute request: %v", err)
			}
			if len(req.Intent) == 0 {
				t.Fatal("expected compiled intent")
			}
			_ = json.NewEncoder(w).Encode(api.ExecuteResponse{ExecutionID: req.ExecutionID, ExitCode: 0, ExitReason: "completed"})
			return
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer apiServer.Close()
	t.Setenv("AEGIS_BASE_URL", apiServer.URL)
	handler := NewToolHandler("dev")
	_, err := handler.Execute(context.Background(), ExecuteArgs{
		Code:     "print(1)",
		Language: "python",
		Capabilities: &capabilities.Request{
			NetworkDomains: []string{"api.example.com"},
			Broker: &capabilities.BrokerRequest{
				Delegations:  []capabilities.Delegation{{Name: "github", Resource: "https://api.github.com/user"}},
				HTTPRequests: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestToolHandlerExecuteAndVerify(t *testing.T) {
	proofRoot := t.TempDir()
	paths := writeVerifiedFixture(t, proofRoot, "exec-fixture")
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "warm_pool": map[string]any{"enabled": true, "available": 1, "warm_claims": 0, "cold_fallbacks": 0}})
			return
		case "/v1/execute":
			var req api.ExecuteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode execute request: %v", err)
			}
			if req.ExecutionID == "" || len(req.Intent) == 0 {
				t.Fatalf("expected execution_id and intent")
			}
			resp := api.ExecuteResponse{
				Stdout:               "hello\n",
				ExitCode:             0,
				ExitReason:           "completed",
				DurationMs:           12,
				ExecutionID:          "exec-fixture",
				ProofDir:             paths.ProofDir,
				ReceiptPath:          paths.ReceiptPath,
				ReceiptPublicKeyPath: paths.PublicKeyPath,
				ReceiptSummaryPath:   paths.SummaryPath,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer apiServer.Close()

	t.Setenv("AEGIS_BASE_URL", apiServer.URL)
	t.Setenv("AEGIS_PROOF_ROOT", proofRoot)
	handler := NewToolHandler("dev")
	result, err := handler.Execute(context.Background(), ExecuteArgs{Code: "print('hello')", Language: "python"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !result.OK || result.ExecutionID != "exec-fixture" {
		t.Fatalf("unexpected execute result: %+v", result)
	}
	if result.Receipt == nil || result.Receipt["verified"] != true {
		t.Fatalf("expected verified receipt, got %+v", result.Receipt)
	}
	verifyResult, err := handler.Verify(VerifyArgs{ProofDir: paths.ProofDir})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verifyResult.Verified || verifyResult.ExecutionID != "exec-fixture" {
		t.Fatalf("unexpected verify result: %+v", verifyResult)
	}
	if verifyResult.ResultClass != "completed" || verifyResult.DivergenceVerdict != "allow" || verifyResult.OutcomeReason != "completed" {
		t.Fatalf("unexpected receipt semantics: %+v", verifyResult)
	}
}

func TestToolHandlerVerifyMissingBundle(t *testing.T) {
	handler := NewToolHandler("dev")
	_, err := handler.Verify(VerifyArgs{ProofDir: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected error for missing bundle")
	}
}

func TestToolHandlerCallToolRejectsUnknown(t *testing.T) {
	handler := NewToolHandler("dev")
	_, err := handler.CallTool(context.Background(), CallToolParams{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWorkspaceRequired(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  bool
	}{
		{name: "no writes", paths: nil, want: false},
		{name: "tmp file", paths: []string{"/tmp/out.json"}, want: false},
		{name: "tmp dir", paths: []string{"/tmp"}, want: false},
		{name: "workspace file", paths: []string{"/workspace/out.json"}, want: true},
		{name: "workspace dir", paths: []string{"/workspace"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := workspaceRequired(tt.paths); got != tt.want {
				t.Fatalf("workspaceRequired(%v) = %v, want %v", tt.paths, got, tt.want)
			}
		})
	}
}

func TestWarmDiagnostics(t *testing.T) {
	payload := api.ExecuteRequest{Lang: "python"}
	warm := warmDiagnostics(&healthWarmPool{Enabled: true, WarmClaims: 1, ColdFallbacks: 2, Available: 1}, &healthWarmPool{Enabled: true, WarmClaims: 2, ColdFallbacks: 2, Available: 0}, payload)
	if warm["dispatch_path"] != "warm" {
		t.Fatalf("unexpected warm diagnostics: %+v", warm)
	}
	cold := warmDiagnostics(&healthWarmPool{Enabled: true, WarmClaims: 2, ColdFallbacks: 2}, &healthWarmPool{Enabled: true, WarmClaims: 2, ColdFallbacks: 3}, payload)
	if cold["dispatch_path"] != "cold" {
		t.Fatalf("unexpected cold diagnostics: %+v", cold)
	}
}

func writeVerifiedFixture(t *testing.T, root string, executionID string) receipt.BundlePaths {
	t.Helper()
	if err := os.Setenv("AEGIS_RECEIPT_SIGNING_SEED_B64", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	signer, err := receipt.NewSignerFromEnv()
	if err != nil {
		t.Fatalf("NewSignerFromEnv(): %v", err)
	}
	signed, err := receipt.BuildSignedReceipt(receipt.Input{
		ExecutionID:     executionID,
		WorkflowID:      "wf_mcp",
		Backend:         models.BackendFirecracker,
		TaskClass:       "mcp_execute",
		DeclaredPurpose: "fixture",
		StartedAt:       mustTime("2026-04-09T10:00:00Z"),
		FinishedAt:      mustTime("2026-04-09T10:00:01Z"),
		Outcome: receipt.Outcome{
			ExitCode: 0,
			Reason:   "completed",
		},
		OutputArtifacts: receipt.ArtifactsFromBundleOutputs(executionID, "hello\n", "", false),
	}, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt(): %v", err)
	}
	paths, err := receipt.WriteProofBundle(root, executionID, signed, signer.PublicKey, "hello\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle(): %v", err)
	}
	return paths
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func equalStrings(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

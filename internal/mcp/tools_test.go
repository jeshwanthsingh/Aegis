package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis/internal/api"
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
	if !equalStrings(intent.ResourceScope.ReadPaths, []string{"/workspace"}) {
		t.Fatalf("unexpected read paths: %v", intent.ResourceScope.ReadPaths)
	}
	if intent.ProcessScope.AllowShell {
		t.Fatalf("expected allow_shell false for python")
	}
	if len(intent.BrokerScope.AllowedDelegations) != 0 {
		t.Fatalf("expected no broker delegation by default")
	}
}

func TestBuildDefaultIntentWithBrokerAndWrites(t *testing.T) {
	intent, err := BuildDefaultIntent("11111111-1111-4111-8111-111111111111", "bash", 10, []string{"api.example.com"}, []string{"/workspace/out"}, []BrokerDelegation{{Name: "github"}})
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
}

func TestToolHandlerExecuteAndVerify(t *testing.T) {
	proofRoot := t.TempDir()
	paths := writeVerifiedFixture(t, proofRoot, "exec-fixture")
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/execute" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
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

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis/internal/config"
	"aegis/internal/receipt"
)

func TestReceiptVerifyCommand(t *testing.T) {
	signer := mustTestSigner(t)
	receiptInput := receipt.Input{
		ExecutionID: "exec_cli",
		Backend:     "firecracker",
		StartedAt:   testTime(),
		FinishedAt:  testTime().Add(2 * time.Second),
		Outcome:     receipt.Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"},
	}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "ok\n", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	paths, err := receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "ok\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptVerify(&stdout, &stderr, []string{"--file", paths.ReceiptPath, "--public-key", paths.PublicKeyPath})
	if code != 0 {
		t.Fatalf("receiptVerify exit=%d stderr=%s", code, stderr.String())
	}
	for _, needle := range []string{"verification=verified", "execution_id=exec_cli", "signing_mode=dev", "key_source=dev_fallback", "artifact_count=2", "output-manifest.json"} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
}

func TestReceiptVerifyCommandFailsForTamperedReceipt(t *testing.T) {
	signer := mustTestSigner(t)
	receiptInput := receipt.Input{ExecutionID: "exec_cli", Backend: "firecracker", StartedAt: testTime(), FinishedAt: testTime().Add(2 * time.Second), Outcome: receipt.Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"}}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	paths, err := receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	if err := os.WriteFile(paths.ReceiptPath, []byte(`{"envelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]},"statement":{"_type":"bad"}}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptVerify(&stdout, &stderr, []string{"--file", paths.ReceiptPath, "--public-key", paths.PublicKeyPath})
	if code == 0 {
		t.Fatal("expected receiptVerify failure")
	}
	if !strings.Contains(stderr.String(), "receipt verification failed") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestReceiptShowCommandByExecutionID(t *testing.T) {
	signer := mustTestSigner(t)
	receiptInput := receipt.Input{
		ExecutionID: "exec_show",
		Backend:     "firecracker",
		StartedAt:   testTime(),
		FinishedAt:  testTime().Add(2 * time.Second),
		Outcome:     receipt.Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"},
	}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "show\n", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	t.Setenv("AEGIS_PROOF_ROOT", root)
	_, err = receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "show\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptShow(&stdout, &stderr, []string{"--execution-id", receiptInput.ExecutionID})
	if code != 0 {
		t.Fatalf("receiptShow exit=%d stderr=%s", code, stderr.String())
	}
	for _, needle := range []string{"[proof bundle", "[artifact output-manifest.json", "verification=verified", "execution_id=exec_show", "signing_mode=dev"} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
}

func TestReceiptVerifyCommandByExecutionID(t *testing.T) {
	signer := mustTestSigner(t)
	receiptInput := receipt.Input{
		ExecutionID: "exec_lookup",
		Backend:     "firecracker",
		StartedAt:   testTime(),
		FinishedAt:  testTime().Add(2 * time.Second),
		Outcome:     receipt.Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"},
	}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "lookup\n", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	t.Setenv("AEGIS_PROOF_ROOT", root)
	_, err = receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "lookup\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptVerify(&stdout, &stderr, []string{"--execution-id", receiptInput.ExecutionID})
	if code != 0 {
		t.Fatalf("receiptVerify exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "execution_id=exec_lookup") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunStreamPrintsProofBundleChunk(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Execution-ID", "exec_stream")
		flusher, _ := w.(http.Flusher)
		for _, payload := range []string{
			`{"type":"stdout","chunk":"hello\n"}`,
			`{"type":"proof","execution_id":"exec_stream","proof_dir":"/tmp/aegis/proofs/exec_stream","receipt_path":"/tmp/aegis/proofs/exec_stream/receipt.dsse.json","receipt_public_key_path":"/tmp/aegis/proofs/exec_stream/receipt.pub","receipt_summary_path":"/tmp/aegis/proofs/exec_stream/receipt.summary.txt","artifact_count":2,"divergence_verdict":"allow"}`,
			`{"type":"done","exit_code":0,"duration_ms":12}`,
		} {
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}))
	defer server.Close()

	t.Setenv("AEGIS_URL", server.URL)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"run", "--lang", "bash", "--code", "echo hello", "--stream"})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, needle := range []string{"[execution exec_stream]", "hello", "[proof bundle /tmp/aegis/proofs/exec_stream]", "[receipt /tmp/aegis/proofs/exec_stream/receipt.dsse.json]", "[done in 12ms]"} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
}

func TestResolveReceiptSelectionInfersPublicKeyPath(t *testing.T) {
	paths, err := resolveReceiptSelection("/tmp/aegis/proofs/abc/receipt.dsse.json", "", "", "")
	if err != nil {
		t.Fatalf("resolveReceiptSelection: %v", err)
	}
	want := filepath.Join("/tmp/aegis/proofs/abc", "receipt.pub")
	if paths.PublicKeyPath != want {
		t.Fatalf("public key path = %q want %q", paths.PublicKeyPath, want)
	}
}

func mustTestSigner(t *testing.T) *receipt.Signer {
	t.Helper()
	signer, err := receipt.NewSigner(receipt.SigningConfig{Mode: receipt.SigningModeDev})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func testTime() time.Time { return time.Unix(1700000000, 0).UTC() }

func TestBaseURLUsesConfigWhenEnvUnset(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "ai"), 0o755); err != nil {
		t.Fatalf("MkdirAll ai: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module aegis\n\ngo 1.22.5\n"), 0o644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}
	cfg := config.Default(repo)
	cfg.API.URL = "http://127.0.0.1:9191"
	configPath := filepath.Join(repo, config.DefaultConfigRelPath)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("MkdirAll config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(config.RenderStarterConfig(cfg)), 0o644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Setenv("AEGIS_URL", "")
	if got := baseURL(); got != cfg.API.URL {
		t.Fatalf("baseURL = %q want %q", got, cfg.API.URL)
	}
}

func TestConsumeSingleHandlesAPIErrorEnvelope(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"auth_required","message":"Authorization header missing"}}`)),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := consumeSingle(&stdout, &stderr, resp); code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "Authorization header missing") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestHealthUsesV1HealthRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","worker_slots_available":5,"worker_slots_total":5}`))
	}))
	defer server.Close()

	t.Setenv("AEGIS_URL", server.URL)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := health(&stdout, &stderr); code != 0 {
		t.Fatalf("health exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "status: ok") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

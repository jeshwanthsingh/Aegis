package main

import (
	"bytes"
	"encoding/json"
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
	for _, needle := range []string{
		"verification=verified",
		"schema_version=v1",
		"execution_id=exec_cli",
		"backend=firecracker",
		"policy_digest=none",
		"signer_key_id=" + signer.KeyID,
		"signing_mode=dev",
		"intent_digest=none",
		"trust_limitations=dev_signing_mode,host_attestation_absent",
		"outcome=completed",
		"exit_code=0",
		"execution_status=none",
		"semantics_mode=explicit_v2",
		"result_class=completed",
		"key_source=configured_seed",
		"artifact_count=2",
		"output-manifest.json",
	} {
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
	if !strings.Contains(stderr.String(), "verification_failure_class=signature_invalid") {
		t.Fatalf("stderr missing failure class: %s", stderr.String())
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
	for _, needle := range []string{"[verification]", "status=verified", "[execution]", "result_class=completed", "[governed_actions]", "[artifacts]", "execution_id=exec_show"} {
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

func TestRunSendsCapabilitiesRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/execute" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		capabilities, ok := req["capabilities"].(map[string]any)
		if !ok {
			t.Fatalf("missing capabilities payload: %#v", req)
		}
		broker, ok := capabilities["broker"].(map[string]any)
		if !ok || broker["http_requests"] != true {
			t.Fatalf("unexpected broker payload: %#v", capabilities["broker"])
		}
		domains, ok := capabilities["network_domains"].([]any)
		if !ok || len(domains) != 1 || domains[0] != "api.example.com" {
			t.Fatalf("unexpected network domains: %#v", capabilities["network_domains"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"execution_id": "exec_caps", "exit_code": 0, "exit_reason": "completed"})
	}))
	defer server.Close()

	t.Setenv("AEGIS_URL", server.URL)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{
		"run",
		"--lang", "python",
		"--code", "print(1)",
		"--network-domain", "api.example.com",
		"--allow-http-request",
		"--broker-delegation", "github=https://api.github.com/user",
	})
	if code != 0 {
		t.Fatalf("runMain exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestRunRejectsIntentAndCapabilitiesTogether(t *testing.T) {
	intentFile := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(intentFile, []byte(`{"version":"v1"}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{
		"run",
		"--lang", "python",
		"--code", "print(1)",
		"--intent-file", intentFile,
		"--allow-http-request",
	})
	if code == 0 {
		t.Fatal("expected mixed-form run rejection")
	}
	if !strings.Contains(stderr.String(), "--intent-file cannot be combined with capability flags") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
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
	signer, err := receipt.NewSigner(receipt.SigningConfig{
		Mode:    receipt.SigningModeDev,
		SeedB64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func testTime() time.Time { return time.Unix(1700000000, 0).UTC() }

func makeRepoRootForCLI(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, "configs"), 0o755); err != nil {
		t.Fatalf("MkdirAll configs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module aegis\n\ngo 1.22.5\n"), 0o644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "configs", "default-policy.yaml"), []byte("runtime:\n  network:\n    mode: none\n"), 0o644); err != nil {
		t.Fatalf("WriteFile default-policy.yaml: %v", err)
	}
}

func TestBaseURLUsesConfigWhenEnvUnset(t *testing.T) {
	repo := t.TempDir()
	makeRepoRootForCLI(t, repo)
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

func TestDoctorCommandReportsHealthyRuntimeAndReceiptPath(t *testing.T) {
	repo := makeTestRepo(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	origStaticChecks := doctorStaticChecksFunc
	origVerify := doctorVerifyBundlePathsFunc
	t.Cleanup(func() {
		doctorStaticChecksFunc = origStaticChecks
		doctorVerifyBundlePathsFunc = origVerify
	})
	doctorStaticChecksFunc = func(string, config.Config) []doctorCheck {
		return []doctorCheck{
			{Bucket: "host", Label: "linux host", Status: doctorPass, Detail: "running on linux"},
			{Bucket: "host", Label: "/dev/kvm access", Status: doctorPass, Detail: "ok"},
			{Bucket: "host", Label: "firecracker", Status: doctorPass, Detail: "/usr/bin/firecracker"},
			{Bucket: "host", Label: "kernel image", Status: doctorPass, Detail: "/tmp/vmlinux"},
			{Bucket: "host", Label: "rootfs", Status: doctorPass, Detail: "/tmp/alpine-base.ext4"},
			{Bucket: "host", Label: "rootfs semantic", Status: doctorPass, Detail: "verified"},
			{Bucket: "host", Label: "database", Status: doctorPass, Detail: "connection ok"},
			{Bucket: "host", Label: "cgroup parent", Status: doctorPass, Detail: "ok"},
		}
	}
	doctorVerifyBundlePathsFunc = func(paths receipt.BundlePaths) (receipt.Statement, error) {
		return receipt.Statement{
			Predicate: receipt.ExecutionReceiptPredicate{
				ExecutionID: "doctor-exec",
				Outcome:     receipt.Outcome{ExitCode: 0, Reason: "completed"},
			},
		}, nil
	}
	proofDir := filepath.Join(t.TempDir(), "doctor-exec")
	if err := os.MkdirAll(proofDir, 0o755); err != nil {
		t.Fatalf("MkdirAll proofDir: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_, _ = w.Write([]byte(`{"status":"ok","worker_slots_available":5,"worker_slots_total":5}`))
		case "/ready":
			_, _ = w.Write([]byte(`{"status":"ready","db_ok":true,"worker_slots_available":5,"worker_slots_total":5}`))
		case "/v1/execute":
			_, _ = fmt.Fprintf(w, `{"stdout":"doctor-self-test\n","exit_code":0,"duration_ms":12,"execution_id":"doctor-exec","proof_dir":%q,"receipt_path":%q,"receipt_public_key_path":%q,"receipt_summary_path":%q}`, proofDir, filepath.Join(proofDir, "receipt.dsse.json"), filepath.Join(proofDir, "receipt.pub"), filepath.Join(proofDir, "receipt.summary.txt"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AEGIS_URL", server.URL)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"doctor"})
	if code != 0 {
		t.Fatalf("doctor exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, needle := range []string{
		"[PASS] runtime health: status=ok workers=5/5 available",
		"[PASS] runtime ready: status=ready db_ok=true workers=5/5 available",
		"[PASS] execute self-test: execution_id=doctor-exec",
		"[PASS] receipt verify: verified execution_id=doctor-exec outcome=completed exit_code=0",
		"host_ready=PASS",
		"runtime_ready=PASS",
		"execution_path_ready=PASS",
		"receipt_path_ready=PASS",
	} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
}

func TestDoctorCommandSurfacesRuntimeFailureHonestly(t *testing.T) {
	repo := makeTestRepo(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(repo); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	origStaticChecks := doctorStaticChecksFunc
	t.Cleanup(func() { doctorStaticChecksFunc = origStaticChecks })
	doctorStaticChecksFunc = func(string, config.Config) []doctorCheck {
		return []doctorCheck{{Bucket: "host", Label: "linux host", Status: doctorPass, Detail: "running on linux"}}
	}
	t.Setenv("AEGIS_URL", "http://127.0.0.1:1")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, []string{"doctor"})
	if code == 0 {
		t.Fatalf("expected doctor failure stdout=%s", stdout.String())
	}
	for _, needle := range []string{
		"[FAIL] runtime health:",
		"[SKIP] execute self-test: skipped because runtime is not reachable",
		"[SKIP] receipt verify: skipped because execution self-test did not run",
		"host_ready=PASS",
		"runtime_ready=FAIL",
		"execution_path_ready=SKIP",
		"receipt_path_ready=SKIP",
	} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q: %s", needle, stdout.String())
		}
	}
}

func makeTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	makeRepoRootForCLI(t, repo)
	cfg := config.Default(repo)
	cfg.API.URL = "http://127.0.0.1:8080"
	configPath := filepath.Join(repo, config.DefaultConfigRelPath)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("MkdirAll config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(config.RenderStarterConfig(cfg)), 0o644); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
	return repo
}

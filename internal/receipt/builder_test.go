package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis/internal/models"
	policycfg "aegis/internal/policy"
	"aegis/internal/telemetry"
)

func TestBuildPredicateAndStatement(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receipt.Statement.Type != StatementType {
		t.Fatalf("statement type = %q", receipt.Statement.Type)
	}
	if receipt.Statement.PredicateType != PredicateType {
		t.Fatalf("predicate type = %q", receipt.Statement.PredicateType)
	}
	if receipt.Statement.Predicate.ExecutionID != input.ExecutionID {
		t.Fatalf("execution id = %q", receipt.Statement.Predicate.ExecutionID)
	}
	if receipt.Statement.Predicate.PointDecisions.DenyCount != 1 {
		t.Fatalf("unexpected point summary: %+v", receipt.Statement.Predicate.PointDecisions)
	}
	if receipt.Statement.Predicate.Runtime == nil {
		t.Fatal("expected runtime envelope")
	}
	if receipt.Statement.Predicate.Runtime.Profile != "standard" || receipt.Statement.Predicate.Runtime.MemoryMB != 768 {
		t.Fatalf("unexpected runtime envelope: %+v", receipt.Statement.Predicate.Runtime)
	}
	if receipt.Statement.Predicate.Policy == nil {
		t.Fatal("expected policy envelope")
	}
	if receipt.Statement.Predicate.Policy.Baseline.Language != "python" || receipt.Statement.Predicate.Policy.Baseline.TimeoutMs != 5000 {
		t.Fatalf("unexpected policy envelope: %+v", receipt.Statement.Predicate.Policy)
	}
}

func TestDSSEEnvelopeGenerationAndVerify(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	statement, err := VerifySignedReceipt(receipt, signer.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignedReceipt: %v", err)
	}
	if statement.Predicate.SignerKeyID != signer.KeyID {
		t.Fatalf("signer key id = %q", statement.Predicate.SignerKeyID)
	}
	if statement.Predicate.Trust.SigningMode != SigningModeDev {
		t.Fatalf("unexpected signing mode: %q", statement.Predicate.Trust.SigningMode)
	}
	if statement.Predicate.Trust.KeySource != KeySourceConfiguredSeed {
		t.Fatalf("unexpected key source: %q", statement.Predicate.Trust.KeySource)
	}
}

func TestArtifactBindingUsesSubject(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = []Artifact{{Name: "summary.md", Digest: map[string]string{"sha256": "abc123"}, Path: "/workspace/summary.md"}}
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if len(receipt.Statement.Subject) != 1 {
		t.Fatalf("subject count = %d", len(receipt.Statement.Subject))
	}
	if receipt.Statement.Subject[0].Digest["sha256"] != "abc123" {
		t.Fatalf("unexpected subject digest: %+v", receipt.Statement.Subject[0])
	}
}

func TestZeroArtifactCaseIsHonest(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if len(receipt.Statement.Subject) != 0 {
		t.Fatalf("expected zero subjects, got %d", len(receipt.Statement.Subject))
	}
}

func TestDivergenceBearingReceiptIncludesRuleIDs(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receipt.Statement.Predicate.Divergence.Verdict != models.DivergenceKillCandidate {
		t.Fatalf("unexpected divergence verdict: %q", receipt.Statement.Predicate.Divergence.Verdict)
	}
	if len(receipt.Statement.Predicate.Divergence.TriggeredRuleIDs) == 0 {
		t.Fatal("expected triggered rule ids")
	}
}

func TestVerifyTamperedPayloadFails(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(receipt.Envelope.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	statement.Predicate.ExecutionID = "tampered"
	bytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal tampered statement: %v", err)
	}
	receipt.Envelope.Payload = base64.StdEncoding.EncodeToString(bytes)
	if _, err := VerifySignedReceipt(receipt, signer.PublicKey); err == nil {
		t.Fatal("expected tampered payload verification failure")
	}
}

func TestVerifyWrongPayloadTypeFails(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	receipt.Envelope.PayloadType = "application/json"
	if _, err := VerifySignedReceipt(receipt, signer.PublicKey); err == nil {
		t.Fatal("expected payload type verification failure")
	}
}

func TestWriteProofBundleAndVerifyFile(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "report ok\n", "", false)
	signedReceipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	paths, err := WriteProofBundle(root, input.ExecutionID, signedReceipt, signer.PublicKey, "report ok\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	statement, err := VerifyBundlePaths(paths)
	if err != nil {
		t.Fatalf("VerifyBundlePaths: %v", err)
	}
	if len(statement.Subject) != 2 {
		t.Fatalf("subject count = %d", len(statement.Subject))
	}
	if paths.ArtifactPaths["stdout.txt"] == "" {
		t.Fatal("expected stdout artifact path")
	}
	if paths.ArtifactPaths["output-manifest.json"] == "" {
		t.Fatal("expected output manifest artifact path")
	}
	if paths.DivergenceVerdict != string(statement.Predicate.Divergence.Verdict) {
		t.Fatalf("divergence verdict = %q", paths.DivergenceVerdict)
	}
}

func TestVerifyBundlePathsRejectsTamperedArtifact(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "report ok\n", "", false)
	signedReceipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	paths, err := WriteProofBundle(root, input.ExecutionID, signedReceipt, signer.PublicKey, "report ok\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	if err := os.WriteFile(paths.ArtifactPaths["output-manifest.json"], []byte("{\"tampered\":true}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile tampered manifest: %v", err)
	}
	if _, err := VerifyBundlePaths(paths); err == nil {
		t.Fatal("expected tampered artifact verification failure")
	}
}

func TestVerifyBundlePathsRejectsUnexpectedArtifact(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "artifact\n", "", false)
	signedReceipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	paths, err := WriteProofBundle(root, input.ExecutionID, signedReceipt, signer.PublicKey, "artifact\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	extraPath := filepath.Join(paths.ProofDir, "ghost.txt")
	if err := os.WriteFile(extraPath, []byte("ghost"), 0o644); err != nil {
		t.Fatalf("WriteFile ghost: %v", err)
	}
	resolved, err := ResolveBundlePaths(root, input.ExecutionID, "")
	if err != nil {
		t.Fatalf("ResolveBundlePaths: %v", err)
	}
	if _, err := VerifyBundlePaths(resolved); err == nil {
		t.Fatal("expected ghost artifact verification failure")
	}
}

func TestBundleArtifactsIncludeManifestWithoutSweepingWorkspace(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "artifact\n", "", false)
	signedReceipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("ignore"), 0o644); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	paths, err := WriteProofBundle(root, input.ExecutionID, signedReceipt, signer.PublicKey, "artifact\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	resolved, err := ResolveBundlePaths(root, input.ExecutionID, "")
	if err != nil {
		t.Fatalf("ResolveBundlePaths: %v", err)
	}
	if len(resolved.ArtifactPaths) != 2 {
		t.Fatalf("artifact path count = %d", len(resolved.ArtifactPaths))
	}
	if resolved.ArtifactPaths["output-manifest.json"] == "" || resolved.ArtifactPaths["stdout.txt"] == "" {
		t.Fatalf("unexpected artifact paths: %+v", resolved.ArtifactPaths)
	}
	if _, ok := resolved.ArtifactPaths["outside.txt"]; ok {
		t.Fatalf("unexpected workspace file in artifact paths: %+v", resolved.ArtifactPaths)
	}
	if paths.ArtifactCount != 2 {
		t.Fatalf("artifact count = %d", paths.ArtifactCount)
	}
}

func TestFormatSummaryIncludesCoreFields(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(receipt.Statement, true)
	expectedPolicyDigest := policyDigestForReceipt(input.Policy)
	for _, needle := range []string{
		"verification=verified",
		"schema_version=v1",
		"execution_id=exec_123",
		"backend=firecracker",
		"policy_digest=" + expectedPolicyDigest,
		"policy_language=python",
		"policy_code_size_bytes=11",
		"policy_max_code_bytes=65536",
		"policy_timeout_ms=5000",
		"policy_max_timeout_ms=10000",
		"policy_profile=standard",
		"policy_network_mode=egress_allowlist",
		"policy_intent_digest=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"policy_intent_source=intent_contract",
		"signer_key_id=" + signer.KeyID,
		"signing_mode=dev",
		"intent_digest=",
		"trust_limitations=dev_signing_mode,host_attestation_absent",
		"outcome=completed",
		"exit_code=0",
		"execution_status=none",
		"result_class=denied",
		"key_source=configured_seed",
		"attestation=absent",
		"divergence_verdict=kill_candidate",
		"artifact_count=0",
		"runtime_profile=standard",
		"runtime_vcpu_count=2",
		"runtime_memory_mb=768",
		"runtime_cgroup_memory_max_mb=896",
		"runtime_network_mode=egress_allowlist",
		"runtime_broker_enabled=true",
		"runtime_applied_overrides=AEGIS_VM_MEMORY_MB",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q: %s", needle, summary)
		}
	}
	if receipt.Statement.Predicate.Policy.Baseline.Network == nil || receipt.Statement.Predicate.Policy.Baseline.Network.Allowlist == nil {
		t.Fatalf("expected baseline network allowlist: %+v", receipt.Statement.Predicate.Policy.Baseline.Network)
	}
	if got := strings.Join(receipt.Statement.Predicate.Policy.Baseline.Network.Allowlist.FQDNs, ","); got != "api.github.com,registry.npmjs.org" {
		t.Fatalf("unexpected baseline network allowlist fqdns: %q", got)
	}
	if got := strings.Join(receipt.Statement.Predicate.Runtime.Network.Allowlist.CIDRs, ","); got != "127.0.0.0/8,198.51.100.0/24" {
		t.Fatalf("unexpected runtime network allowlist cidrs: %q", got)
	}
}

func TestFormatSummaryNormalizesLegacyIsolatedNetworkMode(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.Policy.Baseline.Network.Mode = policycfg.NetworkModeLegacyIsolated
	input.Runtime.Network.Mode = policycfg.NetworkModeLegacyIsolated

	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(receipt.Statement, true)
	if !strings.Contains(summary, "policy_network_mode="+policycfg.NetworkModeEgressAllowlist) {
		t.Fatalf("summary missing canonical policy network mode: %s", summary)
	}
	if !strings.Contains(summary, "runtime_network_mode="+policycfg.NetworkModeEgressAllowlist) {
		t.Fatalf("summary missing canonical runtime network mode: %s", summary)
	}
	if strings.Contains(summary, "policy_network_mode="+policycfg.NetworkModeLegacyIsolated) || strings.Contains(summary, "runtime_network_mode="+policycfg.NetworkModeLegacyIsolated) {
		t.Fatalf("summary still contains legacy isolated mode: %s", summary)
	}
}

func TestVerifySignedReceiptRejectsInvalidRuntimeEnvelope(t *testing.T) {
	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	signed.Statement.Predicate.Runtime.Network.Mode = "broken"
	payload, err := json.Marshal(signed.Statement)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	signed.Envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	signed.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer.PrivateKey, pae(PayloadType, payload)))
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil {
		t.Fatal("expected invalid runtime envelope verification failure")
	}
}

func TestVerifySignedReceiptRejectsInvalidPolicyEnvelope(t *testing.T) {
	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	signed.Statement.Predicate.Policy.Baseline.TimeoutMs = 20000
	payload, err := json.Marshal(signed.Statement)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	signed.Envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	signed.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(signer.PrivateKey, pae(PayloadType, payload)))
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil {
		t.Fatal("expected invalid policy envelope verification failure")
	}
}

func TestBuildPredicateIncludesTopLevelPolicyDigest(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receipt.Statement.Predicate.PolicyDigest != policyDigestForReceipt(input.Policy) {
		t.Fatalf("policy digest = %q", receipt.Statement.Predicate.PolicyDigest)
	}
}

func TestBuildPredicateBareExecutionIncludesBaselinePolicyDigest(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.IntentRaw = nil
	input.Policy.Intent = nil
	receiptValue, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receiptValue.Statement.Predicate.Policy == nil {
		t.Fatal("expected policy envelope")
	}
	if receiptValue.Statement.Predicate.Policy.Intent != nil {
		t.Fatalf("expected no intent policy extension, got %+v", receiptValue.Statement.Predicate.Policy.Intent)
	}
	if receiptValue.Statement.Predicate.PolicyDigest == "" {
		t.Fatal("expected non-empty policy digest")
	}
	if receiptValue.Statement.Predicate.Policy.Baseline.Profile != "standard" {
		t.Fatalf("unexpected baseline policy: %+v", receiptValue.Statement.Predicate.Policy.Baseline)
	}
}

func TestBuildPredicatePolicyDigestChangesWhenBaselinePolicyChanges(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	first, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt(first): %v", err)
	}
	changed := testReceiptInput()
	changed.Policy.Baseline.TimeoutMs = 7000
	second, err := BuildSignedReceipt(changed, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt(second): %v", err)
	}
	if first.Statement.Predicate.PolicyDigest == second.Statement.Predicate.PolicyDigest {
		t.Fatalf("expected policy digest to change when baseline policy changes: %q", first.Statement.Predicate.PolicyDigest)
	}
}

func TestFormatSummaryIncludesWorkspaceID(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.WorkspaceID = "ws-demo"
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(receipt.Statement, true)
	if !strings.Contains(summary, "workspace_id=ws-demo") {
		t.Fatalf("summary missing workspace_id: %s", summary)
	}
}

func TestFormatSummaryIncludesExecutionStatus(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.ExecutionStatus = "teardown_failed"
	receipt, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(receipt.Statement, true)
	if !strings.Contains(summary, "execution_status=teardown_failed") {
		t.Fatalf("summary missing execution_status: %s", summary)
	}
}

func TestFormatSummaryIncludesGovernedActionEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	receipt, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(receipt.Statement, true)
	for _, needle := range []string{
		"governed_action_count=1",
		"governed_action_1=kind=http_request",
		"capability_path=direct_egress",
		"used=false",
		"governed_action_normalized_count=1",
		"governed_action_normalized_1=count=1 kind=http_request",
		"capability_count=1",
		"capability_1=count=1 requested=http_request",
		"decision=deny",
		"denial_marker=direct_egress_denied",
		"denial_class=governed_action",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q: %s", needle, summary)
		}
	}
}

func TestBuildPredicateClassifiesReconciledAndAbnormal(t *testing.T) {
	signer := mustDevSigner(t)
	reconciled := testReceiptInput()
	reconciled.ExecutionStatus = "reconciled"
	reconciled.Outcome = Outcome{ExitCode: -1, Reason: "recovered_on_boot", ContainmentVerdict: "error"}
	reconciled.TelemetryEvents = reconciled.TelemetryEvents[:1]
	receiptValue, err := BuildSignedReceipt(reconciled, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt(reconciled): %v", err)
	}
	if receiptValue.Statement.Predicate.ResultClass != ResultClassReconciled {
		t.Fatalf("result_class = %q want reconciled", receiptValue.Statement.Predicate.ResultClass)
	}

	abnormal := testReceiptInput()
	abnormal.ExecutionStatus = "teardown_failed"
	abnormal.Outcome = Outcome{ExitCode: 137, Reason: "teardown_failed", ContainmentVerdict: "error"}
	abnormal.TelemetryEvents = abnormal.TelemetryEvents[:1]
	receiptValue, err = BuildSignedReceipt(abnormal, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt(abnormal): %v", err)
	}
	if receiptValue.Statement.Predicate.ResultClass != ResultClassAbnormal {
		t.Fatalf("result_class = %q want abnormal", receiptValue.Statement.Predicate.ResultClass)
	}
}

func TestBuildPredicateAddsNormalizedGovernedActionSummary(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	raw := append([]telemetry.Event{}, input.TelemetryEvents...)
	raw = append(raw, input.TelemetryEvents[len(input.TelemetryEvents)-1])
	input.TelemetryEvents = raw
	receiptValue, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receiptValue.Statement.Predicate.GovernedActions == nil {
		t.Fatal("expected governed action summary")
	}
	summary := receiptValue.Statement.Predicate.GovernedActions
	if summary.Count != 2 {
		t.Fatalf("raw governed action count = %d want 2", summary.Count)
	}
	if len(summary.Actions) != 2 {
		t.Fatalf("raw governed action records = %d want 2", len(summary.Actions))
	}
	if len(summary.Normalized) != 1 {
		t.Fatalf("normalized governed action records = %d want 1", len(summary.Normalized))
	}
	if summary.Normalized[0].Count != 2 {
		t.Fatalf("normalized count = %d want 2", summary.Normalized[0].Count)
	}
	if summary.Normalized[0].CapabilityPath != "direct_egress" || summary.Normalized[0].Used {
		t.Fatalf("unexpected normalized capability evidence: %+v", summary.Normalized[0])
	}
}

func testReceiptInput() Input {
	started := time.Unix(1700000000, 0).UTC()
	finished := started.Add(2 * time.Second)
	pointAllow, _ := json.Marshal(models.PolicyPointDecision{ExecutionID: "exec_123", EventSeq: 1, EventType: models.EventProcessExec, CedarAction: models.ActionExec, Decision: models.DecisionAllow, Reason: "allowed", Metadata: map[string]string{"policy_digest": "policy-digest"}})
	pointDeny, _ := json.Marshal(models.PolicyPointDecision{ExecutionID: "exec_123", EventSeq: 2, EventType: models.EventNetConnect, CedarAction: models.ActionConnect, Decision: models.DecisionDeny, Reason: "network disabled", Metadata: map[string]string{"policy_digest": "policy-digest"}})
	divergence, _ := json.Marshal(models.PolicyDivergenceResult{ExecutionID: "exec_123", Backend: models.BackendFirecracker, StartedAt: started, UpdatedAt: finished, LastSeq: 2, CurrentVerdict: models.DivergenceKillCandidate, TriggeredRules: []models.DivergenceRuleHit{{RuleID: "network.connect_disabled", Category: "network", Severity: models.DivergenceSeverityKillCandidate, Message: "connect destination=127.0.0.1 attempted while allow_network=false", EventSeq: 2}}})
	runtimeEvent, _ := json.Marshal(models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: started.UnixNano(), Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/python3", Comm: "python3"})
	governedAction, _ := json.Marshal(telemetry.GovernedActionData{
		ExecutionID:         "exec_123",
		ActionType:          "http_request",
		Target:              "tcp://127.0.0.1:80",
		Resource:            "tcp://127.0.0.1:80",
		Method:              "CONNECT",
		CapabilityPath:      "direct_egress",
		Decision:            "deny",
		Outcome:             "denied",
		Used:                false,
		Reason:              "network access is disabled by intent contract",
		RuleID:              "governance.direct_egress_disabled",
		PolicyDigest:        "policy-digest",
		Brokered:            false,
		BrokeredCredentials: false,
		DenialMarker:        "direct_egress_denied",
	})
	return Input{
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		Backend:         models.BackendFirecracker,
		TaskClass:       "summarize_document",
		DeclaredPurpose: "Summarize report.pdf into summary.md",
		StartedAt:       started,
		FinishedAt:      finished,
		IntentRaw:       []byte(`{"version":"v1","execution_id":"exec_123"}`),
		Policy: &PolicyEnvelope{
			Baseline: BaselinePolicy{
				Language:      "python",
				CodeSizeBytes: 11,
				MaxCodeBytes:  65536,
				TimeoutMs:     5000,
				MaxTimeoutMs:  10000,
				Profile:       "standard",
				Network: &BaselineNetworkPolicy{
					Mode:    policycfg.NetworkModeEgressAllowlist,
					Presets: []string{},
					Allowlist: &NetworkAllowlistEnvelope{
						FQDNs: []string{"registry.npmjs.org", "api.github.com"},
						CIDRs: []string{},
					},
				},
			},
			Intent: &IntentPolicyDigest{
				Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Source: PolicyIntentSourceContract,
			},
		},
		Outcome: Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed", OutputTruncated: false},
		Runtime: &RuntimeEnvelope{
			Profile:   "standard",
			VCPUCount: 2,
			MemoryMB:  768,
			Cgroup: &RuntimeCgroupEnvelope{
				MemoryMaxMB:  896,
				MemoryHighMB: 448,
				PidsMax:      100,
				CPUMax:       "50000 100000",
				SwapMax:      "0",
			},
			Network: &RuntimeNetworkEnvelope{
				Enabled: true,
				Mode:    policycfg.NetworkModeEgressAllowlist,
				Presets: []string{},
				Allowlist: &NetworkAllowlistEnvelope{
					FQDNs: []string{"registry.npmjs.org"},
					CIDRs: []string{"198.51.100.0/24"},
				},
			},
			Broker:           &RuntimeBrokerEnvelope{Enabled: true},
			AppliedOverrides: []string{"AEGIS_VM_MEMORY_MB"},
		},
		TelemetryEvents: []telemetry.Event{{ExecID: "exec_123", Kind: telemetry.KindRuntimeEvent, Data: runtimeEvent}, {ExecID: "exec_123", Kind: telemetry.KindPolicyPointDecision, Data: pointAllow}, {ExecID: "exec_123", Kind: telemetry.KindPolicyPointDecision, Data: pointDeny}, {ExecID: "exec_123", Kind: telemetry.KindPolicyDivergence, Data: divergence}, {ExecID: "exec_123", Kind: telemetry.KindGovernedAction, Data: governedAction}},
		Attributes:      map[string]string{"mode": "test"},
	}
}

func mustDevSigner(t *testing.T) *Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 1
	}
	signer, err := NewSigner(SigningConfig{
		Mode:    SigningModeDev,
		SeedB64: base64.StdEncoding.EncodeToString(seed),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

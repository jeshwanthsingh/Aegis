package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type outputArtifactFile struct {
	name string
	data []byte
	role string
}

type outputManifest struct {
	Version         string                 `json:"version"`
	ExecutionID     string                 `json:"execution_id,omitempty"`
	OutputTruncated bool                   `json:"output_truncated"`
	Artifacts       []outputManifestRecord `json:"artifacts"`
}

type outputManifestRecord struct {
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
	MediaType string `json:"media_type,omitempty"`
}

func ProofRoot(configured string) string {
	if strings.TrimSpace(configured) == "" {
		return DefaultProofRoot
	}
	return configured
}

func BundlePathsForExecution(root string, executionID string) BundlePaths {
	proofDir := filepath.Join(root, executionID)
	return BundlePaths{
		ProofDir:      proofDir,
		ReceiptPath:   filepath.Join(proofDir, "receipt.dsse.json"),
		PublicKeyPath: filepath.Join(proofDir, "receipt.pub"),
		SummaryPath:   filepath.Join(proofDir, "receipt.summary.txt"),
		ArtifactPaths: map[string]string{},
	}
}

func ResolveBundlePaths(root string, executionID string, proofDir string) (BundlePaths, error) {
	if strings.TrimSpace(proofDir) == "" {
		if strings.TrimSpace(executionID) == "" {
			return BundlePaths{}, verificationError(FailureClassBundleIncomplete, "either execution_id or proof_dir is required")
		}
		proofDir = filepath.Join(ProofRoot(root), executionID)
	}
	paths := BundlePaths{
		ProofDir:      proofDir,
		ReceiptPath:   filepath.Join(proofDir, "receipt.dsse.json"),
		PublicKeyPath: filepath.Join(proofDir, "receipt.pub"),
		SummaryPath:   filepath.Join(proofDir, "receipt.summary.txt"),
		ArtifactPaths: map[string]string{},
	}
	if err := hydrateArtifactPaths(&paths); err != nil {
		return BundlePaths{}, err
	}
	return paths, nil
}

func ArtifactsFromOutputs(stdout string, stderr string, truncated bool) []Artifact {
	files := outputArtifactFiles(stdout, stderr, truncated)
	artifacts := make([]Artifact, 0, len(files))
	for _, file := range files {
		digest := sha256.Sum256(file.data)
		artifacts = append(artifacts, Artifact{
			Name:      file.name,
			Digest:    map[string]string{"sha256": hex.EncodeToString(digest[:])},
			Path:      file.name,
			MediaType: "text/plain",
			Role:      file.role,
		})
	}
	return artifacts
}

func ArtifactsFromBundleOutputs(executionID string, stdout string, stderr string, truncated bool) []Artifact {
	files := bundleArtifactFiles(executionID, stdout, stderr, truncated)
	artifacts := make([]Artifact, 0, len(files))
	for _, file := range files {
		mediaType := "text/plain"
		if strings.HasSuffix(file.name, ".json") {
			mediaType = "application/json"
		}
		digest := sha256.Sum256(file.data)
		artifacts = append(artifacts, Artifact{
			Name:      file.name,
			Digest:    map[string]string{"sha256": hex.EncodeToString(digest[:])},
			Path:      file.name,
			MediaType: mediaType,
			Role:      file.role,
		})
	}
	return artifacts
}

func WriteProofBundle(root string, executionID string, signedReceipt SignedReceipt, publicKey ed25519.PublicKey, stdout string, stderr string, truncated bool) (BundlePaths, error) {
	paths := BundlePathsForExecution(root, executionID)
	if err := os.MkdirAll(paths.ProofDir, 0o755); err != nil {
		return BundlePaths{}, fmt.Errorf("create proof dir: %w", err)
	}
	files := bundleArtifactFiles(executionID, stdout, stderr, truncated)
	for _, file := range files {
		artifactPath := filepath.Join(paths.ProofDir, file.name)
		if err := os.WriteFile(artifactPath, file.data, 0o644); err != nil {
			return BundlePaths{}, fmt.Errorf("write artifact %s: %w", file.name, err)
		}
		paths.ArtifactPaths[file.name] = artifactPath
	}
	receiptBytes, err := json.MarshalIndent(signedReceipt, "", "  ")
	if err != nil {
		return BundlePaths{}, fmt.Errorf("marshal signed receipt: %w", err)
	}
	if err := os.WriteFile(paths.ReceiptPath, receiptBytes, 0o644); err != nil {
		return BundlePaths{}, fmt.Errorf("write receipt: %w", err)
	}
	pubPEM, err := MarshalPublicKeyPEM(publicKey)
	if err != nil {
		return BundlePaths{}, fmt.Errorf("encode public key: %w", err)
	}
	if err := os.WriteFile(paths.PublicKeyPath, pubPEM, 0o644); err != nil {
		return BundlePaths{}, fmt.Errorf("write receipt public key: %w", err)
	}
	report, verifyErr := VerifyReceiptFileReport(paths.ReceiptPath, paths.PublicKeyPath)
	summary := FormatSummary(report.Statement, report.Verified)
	if verifyErr != nil {
		summary = fmt.Sprintf("verification=failed\nverification_failure_class=%s\nerror=%s\n", report.FailureClass, report.FailureDetail)
	}
	if err := os.WriteFile(paths.SummaryPath, []byte(summary), 0o644); err != nil {
		return BundlePaths{}, fmt.Errorf("write receipt summary: %w", err)
	}
	paths.ArtifactCount = len(signedReceipt.Statement.Subject)
	paths.DivergenceVerdict = string(signedReceipt.Statement.Predicate.Divergence.Verdict)
	return paths, nil
}

func LoadSignedReceiptFile(path string) (SignedReceipt, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SignedReceipt{}, verificationErrorWrap(FailureClassBundleIncomplete, err, "read receipt file: %v", err)
		}
		return SignedReceipt{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "read receipt file: %v", err)
	}
	return ParseSignedReceiptJSON(bytes)
}

func ParseSignedReceiptJSON(raw []byte) (SignedReceipt, error) {
	var receipt SignedReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return SignedReceipt{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "decode receipt file: %v", err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return SignedReceipt{}, verificationError(FailureClassSignatureInvalid, "decode receipt file: trailing content")
		}
		return SignedReceipt{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "decode receipt file: trailing content: %v", err)
	}
	return receipt, nil
}

func MarshalPublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ParsePublicKeyPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, verificationError(FailureClassSignatureInvalid, "decode public key PEM: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, verificationErrorWrap(FailureClassSignatureInvalid, err, "parse public key PEM: %v", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, verificationError(FailureClassSignatureInvalid, "parse public key PEM: unexpected key type %T", key)
	}
	return publicKey, nil
}

func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, verificationErrorWrap(FailureClassBundleIncomplete, err, "read public key file: %v", err)
		}
		return nil, verificationErrorWrap(FailureClassSignatureInvalid, err, "read public key file: %v", err)
	}
	return ParsePublicKeyPEM(pemBytes)
}

func VerifyReceiptFileReport(receiptPath string, publicKeyPath string) (VerificationReport, error) {
	receiptFile, err := LoadSignedReceiptFile(receiptPath)
	if err != nil {
		class, _ := VerificationFailure(err)
		return VerificationReport{FailureClass: class, FailureDetail: err.Error()}, err
	}
	publicKey, err := LoadPublicKeyFile(publicKeyPath)
	if err != nil {
		class, _ := VerificationFailure(err)
		return VerificationReport{FailureClass: class, FailureDetail: err.Error()}, err
	}
	statement, err := VerifySignedReceipt(receiptFile, publicKey)
	if err != nil {
		class, _ := VerificationFailure(err)
		return VerificationReport{FailureClass: class, FailureDetail: err.Error()}, err
	}
	return VerificationReport{Verified: true, Statement: statement}, nil
}

func VerifyReceiptFile(receiptPath string, publicKeyPath string) (Statement, error) {
	report, err := VerifyReceiptFileReport(receiptPath, publicKeyPath)
	if err != nil {
		return Statement{}, err
	}
	return report.Statement, nil
}

func VerifyBundleReport(paths BundlePaths) (VerificationReport, error) {
	report, err := VerifyReceiptFileReport(paths.ReceiptPath, paths.PublicKeyPath)
	if err != nil {
		return report, err
	}
	if len(paths.ArtifactPaths) == 0 {
		if err := hydrateArtifactPaths(&paths); err != nil {
			class, _ := VerificationFailure(err)
			return VerificationReport{FailureClass: class, FailureDetail: err.Error()}, err
		}
	}
	if err := verifyBundleArtifacts(paths, report.Statement); err != nil {
		class, _ := VerificationFailure(err)
		return VerificationReport{FailureClass: class, FailureDetail: err.Error()}, err
	}
	report.Verified = true
	return report, nil
}

func VerifyBundlePaths(paths BundlePaths) (Statement, error) {
	report, err := VerifyBundleReport(paths)
	if err != nil {
		return Statement{}, err
	}
	return report.Statement, nil
}

func FormatSummary(statement Statement, verified bool) string {
	ruleIDs := append([]string(nil), statement.Predicate.Divergence.TriggeredRuleIDs...)
	sort.Strings(ruleIDs)
	subjects := make([]string, 0, len(statement.Subject))
	for _, subject := range statement.Subject {
		sha := subject.Digest["sha256"]
		if sha == "" {
			sha = "missing"
		}
		subjects = append(subjects, fmt.Sprintf("%s sha256=%s", subject.Name, sha))
	}
	if len(ruleIDs) == 0 {
		ruleIDs = []string{"none"}
	}
	if len(subjects) == 0 {
		subjects = []string{"none"}
	}
	verification := "failed"
	if verified {
		verification = "verified"
	}
	lines := []string{
		"verification=" + verification,
		"schema_version=" + statement.Predicate.Version,
		"execution_id=" + statement.Predicate.ExecutionID,
		"started_at=" + statement.Predicate.StartedAt.Format(time.RFC3339Nano),
		"finished_at=" + statement.Predicate.FinishedAt.Format(time.RFC3339Nano),
		"backend=" + string(statement.Predicate.Backend),
		"policy_digest=" + defaultSummaryValue(statement.Predicate.PolicyDigest),
		"signer_key_id=" + defaultSummaryValue(statement.Predicate.SignerKeyID),
		"signing_mode=" + string(statement.Predicate.Trust.SigningMode),
		"intent_digest=" + defaultSummaryValue(statement.Predicate.IntentDigest),
		"trust_limitations=" + trustLimitationsText(statement.Predicate.Trust),
		"outcome=" + statement.Predicate.Outcome.Reason,
		fmt.Sprintf("exit_code=%d", statement.Predicate.Outcome.ExitCode),
		"execution_status=" + defaultSummaryValue(statement.Predicate.ExecutionStatus),
		"semantics_mode=" + string(statement.Predicate.SemanticsMode),
		"result_class=" + string(statement.Predicate.ResultClass),
		"key_source=" + string(statement.Predicate.Trust.KeySource),
		"attestation=" + statement.Predicate.Trust.Attestation,
		"divergence_verdict=" + string(statement.Predicate.Divergence.Verdict),
		"rule_hits=" + strings.Join(ruleIDs, ","),
		fmt.Sprintf("artifact_count=%d", len(statement.Subject)),
		"artifacts=" + strings.Join(subjects, "; "),
	}
	if statement.Predicate.WorkspaceID != "" {
		lines = append(lines, "workspace_id="+statement.Predicate.WorkspaceID)
	}
	if statement.Predicate.Denial != nil {
		lines = append(lines, "denial_class="+string(statement.Predicate.Denial.Class))
		if statement.Predicate.Denial.RuleID != "" {
			lines = append(lines, "denial_rule_id="+statement.Predicate.Denial.RuleID)
		}
		if statement.Predicate.Denial.Marker != "" {
			lines = append(lines, "denial_marker="+statement.Predicate.Denial.Marker)
		}
	}
	if statement.Predicate.Runtime != nil {
		lines = append(lines,
			"runtime_profile="+defaultSummaryValue(statement.Predicate.Runtime.Profile),
			fmt.Sprintf("runtime_vcpu_count=%d", statement.Predicate.Runtime.VCPUCount),
			fmt.Sprintf("runtime_memory_mb=%d", statement.Predicate.Runtime.MemoryMB),
		)
		if statement.Predicate.Runtime.Cgroup != nil {
			lines = append(lines,
				fmt.Sprintf("runtime_cgroup_memory_max_mb=%d", statement.Predicate.Runtime.Cgroup.MemoryMaxMB),
				fmt.Sprintf("runtime_cgroup_memory_high_mb=%d", statement.Predicate.Runtime.Cgroup.MemoryHighMB),
				fmt.Sprintf("runtime_cgroup_pids_max=%d", statement.Predicate.Runtime.Cgroup.PidsMax),
				"runtime_cgroup_cpu_max="+defaultSummaryValue(statement.Predicate.Runtime.Cgroup.CPUMax),
				"runtime_cgroup_swap_max="+defaultSummaryValue(statement.Predicate.Runtime.Cgroup.SwapMax),
			)
		}
		if statement.Predicate.Runtime.Network != nil {
			lines = append(lines,
				"runtime_network_mode="+defaultSummaryValue(statement.Predicate.Runtime.Network.Mode),
				"runtime_network_enabled="+strconv.FormatBool(statement.Predicate.Runtime.Network.Enabled),
			)
			if len(statement.Predicate.Runtime.Network.Presets) > 0 {
				lines = append(lines, "runtime_network_presets="+strings.Join(statement.Predicate.Runtime.Network.Presets, ","))
			}
		}
		if statement.Predicate.Runtime.Broker != nil {
			lines = append(lines, "runtime_broker_enabled="+strconv.FormatBool(statement.Predicate.Runtime.Broker.Enabled))
		}
		if len(statement.Predicate.Runtime.AppliedOverrides) > 0 {
			lines = append(lines, "runtime_applied_overrides="+strings.Join(statement.Predicate.Runtime.AppliedOverrides, ","))
		}
	}
	if statement.Predicate.BrokerSummary != nil {
		brokerEvents := []string{"credential.request"}
		if statement.Predicate.BrokerSummary.AllowedCount > 0 {
			brokerEvents = append(brokerEvents, "credential.allowed")
		}
		if statement.Predicate.BrokerSummary.DeniedCount > 0 {
			brokerEvents = append(brokerEvents, "credential.denied")
		}
		lines = append(lines,
			"broker_events="+strings.Join(brokerEvents, ","),
			fmt.Sprintf("broker_request_count=%d", statement.Predicate.BrokerSummary.RequestCount),
			fmt.Sprintf("broker_allowed_count=%d", statement.Predicate.BrokerSummary.AllowedCount),
			fmt.Sprintf("broker_denied_count=%d", statement.Predicate.BrokerSummary.DeniedCount),
		)
		if len(statement.Predicate.BrokerSummary.DomainsAllowed) > 0 {
			lines = append(lines, "broker_domains_allowed="+strings.Join(statement.Predicate.BrokerSummary.DomainsAllowed, ","))
		}
		if len(statement.Predicate.BrokerSummary.DomainsDenied) > 0 {
			lines = append(lines, "broker_domains_denied="+strings.Join(statement.Predicate.BrokerSummary.DomainsDenied, ","))
		}
		if len(statement.Predicate.BrokerSummary.BindingsUsed) > 0 {
			lines = append(lines, "broker_bindings_used="+strings.Join(statement.Predicate.BrokerSummary.BindingsUsed, ","))
		}
	}
	if statement.Predicate.GovernedActions != nil {
		lines = append(lines, fmt.Sprintf("governed_action_count=%d", statement.Predicate.GovernedActions.Count))
		for idx, action := range statement.Predicate.GovernedActions.Actions {
			lines = append(lines, fmt.Sprintf("governed_action_%d=%s", idx+1, formatGovernedActionFields(action)))
		}
		lines = append(lines, fmt.Sprintf("governed_action_normalized_count=%d", len(statement.Predicate.GovernedActions.Normalized)))
		for idx, action := range statement.Predicate.GovernedActions.Normalized {
			lines = append(lines, fmt.Sprintf("governed_action_normalized_%d=%s", idx+1, formatNormalizedGovernedActionFields(action)))
			lines = append(lines, fmt.Sprintf("capability_%d=%s", idx+1, formatCapabilitySummaryFields(action)))
		}
		lines = append(lines, fmt.Sprintf("capability_count=%d", len(statement.Predicate.GovernedActions.Normalized)))
	}
	return strings.Join(lines, "\n") + "\n"
}

func defaultSummaryValue(v string) string {
	if strings.TrimSpace(v) == "" {
		return "none"
	}
	return v
}

func hydrateArtifactPaths(paths *BundlePaths) error {
	entries, err := os.ReadDir(paths.ProofDir)
	if err != nil {
		return verificationErrorWrap(FailureClassBundleIncomplete, err, "read proof dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch name {
		case filepath.Base(paths.ReceiptPath), filepath.Base(paths.PublicKeyPath), filepath.Base(paths.SummaryPath):
			continue
		default:
			paths.ArtifactPaths[name] = filepath.Join(paths.ProofDir, name)
		}
	}
	return nil
}

func verifyBundleArtifacts(paths BundlePaths, statement Statement) error {
	expected := make(map[string]string, len(statement.Subject))
	for _, subject := range statement.Subject {
		sha := strings.TrimSpace(subject.Digest["sha256"])
		if sha == "" {
			return verificationError(FailureClassSemanticReceipt, "subject %s missing sha256 digest", subject.Name)
		}
		expected[subject.Name] = sha
	}
	if len(paths.ArtifactPaths) != len(expected) {
		return verificationError(FailureClassArtifactIntegrity, "artifact set mismatch: proof_dir has %d artifact(s), receipt binds %d", len(paths.ArtifactPaths), len(expected))
	}
	for name := range paths.ArtifactPaths {
		if _, ok := expected[name]; !ok {
			return verificationError(FailureClassArtifactIntegrity, "unexpected artifact in proof bundle: %s", name)
		}
	}
	for name, want := range expected {
		artifactPath := paths.ArtifactPaths[name]
		if strings.TrimSpace(artifactPath) == "" {
			return verificationError(FailureClassBundleIncomplete, "missing bound artifact in proof bundle: %s", name)
		}
		raw, err := os.ReadFile(artifactPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return verificationErrorWrap(FailureClassBundleIncomplete, err, "read bound artifact %s: %v", name, err)
			}
			return verificationErrorWrap(FailureClassArtifactIntegrity, err, "read bound artifact %s: %v", name, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			return verificationError(FailureClassArtifactIntegrity, "artifact digest mismatch for %s: got %s want %s", name, got, want)
		}
	}
	if manifestPath := paths.ArtifactPaths["output-manifest.json"]; manifestPath != "" {
		if err := verifyOutputManifest(manifestPath, expected); err != nil {
			return err
		}
	}
	return nil
}

func verifyOutputManifest(path string, expected map[string]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return verificationErrorWrap(FailureClassBundleIncomplete, err, "read output manifest: %v", err)
		}
		return verificationErrorWrap(FailureClassArtifactIntegrity, err, "read output manifest: %v", err)
	}
	var manifest outputManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return verificationErrorWrap(FailureClassArtifactIntegrity, err, "decode output manifest: %v", err)
	}
	manifestExpected := make(map[string]struct{}, len(expected))
	for name := range expected {
		if name == "output-manifest.json" {
			continue
		}
		manifestExpected[name] = struct{}{}
	}
	if len(manifest.Artifacts) != len(manifestExpected) {
		return verificationError(FailureClassArtifactIntegrity, "output manifest artifact count mismatch: got %d want %d", len(manifest.Artifacts), len(manifestExpected))
	}
	for _, artifact := range manifest.Artifacts {
		if _, ok := manifestExpected[artifact.Name]; !ok {
			return verificationError(FailureClassArtifactIntegrity, "output manifest contains unexpected artifact: %s", artifact.Name)
		}
		delete(manifestExpected, artifact.Name)
	}
	if len(manifestExpected) != 0 {
		names := make([]string, 0, len(manifestExpected))
		for name := range manifestExpected {
			names = append(names, name)
		}
		sort.Strings(names)
		return verificationError(FailureClassArtifactIntegrity, "output manifest missing artifact(s): %s", strings.Join(names, ","))
	}
	return nil
}

func FormatReview(paths BundlePaths, report VerificationReport) string {
	lines := []string{
		"[verification]",
		"status=" + map[bool]string{true: "verified", false: "failed"}[report.Verified],
	}
	if report.Verified {
		lines = append(lines, "failure_class=none")
		lines = append(lines, "semantics_mode="+string(report.Statement.Predicate.SemanticsMode))
	} else {
		lines = append(lines, "failure_class="+string(report.FailureClass))
		if strings.TrimSpace(report.FailureDetail) != "" {
			lines = append(lines, "detail="+report.FailureDetail)
		}
	}
	lines = append(lines,
		"[bundle]",
		"proof_dir="+paths.ProofDir,
		"receipt_path="+paths.ReceiptPath,
		"public_key_path="+paths.PublicKeyPath,
		"summary_path="+paths.SummaryPath,
	)
	names := make([]string, 0, len(paths.ArtifactPaths))
	for name := range paths.ArtifactPaths {
		names = append(names, name)
	}
	sort.Strings(names)
	lines = append(lines, "[artifacts]")
	if len(names) == 0 {
		lines = append(lines, "count=0")
	} else {
		lines = append(lines, fmt.Sprintf("count=%d", len(names)))
		for _, name := range names {
			lines = append(lines, fmt.Sprintf("artifact=%s path=%s", name, paths.ArtifactPaths[name]))
		}
	}
	if !report.Verified {
		return strings.Join(lines, "\n") + "\n"
	}
	p := report.Statement.Predicate
	lines = append(lines,
		"[execution]",
		"execution_id="+p.ExecutionID,
		"result_class="+string(p.ResultClass),
		"backend="+string(p.Backend),
		"outcome_reason="+p.Outcome.Reason,
		fmt.Sprintf("exit_code=%d", p.Outcome.ExitCode),
		"divergence_verdict="+string(p.Divergence.Verdict),
	)
	if p.ExecutionStatus != "" {
		lines = append(lines, "execution_status="+p.ExecutionStatus)
	}
	if p.Denial != nil {
		lines = append(lines,
			"[denial]",
			"class="+string(p.Denial.Class),
		)
		if p.Denial.RuleID != "" {
			lines = append(lines, "rule_id="+p.Denial.RuleID)
		}
		if p.Denial.Marker != "" {
			lines = append(lines, "marker="+p.Denial.Marker)
		}
	}
	lines = append(lines, "[capabilities]")
	if p.GovernedActions == nil || len(p.GovernedActions.Normalized) == 0 {
		lines = append(lines, "count=0")
	} else {
		lines = append(lines, fmt.Sprintf("count=%d", len(p.GovernedActions.Normalized)))
		for idx, action := range p.GovernedActions.Normalized {
			lines = append(lines, fmt.Sprintf("capability_%d=%s", idx+1, formatCapabilitySummaryFields(action)))
		}
	}
	lines = append(lines, "[governed_actions]")
	if p.GovernedActions == nil || len(p.GovernedActions.Actions) == 0 {
		lines = append(lines, "raw_count=0", "normalized_count=0")
	} else {
		lines = append(lines,
			fmt.Sprintf("raw_count=%d", p.GovernedActions.Count),
			fmt.Sprintf("normalized_count=%d", len(p.GovernedActions.Normalized)),
		)
		for idx, action := range p.GovernedActions.Normalized {
			lines = append(lines, fmt.Sprintf("normalized_%d=%s", idx+1, formatNormalizedGovernedActionFields(action)))
		}
		for idx, action := range p.GovernedActions.Actions {
			lines = append(lines, fmt.Sprintf("raw_%d=%s", idx+1, formatGovernedActionFields(action)))
		}
	}
	lines = append(lines, "[broker]")
	if p.BrokerSummary == nil {
		lines = append(lines, "request_count=0", "allowed_count=0", "denied_count=0")
	} else {
		lines = append(lines,
			fmt.Sprintf("request_count=%d", p.BrokerSummary.RequestCount),
			fmt.Sprintf("allowed_count=%d", p.BrokerSummary.AllowedCount),
			fmt.Sprintf("denied_count=%d", p.BrokerSummary.DeniedCount),
		)
		if len(p.BrokerSummary.BindingsUsed) > 0 {
			lines = append(lines, "bindings_used="+strings.Join(p.BrokerSummary.BindingsUsed, ","))
		}
		if len(p.BrokerSummary.DomainsAllowed) > 0 {
			lines = append(lines, "domains_allowed="+strings.Join(p.BrokerSummary.DomainsAllowed, ","))
		}
		if len(p.BrokerSummary.DomainsDenied) > 0 {
			lines = append(lines, "domains_denied="+strings.Join(p.BrokerSummary.DomainsDenied, ","))
		}
	}
	lines = append(lines, "[workspace]")
	if p.WorkspaceID == "" {
		lines = append(lines, "workspace_id=none")
	} else {
		lines = append(lines, "workspace_id="+p.WorkspaceID)
	}
	lines = append(lines, "[reconciliation]")
	if p.ResultClass == ResultClassReconciled {
		lines = append(lines, "status=reconciled", "recovered=true")
	} else {
		lines = append(lines, "status=not_reconciled", "recovered=false")
	}
	lines = append(lines,
		"[limitations]",
		"trust_limitations="+trustLimitationsText(p.Trust),
	)
	if len(p.Limitations) > 0 {
		lines = append(lines, "receipt_limitations="+strings.Join(p.Limitations, ","))
	} else {
		lines = append(lines, "receipt_limitations=none")
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatGovernedActionFields(action GovernedActionRecord) string {
	fields := []string{
		fmt.Sprintf("kind=%s", action.ActionType),
		fmt.Sprintf("decision=%s", action.Decision),
		fmt.Sprintf("target=%s", action.Target),
		fmt.Sprintf("used=%t", action.Used),
		fmt.Sprintf("brokered=%t", action.Brokered),
		fmt.Sprintf("brokered_credentials=%t", action.BrokeredCredentials),
	}
	if action.CapabilityPath != "" {
		fields = append(fields, "capability_path="+action.CapabilityPath)
	}
	if action.Method != "" {
		fields = append(fields, "method="+action.Method)
	}
	if action.Outcome != "" {
		fields = append(fields, "outcome="+action.Outcome)
	}
	if action.RuleID != "" {
		fields = append(fields, "rule_id="+action.RuleID)
	}
	if action.PolicyDigest != "" {
		fields = append(fields, "policy_digest="+action.PolicyDigest)
	}
	if action.BindingName != "" {
		fields = append(fields, "binding_name="+action.BindingName)
	}
	if action.ResponseDigest != "" {
		fields = append(fields, fmt.Sprintf("response_digest=%s:%s", action.ResponseDigestAlgo, action.ResponseDigest))
	}
	if action.DenialMarker != "" {
		fields = append(fields, "denial_marker="+action.DenialMarker)
	}
	if action.Reason != "" {
		fields = append(fields, "reason="+action.Reason)
	}
	if action.Error != "" {
		fields = append(fields, "error="+action.Error)
	}
	if len(action.AuditPayload) > 0 {
		fields = append(fields, "audit_payload="+formatAuditPayload(action.AuditPayload))
	}
	return strings.Join(fields, " ")
}

func formatNormalizedGovernedActionFields(action NormalizedGovernedActionEntry) string {
	fields := []string{
		fmt.Sprintf("count=%d", action.Count),
		fmt.Sprintf("kind=%s", action.ActionType),
		fmt.Sprintf("decision=%s", action.Decision),
		fmt.Sprintf("target=%s", action.Target),
		fmt.Sprintf("used=%t", action.Used),
		fmt.Sprintf("brokered=%t", action.Brokered),
		fmt.Sprintf("brokered_credentials=%t", action.BrokeredCredentials),
	}
	if action.CapabilityPath != "" {
		fields = append(fields, "capability_path="+action.CapabilityPath)
	}
	if action.Method != "" {
		fields = append(fields, "method="+action.Method)
	}
	if action.Outcome != "" {
		fields = append(fields, "outcome="+action.Outcome)
	}
	if action.RuleID != "" {
		fields = append(fields, "rule_id="+action.RuleID)
	}
	if action.PolicyDigest != "" {
		fields = append(fields, "policy_digest="+action.PolicyDigest)
	}
	if action.BindingName != "" {
		fields = append(fields, "binding_name="+action.BindingName)
	}
	if action.ResponseDigest != "" {
		fields = append(fields, fmt.Sprintf("response_digest=%s:%s", action.ResponseDigestAlgo, action.ResponseDigest))
	}
	if action.DenialMarker != "" {
		fields = append(fields, "denial_marker="+action.DenialMarker)
	}
	if action.Reason != "" {
		fields = append(fields, "reason="+action.Reason)
	}
	if action.Error != "" {
		fields = append(fields, "error="+action.Error)
	}
	if len(action.AuditPayload) > 0 {
		fields = append(fields, "audit_payload="+formatAuditPayload(action.AuditPayload))
	}
	return strings.Join(fields, " ")
}

func formatCapabilitySummaryFields(action NormalizedGovernedActionEntry) string {
	fields := []string{
		fmt.Sprintf("count=%d", action.Count),
		fmt.Sprintf("requested=%s", action.ActionType),
		fmt.Sprintf("decision=%s", action.Decision),
		fmt.Sprintf("used=%t", action.Used),
		fmt.Sprintf("brokered=%t", action.Brokered),
		fmt.Sprintf("credential_injected=%t", action.BrokeredCredentials),
		fmt.Sprintf("target=%s", action.Target),
	}
	if action.CapabilityPath != "" {
		fields = append(fields, "path="+action.CapabilityPath)
	}
	if action.Method != "" {
		fields = append(fields, "method="+action.Method)
	}
	if action.BindingName != "" {
		fields = append(fields, "binding_name="+action.BindingName)
	}
	if action.RuleID != "" {
		fields = append(fields, "rule_id="+action.RuleID)
	}
	if action.PolicyDigest != "" {
		fields = append(fields, "policy_digest="+action.PolicyDigest)
	}
	if action.DenialMarker != "" {
		fields = append(fields, "denial_marker="+action.DenialMarker)
	}
	return strings.Join(fields, " ")
}

func formatAuditPayload(payload map[string]string) string {
	if len(payload) == 0 {
		return ""
	}
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+payload[key])
	}
	return strings.Join(parts, ",")
}

func bundleArtifactFiles(executionID string, stdout string, stderr string, truncated bool) []outputArtifactFile {
	files := outputArtifactFiles(stdout, stderr, truncated)
	manifest := buildOutputManifest(executionID, files, truncated)
	files = append(files, outputArtifactFile{name: "output-manifest.json", data: manifest, role: "manifest"})
	return files
}

func buildOutputManifest(executionID string, files []outputArtifactFile, truncated bool) []byte {
	records := make([]outputManifestRecord, 0, len(files))
	for _, file := range files {
		mediaType := "text/plain"
		if strings.HasSuffix(file.name, ".json") {
			mediaType = "application/json"
		}
		records = append(records, outputManifestRecord{Name: file.name, Role: file.role, MediaType: mediaType})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	manifest := outputManifest{Version: "v1", ExecutionID: executionID, OutputTruncated: truncated, Artifacts: records}
	bytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fallback := fmt.Sprintf("{\"version\":\"v1\",\"execution_id\":%q,\"output_truncated\":%t,\"artifacts\":[]}", executionID, truncated)
		return []byte(fallback)
	}
	bytes = append(bytes, '\n')
	return bytes
}

func outputArtifactFiles(stdout string, stderr string, truncated bool) []outputArtifactFile {
	files := make([]outputArtifactFile, 0, 2)
	stdoutName := "stdout.txt"
	stderrName := "stderr.txt"
	if truncated {
		stdoutName = "stdout.truncated.txt"
		stderrName = "stderr.truncated.txt"
	}
	if stdout != "" {
		files = append(files, outputArtifactFile{name: stdoutName, data: []byte(stdout), role: "stdout"})
	}
	if stderr != "" {
		files = append(files, outputArtifactFile{name: stderrName, data: []byte(stderr), role: "stderr"})
	}
	return files
}

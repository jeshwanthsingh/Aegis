package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
			return BundlePaths{}, fmt.Errorf("either execution_id or proof_dir is required")
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
	verifiedStatement, verifyErr := VerifySignedReceipt(signedReceipt, publicKey)
	summary := FormatSummary(verifiedStatement, verifyErr == nil)
	if verifyErr != nil {
		summary = fmt.Sprintf("verification=failed\nerror=%s\n", verifyErr.Error())
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
		return SignedReceipt{}, fmt.Errorf("read receipt file: %w", err)
	}
	return ParseSignedReceiptJSON(bytes)
}

func ParseSignedReceiptJSON(raw []byte) (SignedReceipt, error) {
	var receipt SignedReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return SignedReceipt{}, fmt.Errorf("decode receipt file: %w", err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return SignedReceipt{}, fmt.Errorf("decode receipt file: trailing content")
		}
		return SignedReceipt{}, fmt.Errorf("decode receipt file: trailing content: %w", err)
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
		return nil, fmt.Errorf("decode public key PEM: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key PEM: %w", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parse public key PEM: unexpected key type %T", key)
	}
	return publicKey, nil
}

func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	return ParsePublicKeyPEM(pemBytes)
}

func VerifyReceiptFile(receiptPath string, publicKeyPath string) (Statement, error) {
	receiptFile, err := LoadSignedReceiptFile(receiptPath)
	if err != nil {
		return Statement{}, err
	}
	publicKey, err := LoadPublicKeyFile(publicKeyPath)
	if err != nil {
		return Statement{}, err
	}
	return VerifySignedReceipt(receiptFile, publicKey)
}

func VerifyBundlePaths(paths BundlePaths) (Statement, error) {
	statement, err := VerifyReceiptFile(paths.ReceiptPath, paths.PublicKeyPath)
	if err != nil {
		return Statement{}, err
	}
	if len(paths.ArtifactPaths) == 0 {
		if err := hydrateArtifactPaths(&paths); err != nil {
			return Statement{}, err
		}
	}
	if err := verifyBundleArtifacts(paths, statement); err != nil {
		return Statement{}, err
	}
	return statement, nil
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
		"execution_id=" + statement.Predicate.ExecutionID,
		"backend=" + string(statement.Predicate.Backend),
		"signing_mode=" + string(statement.Predicate.Trust.SigningMode),
		"key_source=" + string(statement.Predicate.Trust.KeySource),
		"attestation=" + statement.Predicate.Trust.Attestation,
		"trust_limitations=" + trustLimitationsText(statement.Predicate.Trust),
		"started_at=" + statement.Predicate.StartedAt.Format(time.RFC3339Nano),
		"finished_at=" + statement.Predicate.FinishedAt.Format(time.RFC3339Nano),
		fmt.Sprintf("outcome=%s exit_code=%d", statement.Predicate.Outcome.Reason, statement.Predicate.Outcome.ExitCode),
		"divergence_verdict=" + string(statement.Predicate.Divergence.Verdict),
		"rule_hits=" + strings.Join(ruleIDs, ","),
		fmt.Sprintf("artifact_count=%d", len(statement.Subject)),
		"artifacts=" + strings.Join(subjects, "; "),
	}
	if statement.Predicate.WorkspaceID != "" {
		lines = append(lines, "workspace_id="+statement.Predicate.WorkspaceID)
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
			fields := []string{
				fmt.Sprintf("kind=%s", action.ActionType),
				fmt.Sprintf("decision=%s", action.Decision),
				fmt.Sprintf("target=%s", action.Target),
				fmt.Sprintf("brokered=%t", action.Brokered),
				fmt.Sprintf("brokered_credentials=%t", action.BrokeredCredentials),
			}
			if action.Method != "" {
				fields = append(fields, "method="+action.Method)
			}
			if action.RuleID != "" {
				fields = append(fields, "rule_id="+action.RuleID)
			}
			if action.PolicyDigest != "" {
				fields = append(fields, "policy_digest="+action.PolicyDigest)
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
			lines = append(lines, fmt.Sprintf("governed_action_%d=%s", idx+1, strings.Join(fields, " ")))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func hydrateArtifactPaths(paths *BundlePaths) error {
	entries, err := os.ReadDir(paths.ProofDir)
	if err != nil {
		return fmt.Errorf("read proof dir: %w", err)
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
			return fmt.Errorf("subject %s missing sha256 digest", subject.Name)
		}
		expected[subject.Name] = sha
	}
	if len(paths.ArtifactPaths) != len(expected) {
		return fmt.Errorf("artifact set mismatch: proof_dir has %d artifact(s), receipt binds %d", len(paths.ArtifactPaths), len(expected))
	}
	for name := range paths.ArtifactPaths {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected artifact in proof bundle: %s", name)
		}
	}
	for name, want := range expected {
		artifactPath := paths.ArtifactPaths[name]
		if strings.TrimSpace(artifactPath) == "" {
			return fmt.Errorf("missing bound artifact in proof bundle: %s", name)
		}
		raw, err := os.ReadFile(artifactPath)
		if err != nil {
			return fmt.Errorf("read bound artifact %s: %w", name, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			return fmt.Errorf("artifact digest mismatch for %s: got %s want %s", name, got, want)
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
		return fmt.Errorf("read output manifest: %w", err)
	}
	var manifest outputManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("decode output manifest: %w", err)
	}
	manifestExpected := make(map[string]struct{}, len(expected))
	for name := range expected {
		if name == "output-manifest.json" {
			continue
		}
		manifestExpected[name] = struct{}{}
	}
	if len(manifest.Artifacts) != len(manifestExpected) {
		return fmt.Errorf("output manifest artifact count mismatch: got %d want %d", len(manifest.Artifacts), len(manifestExpected))
	}
	for _, artifact := range manifest.Artifacts {
		if _, ok := manifestExpected[artifact.Name]; !ok {
			return fmt.Errorf("output manifest contains unexpected artifact: %s", artifact.Name)
		}
		delete(manifestExpected, artifact.Name)
	}
	if len(manifestExpected) != 0 {
		names := make([]string, 0, len(manifestExpected))
		for name := range manifestExpected {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("output manifest missing artifact(s): %s", strings.Join(names, ","))
	}
	return nil
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

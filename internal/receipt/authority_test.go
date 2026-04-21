package receipt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"aegis/internal/authority"
	"aegis/internal/governance"
	policycfg "aegis/internal/policy"
)

func testAuthorityContext() authority.Context {
	ctx := authority.Context{
		ExecutionID:          "exec_123",
		PolicyDigest:         PolicyDigest(testReceiptInput().Policy),
		BrokerAllowedDomains: []string{"api.github.com"},
		BrokerRepoLabels:     []string{"demo"},
		BrokerActionTypes:    []string{governance.ActionHTTPRequest},
		ApprovalMode:         authority.ApprovalModeNone,
		Boot: authority.BootContext{
			RootfsImage: "alpine-base.ext4#abc12345",
			Mounts: []authority.MountSpec{
				{Name: "rootfs", Kind: authority.MountKindRootfs, Target: "/", ReadOnly: true},
				{Name: "workspace", Kind: authority.MountKindWorkspace, Target: "/workspace", Persistent: true},
			},
			NetworkMode: policycfg.NetworkModeEgressAllowlist,
			EgressAllowlist: policycfg.NetworkAllowlist{
				FQDNs: []string{"api.github.com"},
				CIDRs: []string{"198.51.100.0/24"},
			},
			ResolvedHosts: []authority.ResolvedHost{
				{Host: "api.github.com", IPv4: []string{"198.51.100.7"}},
			},
		},
	}
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	return ctx
}

func TestAuthorityEnvelopeIncludesBrokerActionTypes(t *testing.T) {
	envelope := AuthorityEnvelopeFromContext(testAuthorityContext(), nil)
	if got, want := envelope.BrokerActionTypes, []string{governance.ActionHTTPRequest}; !slices.Equal(got, want) {
		t.Fatalf("broker action types = %v, want %v", got, want)
	}
}

func TestAuthorityEnvelopeIncludesBrokerRepoLabels(t *testing.T) {
	envelope := AuthorityEnvelopeFromContext(testAuthorityContext(), nil)
	if got, want := envelope.BrokerRepoLabels, []string{"demo"}; !slices.Equal(got, want) {
		t.Fatalf("broker repo labels = %v, want %v", got, want)
	}
}

func TestBuildSignedReceiptIncludesAuthorityEnvelope(t *testing.T) {
	input := testReceiptInput()
	ctx := testAuthorityContext()
	input.Authority = AuthorityEnvelopeFromContext(ctx, &authority.MutationAttempt{
		Field:            "rootfs_image",
		Expected:         "frozen",
		Observed:         "mutated",
		EnforcementPoint: "post_vm_acquisition",
	})

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if signed.Statement.Predicate.Authority == nil {
		t.Fatal("expected authority envelope")
	}
	if signed.Statement.Predicate.Authority.RootfsImage != ctx.Boot.RootfsImage {
		t.Fatalf("RootfsImage = %q, want %q", signed.Statement.Predicate.Authority.RootfsImage, ctx.Boot.RootfsImage)
	}
	if signed.Statement.Predicate.Authority.MutationAttempt == nil || signed.Statement.Predicate.Authority.MutationAttempt.Field != "rootfs_image" {
		t.Fatalf("unexpected mutation attempt: %+v", signed.Statement.Predicate.Authority.MutationAttempt)
	}
}

func TestReceiptPredicateMatchesSchemaWithAuthority(t *testing.T) {
	schema := loadReceiptPredicateSchema(t)
	input := testReceiptInput()
	input.Authority = AuthorityEnvelopeFromContext(testAuthorityContext(), nil)

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	payload, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("Marshal predicate: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("Unmarshal predicate: %v", err)
	}
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("predicate does not match schema with authority: %v\npayload=%s", err, string(payload))
	}
}

func TestVerifySignedReceiptRejectsAuthorityDigestMismatch(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.Authority = AuthorityEnvelopeFromContext(testAuthorityContext(), nil)
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	signed.Statement.Predicate.Authority.Digest = strings.Repeat("a", 64)
	reSignStatement(t, &signed, signer)

	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "authority envelope invalid") {
		t.Fatalf("expected authority digest verification failure, got %v", err)
	}
}

func TestVerifySignedReceiptAcceptsLegacyReceiptWithoutAuthority(t *testing.T) {
	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt: %v", err)
	}
}

func TestVerifySignedReceiptAcceptsLegacyAuthorityWithoutBrokerRepoLabels(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	ctx := testAuthorityContext()
	ctx.BrokerRepoLabels = nil
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	input.Authority = AuthorityEnvelopeFromContext(ctx, nil)
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt: %v", err)
	}
}

func TestVerifySignedReceiptRejectsMalformedBrokerRepoLabels(t *testing.T) {
	signer := mustDevSigner(t)
	input := testReceiptInput()
	input.Authority = AuthorityEnvelopeFromContext(testAuthorityContext(), nil)
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	signed.Statement.Predicate.Authority.BrokerRepoLabels = []string{"Demo", "demo", ""}
	reSignStatement(t, &signed, signer)

	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "broker_repo_labels") {
		t.Fatalf("expected broker_repo_labels verification failure, got %v", err)
	}
}

func TestAuthorityEnvelopeSanitizesRootfsImage(t *testing.T) {
	assetsDir := t.TempDir()
	rootfsPath := filepath.Join(assetsDir, "images", "alpine-base.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	ctx, err := authority.Freeze(authority.FreezeInput{
		ExecutionID:        "exec_123",
		AssetsDir:          assetsDir,
		RootfsPath:         rootfsPath,
		WorkspaceRequested: true,
		Network:            policycfg.NetworkPolicy{Mode: policycfg.NetworkModeNone},
		PolicyDigest:       PolicyDigest(testReceiptInput().Policy),
	})
	if err != nil {
		t.Fatalf("authority.Freeze: %v", err)
	}
	envelope := AuthorityEnvelopeFromContext(ctx, nil)
	if envelope.RootfsImage == rootfsPath || strings.Contains(envelope.RootfsImage, assetsDir) {
		t.Fatalf("rootfs_image leaked host path: %q", envelope.RootfsImage)
	}
	if !strings.HasPrefix(envelope.RootfsImage, "alpine-base.ext4#") {
		t.Fatalf("unexpected sanitized rootfs_image: %q", envelope.RootfsImage)
	}
}

func TestAuthorityEnvelopeMountJSONDoesNotExposeHostSources(t *testing.T) {
	assetsDir := t.TempDir()
	rootfsPath := filepath.Join(assetsDir, "vm", "alpine-base.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	ctx, err := authority.Freeze(authority.FreezeInput{
		ExecutionID:        "exec_123",
		AssetsDir:          assetsDir,
		RootfsPath:         rootfsPath,
		WorkspaceRequested: true,
		Network:            policycfg.NetworkPolicy{Mode: policycfg.NetworkModeNone},
		PolicyDigest:       PolicyDigest(testReceiptInput().Policy),
	})
	if err != nil {
		t.Fatalf("authority.Freeze: %v", err)
	}
	raw, err := json.Marshal(AuthorityEnvelopeFromContext(ctx, nil))
	if err != nil {
		t.Fatalf("Marshal authority envelope: %v", err)
	}
	if strings.Contains(string(raw), rootfsPath) || strings.Contains(string(raw), assetsDir) {
		t.Fatalf("authority envelope leaked host path: %s", string(raw))
	}
	if strings.Contains(string(raw), `"source"`) {
		t.Fatalf("authority envelope should not expose mount source fields: %s", string(raw))
	}
}

func TestSignedAuthorityReceiptJSONDoesNotLeakHostPaths(t *testing.T) {
	assetsDir := t.TempDir()
	rootfsPath := filepath.Join(assetsDir, "nested", "alpine-base.ext4")
	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	ctx, err := authority.Freeze(authority.FreezeInput{
		ExecutionID:        "exec_123",
		AssetsDir:          assetsDir,
		RootfsPath:         rootfsPath,
		WorkspaceRequested: true,
		Network:            policycfg.NetworkPolicy{Mode: policycfg.NetworkModeNone},
		PolicyDigest:       PolicyDigest(testReceiptInput().Policy),
	})
	if err != nil {
		t.Fatalf("authority.Freeze: %v", err)
	}
	input := testReceiptInput()
	input.Authority = AuthorityEnvelopeFromContext(ctx, nil)
	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal signed receipt: %v", err)
	}
	if strings.Contains(string(raw), rootfsPath) || strings.Contains(string(raw), assetsDir) {
		t.Fatalf("signed receipt leaked host path: %s", string(raw))
	}
}

func TestAuthorityReceiptSummaryIncludesRepoLabelsOnly(t *testing.T) {
	input := testReceiptInput()
	ctx := testAuthorityContext()
	ctx.BrokerRepoLabels = []string{"demo", "alpha"}
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	input.Authority = AuthorityEnvelopeFromContext(ctx, nil)

	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	summary := FormatSummary(signed.Statement, true)
	if !strings.Contains(summary, "broker_repo_labels=alpha,demo") {
		t.Fatalf("summary missing broker repo labels: %s", summary)
	}
	if strings.Contains(summary, "/tmp/") {
		t.Fatalf("summary leaked host path: %s", summary)
	}
}

func TestAuthorityMutationReceiptSummaryPreservesExactReason(t *testing.T) {
	input := testReceiptInput()
	ctx := testAuthorityContext()
	input.Authority = AuthorityEnvelopeFromContext(ctx, &authority.MutationAttempt{
		Field:            "rootfs_image",
		Expected:         ctx.Boot.RootfsImage,
		Observed:         "mutated#deadbeef",
		EnforcementPoint: "post_vm_acquisition",
	})
	input.ExecutionStatus = "sandbox_error"
	input.Outcome = Outcome{
		ExitCode:           137,
		Reason:             "security_denied_authority_mutation",
		ContainmentVerdict: "contained",
	}
	input.OutputArtifacts = ArtifactsFromBundleOutputs(input.ExecutionID, "", "", false)

	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	paths, err := WriteProofBundle(t.TempDir(), input.ExecutionID, signed, signer.PublicKey, "", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	report, err := VerifyBundleReport(paths)
	if err != nil {
		t.Fatalf("VerifyBundleReport: %v", err)
	}
	if got := report.Statement.Predicate.Outcome.Reason; got != "security_denied_authority_mutation" {
		t.Fatalf("outcome reason = %q", got)
	}
	summaryBytes, err := os.ReadFile(paths.SummaryPath)
	if err != nil {
		t.Fatalf("ReadFile(summary): %v", err)
	}
	if !strings.Contains(string(summaryBytes), "outcome=security_denied_authority_mutation") {
		t.Fatalf("summary missing exact mutation reason: %s", string(summaryBytes))
	}
}

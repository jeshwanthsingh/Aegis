package receipt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/telemetry"
)

func hostPatchReceiptInput(t *testing.T, check *approval.Check, evidence *hostaction.Evidence, used bool, outcome string, errText string) Input {
	t.Helper()
	input := testReceiptInput()
	input.TelemetryEvents = input.TelemetryEvents[:1]
	input.ExecutionStatus = "completed"
	input.Outcome = Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"}
	input.Runtime.Network.BlockedEgress = nil
	ctx := testAuthorityContext()
	ctx.BrokerActionTypes = []string{governance.ActionHostRepoApply}
	ctx.ApprovalMode = authority.ApprovalModeNone
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	input.Authority = AuthorityEnvelopeFromContext(ctx, nil)

	resource, err := approval.CanonicalizeResource(approval.Resource{
		Kind: approval.ResourceKindHostRepoApplyPatchV1,
		HostRepoApplyPatch: &approval.HostRepoApplyPatchResource{
			RepoLabel:       "demo",
			TargetScope:     []string{"README.md"},
			AffectedPaths:   []string{"README.md"},
			PatchDigest:     strings.Repeat("a", 64),
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	})
	if err != nil {
		t.Fatalf("CanonicalizeResource: %v", err)
	}
	if check != nil {
		check.ResourceDigest = resourceDigestForTest(t, resource)
		check.ResourceDigestAlgo = approval.ResourceDigestAlgo
	}
	governedAction, err := json.Marshal(telemetry.GovernedActionData{
		ExecutionID:         input.ExecutionID,
		ActionType:          governance.ActionHostRepoApply,
		Target:              "repo:demo",
		Resource:            "demo",
		CapabilityPath:      "broker",
		Decision:            "allow",
		Outcome:             outcome,
		Reason:              "governed action allowed by broker scope",
		RuleID:              "governance.allow",
		PolicyDigest:        PolicyDigest(input.Policy),
		Brokered:            true,
		BrokeredCredentials: false,
		Lease: &lease.Check{
			Required:           true,
			LeaseID:            "lease-host-1",
			Issuer:             "local_orchestrator",
			IssuerKeyID:        "ed25519:test",
			Result:             lease.CheckVerified,
			ExpiresAt:          time.Unix(1700000010, 0).UTC(),
			GrantID:            "grant-host-1",
			SelectorDigest:     strings.Repeat("b", 64),
			SelectorDigestAlgo: approval.ResourceDigestAlgo,
			BudgetResult:       lease.BudgetConsumed,
			RemainingCount:     ptrUint64(0),
		},
		Approval:   check,
		HostAction: evidence,
		Error:      errText,
		Used:       used,
	})
	if err != nil {
		t.Fatalf("Marshal(governed action): %v", err)
	}
	input.TelemetryEvents = append(input.TelemetryEvents, telemetry.Event{
		ExecID:    input.ExecutionID,
		Timestamp: input.FinishedAt.UnixMilli(),
		Kind:      telemetry.KindGovernedAction,
		Data:      governedAction,
	})
	return input
}

func resourceDigestForTest(t *testing.T, resource approval.Resource) string {
	t.Helper()
	digest, _, err := approval.DigestResource(resource)
	if err != nil {
		t.Fatalf("DigestResource: %v", err)
	}
	return digest
}

func validHostActionEvidence() *hostaction.Evidence {
	return &hostaction.Evidence{
		Class: hostaction.ClassRepoApplyPatchV1,
		RepoApplyPatch: &hostaction.RepoApplyPatchEvidence{
			RepoLabel:       "demo",
			TargetScope:     []string{"README.md"},
			AffectedPaths:   []string{"README.md"},
			PatchDigest:     strings.Repeat("a", 64),
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	}
}

func TestBuildSignedReceiptCarriesHostActionEvidence(t *testing.T) {
	repoRoot := t.TempDir()
	input := hostPatchReceiptInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-host-1",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		Reason:      "operator_approved",
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	}, validHostActionEvidence(), true, "completed", "")
	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if signed.Statement.Predicate.Authority == nil || len(signed.Statement.Predicate.Authority.BrokerActionTypes) != 1 {
		t.Fatalf("authority = %+v", signed.Statement.Predicate.Authority)
	}
	action := signed.Statement.Predicate.GovernedActions.Actions[0]
	if action.HostAction == nil || action.HostAction.RepoApplyPatch == nil {
		t.Fatalf("host action evidence = %+v", action.HostAction)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal(signed): %v", err)
	}
	if strings.Contains(string(raw), repoRoot) {
		t.Fatalf("signed receipt leaked repo root: %s", string(raw))
	}
	summary := FormatSummary(signed.Statement, true)
	for _, needle := range []string{
		"repo_label=demo",
		"patch_digest=sha256:" + strings.Repeat("a", 64),
		"affected_paths=README.md",
		"approval_result=verified",
		"approval_ticket_id=ticket-host-1",
		"approval_reason=operator_approved",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q:\n%s", needle, summary)
		}
	}
	var doc any
	if err := json.Unmarshal(mustJSON(t, signed.Statement.Predicate), &doc); err != nil {
		t.Fatalf("Unmarshal(predicate): %v", err)
	}
	schema := loadReceiptPredicateSchema(t)
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("predicate does not match schema with host action evidence: %v", err)
	}
}

func TestVerifySignedReceiptRejectsUsedHostRepoApplyWithoutHostAction(t *testing.T) {
	signer := mustDevSigner(t)
	input := hostPatchReceiptInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-host-2",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	}, nil, true, "completed", "")
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "require host_action evidence") {
		t.Fatalf("expected host action verification failure, got %v", err)
	}
}

func TestVerifySignedReceiptRejectsMalformedHostActionEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	evidence := validHostActionEvidence()
	evidence.RepoApplyPatch.AffectedPaths = []string{"/tmp/evil.txt"}
	input := hostPatchReceiptInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-host-3",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	}, evidence, true, "completed", "")
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "affected_paths must contain relative slash-separated paths") {
		t.Fatalf("expected malformed host action verification failure, got %v", err)
	}
}

func TestVerifySignedReceiptAcceptsHostRepoApplyErrorAfterConsume(t *testing.T) {
	signer := mustDevSigner(t)
	input := hostPatchReceiptInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-host-4",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	}, validHostActionEvidence(), false, "error", "apply patch: failed")
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt: %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

func TestHostActionReceiptDoesNotLeakRepoPathViaProofSummary(t *testing.T) {
	repoRoot := t.TempDir()
	signer := mustDevSigner(t)
	input := hostPatchReceiptInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-host-5",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		Reason:      "operator_approved",
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	}, validHostActionEvidence(), true, "completed", "")
	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("Marshal(signed): %v", err)
	}
	if strings.Contains(string(raw), repoRoot) || strings.Contains(base64.StdEncoding.EncodeToString(raw), repoRoot) {
		t.Fatalf("signed receipt leaked repo root: %s", string(raw))
	}
}

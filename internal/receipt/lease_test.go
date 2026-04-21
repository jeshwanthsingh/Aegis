package receipt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/lease"
	"aegis/internal/telemetry"
)

func brokerLeaseInput(t *testing.T, leaseCheck *lease.Check, approvalCheck *approval.Check) Input {
	t.Helper()
	input := testReceiptInput()
	input.TelemetryEvents = input.TelemetryEvents[:1]
	input.ExecutionStatus = "completed"
	input.Outcome = Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"}
	input.Runtime.Network.BlockedEgress = nil
	ctx := testAuthorityContext()
	ctx.ApprovalMode = authority.ApprovalModeRequireHostConsent
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	input.Authority = AuthorityEnvelopeFromContext(ctx, nil)
	policyDigest := PolicyDigest(input.Policy)
	resource, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method: "GET",
		URL:    "https://api.github.com/repos/openai/aegis",
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	if approvalCheck != nil {
		approvalCheck.ResourceDigest = resource.ResourceDigest
		approvalCheck.ResourceDigestAlgo = resource.ResourceDigestAlgo
	}
	governedAction, err := json.Marshal(telemetry.GovernedActionData{
		ExecutionID:         input.ExecutionID,
		ActionType:          "http_request",
		Target:              "https://api.github.com/repos/openai/aegis",
		Resource:            "api.github.com",
		Method:              "GET",
		CapabilityPath:      "broker",
		Decision:            "allow",
		Outcome:             "completed",
		Reason:              "governed action allowed by broker scope",
		RuleID:              "governance.allow",
		PolicyDigest:        policyDigest,
		Brokered:            true,
		BrokeredCredentials: true,
		ResponseDigest:      strings.Repeat("a", 64),
		ResponseDigestAlgo:  "sha256",
		Lease:               leaseCheck,
		Approval:            approvalCheck,
		Used:                true,
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

func TestBuildSignedReceiptCarriesLeaseEvidence(t *testing.T) {
	input := brokerLeaseInput(t, &lease.Check{
		Required:           true,
		LeaseID:            "lease-1",
		Issuer:             "local_orchestrator",
		IssuerKeyID:        "ed25519:test",
		Result:             lease.CheckVerified,
		ExpiresAt:          time.Unix(1700000010, 0).UTC(),
		GrantID:            "grant-http-1",
		SelectorDigest:     strings.Repeat("b", 64),
		SelectorDigestAlgo: approval.ResourceDigestAlgo,
		BudgetResult:       lease.BudgetConsumed,
		RemainingCount:     ptrUint64(4),
	}, &approval.Check{
		Required:    true,
		TicketID:    "ticket-1",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	})

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	action := signed.Statement.Predicate.GovernedActions.Actions[0]
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified {
		t.Fatalf("lease = %+v", action.Lease)
	}
	summary := FormatSummary(signed.Statement, true)
	for _, needle := range []string{
		"lease_id=lease-1",
		"lease_result=verified",
		"lease_budget_result=consumed",
		"lease_remaining_count=4",
		"lease_grant_id=grant-http-1",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q:\n%s", needle, summary)
		}
	}
}

func TestVerifySignedReceiptAcceptsLegacyReceiptWithoutLeaseEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt(legacy-compatible): %v", err)
	}
}

func TestVerifySignedReceiptRejectsContradictoryLeaseEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	input := brokerLeaseInput(t, &lease.Check{
		Required:           true,
		LeaseID:            "lease-2",
		Issuer:             "local_orchestrator",
		IssuerKeyID:        "ed25519:test",
		Result:             lease.CheckVerified,
		ExpiresAt:          time.Unix(1700000010, 0).UTC(),
		GrantID:            "grant-http-2",
		SelectorDigest:     strings.Repeat("c", 64),
		SelectorDigestAlgo: approval.ResourceDigestAlgo,
		BudgetResult:       lease.BudgetConsumed,
	}, &approval.Check{
		Required:    true,
		TicketID:    "ticket-2",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
		Consumed:    true,
	})

	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "lease remaining_count is required when budget_result=consumed") {
		t.Fatalf("expected contradictory lease verification failure, got %v", err)
	}
}

func ptrUint64(value uint64) *uint64 {
	return &value
}

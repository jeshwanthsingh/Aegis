package receipt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/telemetry"
)

func brokerApprovalInput(t *testing.T, check *approval.Check) Input {
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
		Method:  "GET",
		URL:     "https://api.github.com/repos/openai/aegis",
		Headers: map[string][]string{"Accept": {"application/json"}},
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	if check != nil {
		check.ResourceDigest = resource.ResourceDigest
		check.ResourceDigestAlgo = resource.ResourceDigestAlgo
	}
	credentialAllowed, _ := json.Marshal(telemetry.CredentialBrokerData{
		ExecutionID:  input.ExecutionID,
		BindingName:  "github",
		TargetDomain: "api.github.com",
		Method:       "GET",
		ActionType:   "http_request",
		Outcome:      "allowed",
	})
	governedAction, _ := json.Marshal(telemetry.GovernedActionData{
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
		BindingName:         "github",
		ResponseDigest:      strings.Repeat("a", 64),
		ResponseDigestAlgo:  "sha256",
		Lease:               validHTTPLeaseCheck(),
		Approval:            check,
		Used:                true,
	})
	input.TelemetryEvents = append(input.TelemetryEvents, telemetry.Event{
		ExecID:    input.ExecutionID,
		Timestamp: input.FinishedAt.UnixMilli(),
		Kind:      telemetry.KindCredentialAllowed,
		Data:      credentialAllowed,
	}, telemetry.Event{
		ExecID:    input.ExecutionID,
		Timestamp: input.FinishedAt.UnixMilli(),
		Kind:      telemetry.KindGovernedAction,
		Data:      governedAction,
	})
	return input
}

func TestBuildSignedReceiptCarriesApprovalFields(t *testing.T) {
	input := brokerApprovalInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-1",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
	})

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if signed.Statement.Predicate.GovernedActions == nil || len(signed.Statement.Predicate.GovernedActions.Actions) != 1 {
		t.Fatalf("governed actions = %+v", signed.Statement.Predicate.GovernedActions)
	}
	action := signed.Statement.Predicate.GovernedActions.Actions[0]
	if action.Approval == nil || action.Approval.Result != approval.VerificationVerified {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Approval.ResourceDigest == "" || action.Approval.ResourceDigestAlgo != "sha256" {
		t.Fatalf("approval resource digest = %+v", action.Approval)
	}
	payload, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("json.Marshal(predicate): %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("json.Unmarshal(predicate): %v", err)
	}
	schema := loadReceiptPredicateSchema(t)
	if err := validateSchemaValue(doc, schema, schema, "$"); err != nil {
		t.Fatalf("predicate does not match schema with approval evidence: %v\npayload=%s", err, string(payload))
	}
	summary := FormatSummary(signed.Statement, true)
	for _, needle := range []string{
		"approval_result=verified",
		"approval_ticket_id=ticket-1",
		"resource_digest=sha256:",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q:\n%s", needle, summary)
		}
	}
}

func TestVerifySignedReceiptRejectsHostConsentReceiptWithoutVerifiedApproval(t *testing.T) {
	signer := mustDevSigner(t)
	input := brokerApprovalInput(t, nil)

	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), "requires approval evidence") {
		t.Fatalf("expected approval verification failure, got %v", err)
	}
}

func TestVerifySignedReceiptAcceptsHostConsentReceiptWithVerifiedApproval(t *testing.T) {
	signer := mustDevSigner(t)
	input := brokerApprovalInput(t, &approval.Check{
		Required:    true,
		TicketID:    "ticket-verified",
		IssuerKeyID: "ed25519:test",
		Result:      approval.VerificationVerified,
		ExpiresAt:   time.Unix(1700000010, 0).UTC(),
	})

	signed, err := BuildSignedReceipt(input, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt: %v", err)
	}
}

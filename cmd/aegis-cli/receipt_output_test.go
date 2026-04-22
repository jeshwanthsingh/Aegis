package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/escalation"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/receipt"
	"aegis/internal/telemetry"
)

func TestReceiptShowCommandIncludesAuthorityAndRuntimePolicySections(t *testing.T) {
	signer := mustTestSigner(t)
	remaining := uint64(3)
	allowAction, err := json.Marshal(telemetry.GovernedActionData{
		ExecutionID: "exec_review",
		ActionType:  "host_repo_apply_patch",
		Decision:    "allow",
		Target:      "repo:demo",
		Resource:    "demo",
		Used:        true,
		Brokered:    true,
		HostAction: &hostaction.Evidence{
			Class: hostaction.ClassRepoApplyPatchV1,
			RepoApplyPatch: &hostaction.RepoApplyPatchEvidence{
				RepoLabel:       "demo",
				AffectedPaths:   []string{"demo.txt"},
				PatchDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				PatchDigestAlgo: "sha256",
				BaseRevision:    "HEAD",
			},
		},
		Approval: &approval.Check{
			Required:           true,
			Result:             approval.VerificationVerified,
			TicketID:           "ticket-1",
			IssuerKeyID:        "ed25519:test-approval",
			ResourceDigest:     "abcd",
			ResourceDigestAlgo: "sha256",
			Consumed:           true,
		},
		Lease: &lease.Check{
			Required:           true,
			Result:             lease.CheckVerified,
			LeaseID:            "lease-1",
			Issuer:             "local_orchestrator",
			IssuerKeyID:        "ed25519:test-lease",
			GrantID:            "grant-1",
			SelectorDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			SelectorDigestAlgo: "sha256",
			BudgetResult:       lease.BudgetConsumed,
			RemainingCount:     &remaining,
		},
	})
	if err != nil {
		t.Fatalf("Marshal(allow action): %v", err)
	}
	denyAction, err := json.Marshal(telemetry.GovernedActionData{
		ExecutionID:    "exec_review",
		ActionType:     "http_request",
		Decision:       "deny",
		CapabilityPath: "broker",
		Target:         "https://example.com",
		Resource:       "https://example.com",
		Escalation: &escalation.Evidence{
			Signals: []escalation.Signal{escalation.SignalRepeatedProbingPattern},
		},
	})
	if err != nil {
		t.Fatalf("Marshal(deny action): %v", err)
	}
	receiptInput := receipt.Input{
		ExecutionID: "exec_review",
		Backend:     "firecracker",
		StartedAt:   testTime(),
		FinishedAt:  testTime().Add(2 * time.Second),
		Authority: receipt.AuthorityEnvelopeFromContext(authority.Context{
			ExecutionID:       "exec_review",
			ApprovalMode:      authority.ApprovalModeRequireHostConsent,
			BrokerRepoLabels:  []string{"demo"},
			BrokerActionTypes: []string{"host_repo_apply_patch", "http_request"},
			Boot: authority.BootContext{
				RootfsImage: "alpine-base.ext4",
				NetworkMode: "none",
			},
		}, nil),
		Runtime: &receipt.RuntimeEnvelope{
			Policy: &escalation.RuntimePolicyEnvelope{
				EscalationAttempts: &escalation.Summary{
					Count: 1,
					Sample: []escalation.Sample{{
						Count:      1,
						Source:     escalation.SourceGovernedAction,
						Signals:    []escalation.Signal{escalation.SignalRepeatedProbingPattern},
						RuleID:     "broker.domain_denied",
						ActionType: "http_request",
						Target:     "https://example.com",
					}},
				},
				TerminationReason: escalation.TerminationReasonPrivilegeEscalation,
			},
		},
		TelemetryEvents: []telemetry.Event{
			{Kind: telemetry.KindGovernedAction, Data: allowAction},
			{Kind: telemetry.KindGovernedAction, Data: denyAction},
		},
		Outcome: receipt.Outcome{ExitCode: 137, Reason: escalation.TerminationReasonPrivilegeEscalation, ContainmentVerdict: "contained"},
	}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "ok\n", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	root := t.TempDir()
	t.Setenv("AEGIS_PROOF_ROOT", root)
	_, err = receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "ok\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptShow(&stdout, &stderr, []string{"--execution-id", receiptInput.ExecutionID})
	if code != 0 {
		t.Fatalf("receiptShow exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	for _, needle := range []string{
		"[authority]",
		"authority_digest=" + receiptInput.Authority.Digest,
		"broker_action_types=host_repo_apply_patch,http_request",
		"broker_repo_labels=demo",
		"[runtime_policy]",
		"escalation_count=1",
		"termination_reason=privilege_escalation_attempt",
	} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q:\n%s", needle, stdout.String())
		}
	}
}

func TestReceiptShowCommandSanitizesHTTPQueryStrings(t *testing.T) {
	signer := mustTestSigner(t)
	resource, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method: "GET",
		URL:    "https://api.example.com/v1/data?token=super-secret&sig=abc123",
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	action, err := json.Marshal(telemetry.GovernedActionData{
		ExecutionID:  "exec_http_review",
		ActionType:   "http_request",
		Decision:     "allow",
		Outcome:      "completed",
		Target:       "https://api.example.com/v1/data",
		Resource:     "api.example.com",
		Method:       "GET",
		Brokered:     true,
		Used:         true,
		AuditPayload: approval.ResourceToAuditPayload(resource.Resource),
		Lease: &lease.Check{
			Required:           true,
			Result:             lease.CheckVerified,
			LeaseID:            "lease-http-1",
			Issuer:             "local_orchestrator",
			IssuerKeyID:        "ed25519:test-lease",
			GrantID:            "grant-http-1",
			SelectorDigest:     strings.Repeat("b", 64),
			SelectorDigestAlgo: "sha256",
			BudgetResult:       lease.BudgetConsumed,
			RemainingCount:     ptrUint64(4),
		},
	})
	if err != nil {
		t.Fatalf("Marshal(action): %v", err)
	}
	receiptInput := receipt.Input{
		ExecutionID: "exec_http_review",
		Backend:     "firecracker",
		StartedAt:   testTime(),
		FinishedAt:  testTime().Add(2 * time.Second),
		TelemetryEvents: []telemetry.Event{
			{Kind: telemetry.KindGovernedAction, Data: action},
		},
		Outcome: receipt.Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"},
	}
	receiptInput.OutputArtifacts = receipt.ArtifactsFromBundleOutputs(receiptInput.ExecutionID, "ok\n", "", false)
	signed, err := receipt.BuildSignedReceipt(receiptInput, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	rawReceipt, err := json.Marshal(signed.Statement.Predicate)
	if err != nil {
		t.Fatalf("Marshal(predicate): %v", err)
	}
	for _, value := range []string{"super-secret", "abc123", "token=", "sig="} {
		if strings.Contains(string(rawReceipt), value) {
			t.Fatalf("signed receipt leaked query data %q: %s", value, string(rawReceipt))
		}
	}
	root := t.TempDir()
	t.Setenv("AEGIS_PROOF_ROOT", root)
	paths, err := receipt.WriteProofBundle(root, receiptInput.ExecutionID, signed, signer.PublicKey, "ok\n", "", false)
	if err != nil {
		t.Fatalf("WriteProofBundle: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := receiptShow(&stdout, &stderr, []string{"--proof-dir", paths.ProofDir})
	if code != 0 {
		t.Fatalf("receiptShow exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "resource_url_query_key_count=2") {
		t.Fatalf("stdout missing sanitized query count:\n%s", stdout.String())
	}
	for _, value := range []string{"super-secret", "abc123", "token=", "sig="} {
		if strings.Contains(stdout.String(), value) {
			t.Fatalf("receipt show leaked query data %q:\n%s", value, stdout.String())
		}
	}
}

func ptrUint64(value uint64) *uint64 {
	return &value
}

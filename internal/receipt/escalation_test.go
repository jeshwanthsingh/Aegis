package receipt

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"aegis/internal/authority"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/telemetry"
)

func escalationInput(t *testing.T, action telemetry.GovernedActionData) Input {
	t.Helper()
	input := testReceiptInput()
	input.TelemetryEvents = input.TelemetryEvents[:1]
	raw, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("Marshal(governed action): %v", err)
	}
	input.TelemetryEvents = append(input.TelemetryEvents, telemetry.Event{
		ExecID:    input.ExecutionID,
		Timestamp: input.FinishedAt.UnixMilli(),
		Kind:      telemetry.KindGovernedAction,
		Data:      raw,
	})
	return input
}

func resignTestReceipt(t *testing.T, signer *Signer, signed *SignedReceipt) {
	t.Helper()
	payload, err := json.Marshal(signed.Statement)
	if err != nil {
		t.Fatalf("Marshal(statement): %v", err)
	}
	envelope, err := dsse.SignEnvelope(PayloadType, payload, signer.PrivateKey)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	signed.Envelope = envelope
}

func TestBuildSignedReceiptCarriesAuthorityMutationEscalationSummary(t *testing.T) {
	input := testReceiptInput()
	input.TelemetryEvents = input.TelemetryEvents[:1]
	input.ExecutionStatus = "contained"
	input.Outcome = Outcome{ExitCode: 137, Reason: "security_denied_authority_mutation", ContainmentVerdict: "contained"}
	input.Authority = AuthorityEnvelopeFromContext(testAuthorityContext(), &authority.MutationAttempt{
		Field:            "rootfs_image",
		Expected:         "aegis-rootfs:test",
		Observed:         "mutated-rootfs:test",
		EnforcementPoint: "post_vm_acquisition",
	})

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	policy := signed.Statement.Predicate.Runtime.Policy
	if policy == nil || policy.EscalationAttempts == nil {
		t.Fatalf("runtime.policy = %+v", policy)
	}
	if policy.TerminationReason != "security_denied_authority_mutation" {
		t.Fatalf("termination_reason = %q", policy.TerminationReason)
	}
	sample := policy.EscalationAttempts.Sample[0]
	if sample.Source != escalation.SourceAuthorityMutation || sample.MutationField != "rootfs_image" || sample.EnforcementPoint != "post_vm_acquisition" {
		t.Fatalf("sample = %+v", sample)
	}
	if len(sample.Signals) != 1 || sample.Signals[0] != escalation.SignalAuthorityBroadeningAttempt {
		t.Fatalf("signals = %v", sample.Signals)
	}
}

func TestBuildSignedReceiptCarriesGovernedEscalationSummaryAndSummaryOutput(t *testing.T) {
	input := escalationInput(t, telemetry.GovernedActionData{
		ExecutionID:    "exec_123",
		ActionType:     "host_repo_apply_patch",
		Target:         "repo:demo",
		Resource:       "demo",
		CapabilityPath: "broker",
		Decision:       "deny",
		Outcome:        "denied",
		Reason:         "host action class \"host_file_delete_v1\" is not supported",
		RuleID:         "broker.host_action_unsupported",
		PolicyDigest:   PolicyDigest(testReceiptInput().Policy),
		Brokered:       true,
		AuditPayload: map[string]string{
			"host_action_class": "host_file_delete_v1",
			"repo_root":         "/home/cellardoor72/demo",
		},
		Escalation: &escalation.Evidence{
			Signals: []escalation.Signal{escalation.SignalUnsupportedDestructiveClassAccess},
		},
	})
	input.ExecutionStatus = "contained"
	input.Outcome = Outcome{ExitCode: 137, Reason: escalation.TerminationReasonPrivilegeEscalation, ContainmentVerdict: "contained"}

	signed, err := BuildSignedReceipt(input, mustDevSigner(t))
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	policy := signed.Statement.Predicate.Runtime.Policy
	if policy == nil || policy.EscalationAttempts == nil {
		t.Fatalf("runtime.policy = %+v", policy)
	}
	if got, want := policy.DeniedDestructiveActions, []escalation.DestructiveActionClass{escalation.DestructiveActionHostFileDelete}; !reflect.DeepEqual(got, want) {
		t.Fatalf("denied_destructive_actions = %v, want %v", got, want)
	}
	if policy.TerminationReason != escalation.TerminationReasonPrivilegeEscalation {
		t.Fatalf("termination_reason = %q", policy.TerminationReason)
	}
	summary := FormatSummary(signed.Statement, true)
	for _, needle := range []string{
		"runtime_policy_escalation_count=1",
		"runtime_policy_escalation_sample_count=1",
		"runtime_policy_denied_destructive_actions=host_file_delete",
		"runtime_policy_termination_reason=privilege_escalation_attempt",
		"runtime_policy_escalation_sample_1=source=governed_action",
	} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q:\n%s", needle, summary)
		}
	}
	if strings.Contains(summary, "/home/cellardoor72/demo") {
		t.Fatalf("summary leaked repo root:\n%s", summary)
	}
}

func TestVerifySignedReceiptAcceptsLegacyReceiptWithoutEscalationEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	signed, err := BuildSignedReceipt(testReceiptInput(), signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if _, err := VerifySignedReceipt(signed, signer.PublicKey); err != nil {
		t.Fatalf("VerifySignedReceipt(legacy no escalation): %v", err)
	}
}

func TestVerifySignedReceiptRejectsContradictoryEscalationEvidence(t *testing.T) {
	signer := mustDevSigner(t)
	tests := []struct {
		name     string
		mutate   func(*SignedReceipt)
		contains string
	}{
		{
			name: "count without sample",
			mutate: func(signed *SignedReceipt) {
				signed.Statement.Predicate.Runtime.Policy = &escalation.RuntimePolicyEnvelope{
					EscalationAttempts: &escalation.Summary{Count: 1},
				}
			},
			contains: "sample is required when count>0",
		},
		{
			name: "allowed action escalation",
			mutate: func(signed *SignedReceipt) {
				input := escalationInput(t, telemetry.GovernedActionData{
					ExecutionID:    "exec_123",
					ActionType:     "http_request",
					Target:         "https://api.example.com/v1",
					Resource:       "api.example.com",
					Method:         "GET",
					CapabilityPath: "broker",
					Decision:       "allow",
					Outcome:        "completed",
					Reason:         "allowed",
					RuleID:         "governance.allow",
					PolicyDigest:   PolicyDigest(testReceiptInput().Policy),
					Brokered:       true,
					Used:           true,
					Escalation: &escalation.Evidence{
						Signals: []escalation.Signal{escalation.SignalAuthorityBroadeningAttempt},
					},
				})
				built, err := BuildSignedReceipt(input, signer)
				if err != nil {
					t.Fatalf("BuildSignedReceipt: %v", err)
				}
				*signed = built
			},
			contains: "escalation evidence is only valid on denied governed actions",
		},
		{
			name: "termination without evidence",
			mutate: func(signed *SignedReceipt) {
				input := testReceiptInput()
				input.ExecutionStatus = "contained"
				input.Outcome = Outcome{ExitCode: 137, Reason: escalation.TerminationReasonPrivilegeEscalation, ContainmentVerdict: "contained"}
				built, err := BuildSignedReceipt(input, signer)
				if err != nil {
					t.Fatalf("BuildSignedReceipt: %v", err)
				}
				built.Statement.Predicate.Runtime = &RuntimeEnvelope{
					Policy: &escalation.RuntimePolicyEnvelope{
						EscalationAttempts: &escalation.Summary{
							Count:  1,
							Sample: []escalation.Sample{{Count: 1, Source: escalation.SourceGovernedAction, Signals: []escalation.Signal{escalation.SignalDestructiveBoundaryProbe}, RuleID: "broker.host_action_path_escape", ActionType: "host_repo_apply_patch", CapabilityPath: "broker", Target: "repo:demo", Resource: "demo", HostActionClass: "host_repo_apply_patch"}},
						},
						TerminationReason: escalation.TerminationReasonPrivilegeEscalation,
					},
				}
				*signed = built
			},
			contains: "requires underlying governed-action escalation evidence",
		},
		{
			name: "malformed authority mutation sample",
			mutate: func(signed *SignedReceipt) {
				input := testReceiptInput()
				input.TelemetryEvents = input.TelemetryEvents[:1]
				input.ExecutionStatus = "contained"
				input.Outcome = Outcome{ExitCode: 137, Reason: "security_denied_authority_mutation", ContainmentVerdict: "contained"}
				input.Authority = AuthorityEnvelopeFromContext(testAuthorityContext(), &authority.MutationAttempt{
					Field:            "rootfs_image",
					Expected:         "aegis-rootfs:test",
					Observed:         "mutated-rootfs:test",
					EnforcementPoint: "post_vm_acquisition",
				})
				built, err := BuildSignedReceipt(input, signer)
				if err != nil {
					t.Fatalf("BuildSignedReceipt: %v", err)
				}
				built.Statement.Predicate.Runtime.Policy.EscalationAttempts.Sample[0].MutationField = ""
				*signed = built
			},
			contains: "authority_mutation samples require mutation_field",
		},
		{
			name: "unknown enum",
			mutate: func(signed *SignedReceipt) {
				input := escalationInput(t, telemetry.GovernedActionData{
					ExecutionID:    "exec_123",
					ActionType:     "host_repo_apply_patch",
					Target:         "repo:demo",
					Resource:       "demo",
					CapabilityPath: "broker",
					Decision:       "deny",
					Outcome:        "denied",
					Reason:         "host action class unsupported",
					RuleID:         "broker.host_action_unsupported",
					PolicyDigest:   PolicyDigest(testReceiptInput().Policy),
					Brokered:       true,
					AuditPayload:   map[string]string{"host_action_class": "host_file_delete_v1"},
					Escalation:     &escalation.Evidence{Signals: []escalation.Signal{"weird"}},
				})
				built, err := BuildSignedReceipt(input, signer)
				if err != nil {
					t.Fatalf("BuildSignedReceipt: %v", err)
				}
				*signed = built
			},
			contains: "unexpected signal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := BuildSignedReceipt(testReceiptInput(), signer)
			if err != nil {
				t.Fatalf("BuildSignedReceipt: %v", err)
			}
			tc.mutate(&signed)
			resignTestReceipt(t, signer, &signed)
			if _, err := VerifySignedReceipt(signed, signer.PublicKey); err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("VerifySignedReceipt error = %v, want substring %q", err, tc.contains)
			}
		})
	}
}

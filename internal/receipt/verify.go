package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"

	"aegis/internal/approval"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	policycfg "aegis/internal/policy"
)

type VerificationFailureClass string

const (
	FailureClassSignatureInvalid  VerificationFailureClass = "signature_invalid"
	FailureClassBundleIncomplete  VerificationFailureClass = "bundle_incomplete"
	FailureClassArtifactIntegrity VerificationFailureClass = "artifact_integrity_failed"
	FailureClassSemanticReceipt   VerificationFailureClass = "semantic_receipt_invalid"
)

type VerificationError struct {
	Class   VerificationFailureClass
	Message string
	Cause   error
}

type VerificationReport struct {
	Verified      bool
	FailureClass  VerificationFailureClass
	FailureDetail string
	Statement     Statement
}

func (e *VerificationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return string(e.Class)
}

func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func verificationError(class VerificationFailureClass, format string, args ...any) error {
	return &VerificationError{Class: class, Message: fmt.Sprintf(format, args...)}
}

func verificationErrorWrap(class VerificationFailureClass, err error, format string, args ...any) error {
	return &VerificationError{Class: class, Message: fmt.Sprintf(format, args...), Cause: err}
}

func VerificationFailure(err error) (VerificationFailureClass, bool) {
	var typed *VerificationError
	if typed == nil && err == nil {
		return "", false
	}
	if !errors.As(err, &typed) {
		return "", false
	}
	return typed.Class, true
}

func VerifySignedReceipt(receipt SignedReceipt, publicKey ed25519.PublicKey) (Statement, error) {
	if receipt.Envelope.PayloadType != PayloadType {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "unexpected payload type: %s", receipt.Envelope.PayloadType)
	}
	payload, signature, err := dsse.VerifyEnvelope(receipt.Envelope, publicKey)
	if err != nil {
		return Statement{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "verify dsse envelope: %v", err)
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return Statement{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "decode receipt statement: %v", err)
	}
	if statement.Type != StatementType {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "unexpected statement type: %s", statement.Type)
	}
	if statement.PredicateType != PredicateType {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "unexpected predicate type: %s", statement.PredicateType)
	}
	if statement.Predicate.SignerKeyID == "" {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "statement signer key id is required")
	}
	if statement.Predicate.SignerKeyID != signature.KeyID {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "statement signer key id does not match DSSE key id")
	}
	if statement.Predicate.Trust.SigningMode != SigningModeDev && statement.Predicate.Trust.SigningMode != SigningModeStrict {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "unexpected signing mode: %s", statement.Predicate.Trust.SigningMode)
	}
	if statement.Predicate.Trust.KeySource != KeySourceConfiguredSeed && statement.Predicate.Trust.KeySource != KeySourceDevFallback {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "unexpected key source: %s", statement.Predicate.Trust.KeySource)
	}
	if statement.Predicate.Trust.Attestation == "" {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "statement trust attestation field is required")
	}
	for _, subject := range statement.Subject {
		if subject.Name == "" {
			return Statement{}, verificationError(FailureClassSignatureInvalid, "statement subject name is required")
		}
		if subject.Digest == nil || subject.Digest["sha256"] == "" {
			return Statement{}, verificationError(FailureClassSignatureInvalid, "statement subject sha256 digest is required")
		}
	}
	applyLegacySemantics(&statement)
	if err := validateSemanticReceipt(statement); err != nil {
		return Statement{}, err
	}
	return statement, nil
}

func validateSemanticReceipt(statement Statement) error {
	predicate := statement.Predicate
	switch predicate.SemanticsMode {
	case "", SemanticsModeExplicitV1, SemanticsModeExplicitV2, SemanticsModeLegacyDerived:
	default:
		return verificationError(FailureClassSemanticReceipt, "unexpected semantics mode: %s", predicate.SemanticsMode)
	}
	switch predicate.ResultClass {
	case ResultClassCompleted, ResultClassDenied, ResultClassAbnormal, ResultClassReconciled:
	default:
		return verificationError(FailureClassSemanticReceipt, "unexpected result class: %s", predicate.ResultClass)
	}
	if strings.TrimSpace(predicate.Outcome.Reason) == "" {
		return verificationError(FailureClassSemanticReceipt, "statement outcome reason is required")
	}
	switch predicate.ResultClass {
	case ResultClassDenied:
		if predicate.Denial == nil {
			return verificationError(FailureClassSemanticReceipt, "denied receipts must include denial evidence")
		}
		switch predicate.Denial.Class {
		case DenialClassGovernedAction, DenialClassPolicy:
		default:
			return verificationError(FailureClassSemanticReceipt, "unexpected denial class: %s", predicate.Denial.Class)
		}
		if predicate.Denial.Class == DenialClassGovernedAction && !hasGovernedActionDeny(predicate.GovernedActions) {
			return verificationError(FailureClassSemanticReceipt, "governed-action denial receipts must include a denied governed action")
		}
		if predicate.Denial.Class == DenialClassPolicy && !hasPolicyDenial(predicate) {
			return verificationError(FailureClassSemanticReceipt, "policy denial receipts must include explicit policy-denied terminal evidence")
		}
	default:
		if predicate.Denial != nil {
			return verificationError(FailureClassSemanticReceipt, "only denied receipts may include denial evidence")
		}
	}
	if predicate.ResultClass == ResultClassReconciled {
		if strings.TrimSpace(predicate.ExecutionStatus) != "reconciled" {
			return verificationError(FailureClassSemanticReceipt, "reconciled receipts must use execution_status=reconciled")
		}
		if strings.TrimSpace(predicate.Outcome.Reason) != "recovered_on_boot" {
			return verificationError(FailureClassSemanticReceipt, "reconciled receipts must use outcome reason recovered_on_boot")
		}
	}
	if predicate.ResultClass != ResultClassReconciled && strings.TrimSpace(predicate.ExecutionStatus) == "reconciled" {
		return verificationError(FailureClassSemanticReceipt, "only reconciled receipts may use execution_status=reconciled")
	}
	if predicate.Runtime != nil {
		if err := validateRuntimeEnvelope(predicate.Runtime); err != nil {
			return verificationError(FailureClassSemanticReceipt, "runtime envelope invalid: %v", err)
		}
		if predicate.Runtime.Policy != nil && strings.TrimSpace(predicate.Runtime.Policy.TerminationReason) != "" && strings.TrimSpace(predicate.Runtime.Policy.TerminationReason) != strings.TrimSpace(predicate.Outcome.Reason) {
			return verificationError(FailureClassSemanticReceipt, "runtime policy termination_reason must match outcome reason")
		}
	}
	if predicate.Policy != nil {
		if err := validatePolicyEnvelope(predicate.Policy); err != nil {
			return verificationError(FailureClassSemanticReceipt, "policy envelope invalid: %v", err)
		}
		if strings.TrimSpace(predicate.PolicyDigest) == "" {
			return verificationError(FailureClassSemanticReceipt, "policy_digest is required when policy evidence is present")
		}
	}
	if predicate.Authority != nil {
		if err := validateAuthorityEnvelope(predicate.ExecutionID, predicate.PolicyDigest, predicate.Authority); err != nil {
			return verificationError(FailureClassSemanticReceipt, "authority envelope invalid: %v", err)
		}
	}
	if strings.TrimSpace(predicate.Outcome.Reason) == "security_denied_authority_mutation" {
		if predicate.Authority == nil {
			return verificationError(FailureClassSemanticReceipt, "authority mutation denial receipts must include authority evidence")
		}
		if predicate.Authority.MutationAttempt == nil {
			return verificationError(FailureClassSemanticReceipt, "authority mutation denial receipts must include mutation_attempt")
		}
	}
	if predicate.GovernedActions != nil {
		if predicate.GovernedActions.Count != len(predicate.GovernedActions.Actions) {
			return verificationError(FailureClassSemanticReceipt, "governed action raw count mismatch: count=%d actions=%d", predicate.GovernedActions.Count, len(predicate.GovernedActions.Actions))
		}
		for idx, action := range predicate.GovernedActions.Actions {
			if err := validateGovernedActionRecord(action, predicate.SemanticsMode); err != nil {
				return verificationError(FailureClassSemanticReceipt, "governed action %d invalid: %v", idx+1, err)
			}
		}
		if len(predicate.GovernedActions.Normalized) > 0 {
			total := 0
			lastKey := ""
			for idx, action := range predicate.GovernedActions.Normalized {
				if err := validateNormalizedGovernedAction(action); err != nil {
					return verificationError(FailureClassSemanticReceipt, "normalized governed action %d invalid: %v", idx+1, err)
				}
				if action.Count <= 0 {
					return verificationError(FailureClassSemanticReceipt, "normalized governed action %d has invalid count %d", idx+1, action.Count)
				}
				key := normalizedGovernedActionSortKey(action)
				if idx > 0 && key < lastKey {
					return verificationError(FailureClassSemanticReceipt, "normalized governed actions are not in canonical order")
				}
				lastKey = key
				total += action.Count
			}
			if total != predicate.GovernedActions.Count {
				return verificationError(FailureClassSemanticReceipt, "normalized governed action count mismatch: normalized=%d raw=%d", total, predicate.GovernedActions.Count)
			}
		}
		if predicate.Authority != nil && strings.TrimSpace(predicate.Authority.ApprovalMode) == "require_host_consent" {
			for idx, action := range predicate.GovernedActions.Actions {
				if !action.Brokered || strings.ToLower(strings.TrimSpace(action.Decision)) != "allow" || !action.Used {
					continue
				}
				if action.Approval == nil {
					return verificationError(FailureClassSemanticReceipt, "governed action %d requires approval evidence", idx+1)
				}
				if action.Approval.Result != approval.VerificationVerified {
					return verificationError(FailureClassSemanticReceipt, "governed action %d requires approval.result=verified", idx+1)
				}
				if strings.TrimSpace(action.Approval.TicketID) == "" {
					return verificationError(FailureClassSemanticReceipt, "governed action %d requires approval.ticket_id", idx+1)
				}
			}
		}
	}
	if err := validateRuntimePolicyTermination(predicate); err != nil {
		return verificationError(FailureClassSemanticReceipt, "runtime policy termination invalid: %v", err)
	}
	if strings.TrimSpace(predicate.Outcome.Reason) == escalation.TerminationReasonPrivilegeEscalation {
		if predicate.Runtime == nil || predicate.Runtime.Policy == nil {
			return verificationError(FailureClassSemanticReceipt, "privilege_escalation_attempt receipts must include runtime.policy evidence")
		}
		if strings.TrimSpace(predicate.Runtime.Policy.TerminationReason) != escalation.TerminationReasonPrivilegeEscalation {
			return verificationError(FailureClassSemanticReceipt, "privilege_escalation_attempt receipts must set runtime.policy.termination_reason")
		}
	}
	return nil
}

func validatePolicyEnvelope(policy *PolicyEnvelope) error {
	if policy == nil {
		return nil
	}
	if strings.TrimSpace(policy.Baseline.Language) == "" {
		return fmt.Errorf("baseline language is required")
	}
	if policy.Baseline.CodeSizeBytes < 0 {
		return fmt.Errorf("baseline code_size_bytes must be >= 0")
	}
	if policy.Baseline.MaxCodeBytes <= 0 {
		return fmt.Errorf("baseline max_code_bytes must be > 0")
	}
	if policy.Baseline.CodeSizeBytes > policy.Baseline.MaxCodeBytes {
		return fmt.Errorf("baseline code_size_bytes cannot exceed max_code_bytes")
	}
	if policy.Baseline.TimeoutMs < 0 {
		return fmt.Errorf("baseline timeout_ms must be >= 0")
	}
	if policy.Baseline.MaxTimeoutMs <= 0 {
		return fmt.Errorf("baseline max_timeout_ms must be > 0")
	}
	if policy.Baseline.TimeoutMs > policy.Baseline.MaxTimeoutMs {
		return fmt.Errorf("baseline timeout_ms cannot exceed max_timeout_ms")
	}
	if policy.Baseline.Network != nil {
		switch strings.TrimSpace(policy.Baseline.Network.Mode) {
		case policycfg.NetworkModeNone, policycfg.NetworkModeEgressAllowlist:
		default:
			return fmt.Errorf("unexpected baseline network mode: %s", policy.Baseline.Network.Mode)
		}
		if policy.Baseline.Network.Mode == policycfg.NetworkModeNone && policy.Baseline.Network.Allowlist != nil && (len(policy.Baseline.Network.Allowlist.FQDNs) > 0 || len(policy.Baseline.Network.Allowlist.CIDRs) > 0) {
			return fmt.Errorf("baseline network allowlist requires egress_allowlist mode")
		}
		if err := validateNetworkAllowlistEnvelope(policy.Baseline.Network.Allowlist); err != nil {
			return fmt.Errorf("baseline network allowlist invalid: %w", err)
		}
	}
	if policy.Intent != nil {
		if strings.TrimSpace(policy.Intent.Digest) == "" {
			return fmt.Errorf("intent digest is required when intent policy evidence is present")
		}
		switch policy.Intent.Source {
		case "", PolicyIntentSourceContract, PolicyIntentSourceCompiledCapabilities:
		default:
			return fmt.Errorf("unexpected intent source: %s", policy.Intent.Source)
		}
	}
	return nil
}

func validateAuthorityEnvelope(executionID string, policyDigest string, envelope *AuthorityEnvelope) error {
	if envelope == nil {
		return nil
	}
	if strings.TrimSpace(envelope.Digest) == "" {
		return fmt.Errorf("digest is required")
	}
	if strings.TrimSpace(envelope.RootfsImage) == "" {
		return fmt.Errorf("rootfs_image is required")
	}
	switch strings.TrimSpace(envelope.ApprovalMode) {
	case "none", "require_host_consent":
	default:
		return fmt.Errorf("unexpected approval_mode: %s", envelope.ApprovalMode)
	}
	switch policycfg.NormalizeNetworkMode(envelope.NetworkMode) {
	case policycfg.NetworkModeNone, policycfg.NetworkModeEgressAllowlist:
	default:
		return fmt.Errorf("unexpected network_mode: %s", envelope.NetworkMode)
	}
	if err := validateNetworkAllowlistEnvelope(envelope.EgressAllowlist); err != nil {
		return fmt.Errorf("egress_allowlist invalid: %w", err)
	}
	if policycfg.NormalizeNetworkMode(envelope.NetworkMode) == policycfg.NetworkModeNone && envelope.EgressAllowlist != nil && (len(envelope.EgressAllowlist.FQDNs) > 0 || len(envelope.EgressAllowlist.CIDRs) > 0) {
		return fmt.Errorf("egress_allowlist requires egress_allowlist network_mode")
	}
	for _, mount := range envelope.Mounts {
		if strings.TrimSpace(mount.Name) == "" || strings.TrimSpace(mount.Kind) == "" || strings.TrimSpace(mount.Target) == "" {
			return fmt.Errorf("mounts require non-empty name, kind, and target")
		}
	}
	for _, host := range envelope.ResolvedHosts {
		if strings.TrimSpace(host.Host) == "" {
			return fmt.Errorf("resolved host name is required")
		}
		if len(host.IPv4) == 0 {
			return fmt.Errorf("resolved host %s must include ipv4 addresses", host.Host)
		}
		for _, value := range host.IPv4 {
			addr, err := netip.ParseAddr(strings.TrimSpace(value))
			if err != nil || !addr.Is4() {
				return fmt.Errorf("resolved host %s contains invalid ipv4 %q", host.Host, value)
			}
		}
	}
	for _, actionType := range envelope.BrokerActionTypes {
		if !governance.IsValidActionType(actionType) {
			return fmt.Errorf("unexpected broker action type: %s", actionType)
		}
	}
	ctx := authorityContextFromEnvelope(executionID, policyDigest, envelope)
	if !slices.Equal(envelope.BrokerRepoLabels, ctx.BrokerRepoLabels) {
		return fmt.Errorf("broker_repo_labels must be unique, canonical, and non-empty when present")
	}
	if envelope.MutationAttempt != nil {
		if strings.TrimSpace(envelope.MutationAttempt.Field) == "" ||
			strings.TrimSpace(envelope.MutationAttempt.Expected) == "" ||
			strings.TrimSpace(envelope.MutationAttempt.Observed) == "" ||
			strings.TrimSpace(envelope.MutationAttempt.EnforcementPoint) == "" {
			return fmt.Errorf("mutation_attempt fields are required when present")
		}
	}
	if want := ctx.AuthorityDigest; strings.TrimSpace(envelope.Digest) != want {
		return fmt.Errorf("digest mismatch: got %s want %s", envelope.Digest, want)
	}
	return nil
}

func validateRuntimeEnvelope(runtime *RuntimeEnvelope) error {
	if runtime == nil {
		return nil
	}
	if runtime.VCPUCount < 0 {
		return fmt.Errorf("vcpu_count must be >= 0")
	}
	if runtime.MemoryMB < 0 {
		return fmt.Errorf("memory_mb must be >= 0")
	}
	for _, override := range runtime.AppliedOverrides {
		if strings.TrimSpace(override) == "" {
			return fmt.Errorf("applied_overrides must not contain blank values")
		}
	}
	if runtime.Cgroup != nil {
		if runtime.Cgroup.MemoryMaxMB < 0 {
			return fmt.Errorf("cgroup memory_max_mb must be >= 0")
		}
		if runtime.Cgroup.MemoryHighMB < 0 {
			return fmt.Errorf("cgroup memory_high_mb must be >= 0")
		}
		if runtime.Cgroup.MemoryHighMB > 0 && runtime.Cgroup.MemoryMaxMB > 0 && runtime.Cgroup.MemoryHighMB > runtime.Cgroup.MemoryMaxMB {
			return fmt.Errorf("cgroup memory_high_mb cannot exceed memory_max_mb")
		}
		if runtime.Cgroup.PidsMax < 0 {
			return fmt.Errorf("cgroup pids_max must be >= 0")
		}
	}
	if runtime.Network != nil {
		switch strings.TrimSpace(runtime.Network.Mode) {
		case policycfg.NetworkModeNone, policycfg.NetworkModeEgressAllowlist:
		default:
			return fmt.Errorf("unexpected network mode: %s", runtime.Network.Mode)
		}
		if !runtime.Network.Enabled && runtime.Network.Mode != policycfg.NetworkModeNone {
			return fmt.Errorf("disabled network must use mode none")
		}
		if runtime.Network.Enabled && runtime.Network.Mode == policycfg.NetworkModeNone {
			return fmt.Errorf("enabled network cannot use mode none")
		}
		if runtime.Network.Mode == policycfg.NetworkModeNone && runtime.Network.Allowlist != nil && (len(runtime.Network.Allowlist.FQDNs) > 0 || len(runtime.Network.Allowlist.CIDRs) > 0) {
			return fmt.Errorf("network allowlist requires egress_allowlist mode")
		}
		if err := validateNetworkAllowlistEnvelope(runtime.Network.Allowlist); err != nil {
			return fmt.Errorf("network allowlist invalid: %w", err)
		}
		if err := validateBlockedEgressSummary(runtime.Network.BlockedEgress); err != nil {
			return fmt.Errorf("blocked egress invalid: %w", err)
		}
	}
	if runtime.Policy != nil {
		if err := validateRuntimePolicyEnvelope(runtime.Policy); err != nil {
			return fmt.Errorf("policy invalid: %w", err)
		}
	}
	return nil
}

func validateRuntimePolicyEnvelope(policy *escalation.RuntimePolicyEnvelope) error {
	if policy == nil {
		return nil
	}
	if policy.EscalationAttempts != nil {
		summary := policy.EscalationAttempts
		if summary.Count < 0 {
			return fmt.Errorf("runtime.policy.escalation_attempts.count must be >= 0")
		}
		if summary.Count == 0 {
			if len(summary.Sample) != 0 {
				return fmt.Errorf("runtime.policy.escalation_attempts.sample must be empty when count=0")
			}
			if summary.SampleTruncated {
				return fmt.Errorf("runtime.policy.escalation_attempts.sample_truncated must be false when count=0")
			}
		}
		if summary.Count > 0 && len(summary.Sample) == 0 {
			return fmt.Errorf("runtime.policy.escalation_attempts.sample is required when count>0")
		}
		if len(summary.Sample) > escalation.SampleLimit {
			return fmt.Errorf("runtime.policy.escalation_attempts.sample exceeds limit %d", escalation.SampleLimit)
		}
		lastKey := ""
		seen := map[string]struct{}{}
		for idx, sample := range summary.Sample {
			if err := validateEscalationSample(sample); err != nil {
				return fmt.Errorf("runtime.policy.escalation_attempts.sample[%d] invalid: %w", idx, err)
			}
			key := escalationSampleSortKey(sample)
			if _, ok := seen[key]; ok {
				return fmt.Errorf("runtime.policy.escalation_attempts.sample must not contain duplicates")
			}
			seen[key] = struct{}{}
			if idx > 0 && key < lastKey {
				return fmt.Errorf("runtime.policy.escalation_attempts.sample must be in canonical order")
			}
			lastKey = key
		}
	}
	lastClass := ""
	seenClasses := map[escalation.DestructiveActionClass]struct{}{}
	for _, class := range policy.DeniedDestructiveActions {
		if !escalation.IsValidDestructiveActionClass(class) {
			return fmt.Errorf("unexpected denied_destructive_actions value: %s", class)
		}
		if _, ok := seenClasses[class]; ok {
			return fmt.Errorf("runtime.policy.denied_destructive_actions must not contain duplicates")
		}
		seenClasses[class] = struct{}{}
		if lastClass != "" && string(class) < lastClass {
			return fmt.Errorf("runtime.policy.denied_destructive_actions must be sorted")
		}
		lastClass = string(class)
	}
	switch strings.TrimSpace(policy.TerminationReason) {
	case "", "security_denied_authority_mutation", escalation.TerminationReasonPrivilegeEscalation:
		return nil
	default:
		return fmt.Errorf("unexpected runtime.policy.termination_reason: %s", policy.TerminationReason)
	}
}

func applyLegacySemantics(statement *Statement) {
	if statement == nil {
		return
	}
	predicate := &statement.Predicate
	if predicate.Policy != nil && predicate.Policy.Baseline.Network != nil {
		mode, allowlist := normalizeReceiptNetwork(predicate.Policy.Baseline.Network.Mode, predicate.Policy.Baseline.Network.Presets, predicate.Policy.Baseline.Network.Allowlist)
		predicate.Policy.Baseline.Network.Mode = mode
		predicate.Policy.Baseline.Network.Presets = []string{}
		predicate.Policy.Baseline.Network.Allowlist = allowlist
	}
	if predicate.Runtime != nil && predicate.Runtime.Network != nil {
		mode, allowlist := normalizeReceiptNetwork(predicate.Runtime.Network.Mode, predicate.Runtime.Network.Presets, predicate.Runtime.Network.Allowlist)
		predicate.Runtime.Network.Mode = mode
		predicate.Runtime.Network.Presets = []string{}
		predicate.Runtime.Network.Allowlist = allowlist
	}
	if predicate.GovernedActions != nil {
		if predicate.GovernedActions.Count == 0 && len(predicate.GovernedActions.Actions) > 0 {
			predicate.GovernedActions.Count = len(predicate.GovernedActions.Actions)
		}
		if len(predicate.GovernedActions.Normalized) == 0 && len(predicate.GovernedActions.Actions) > 0 {
			predicate.GovernedActions.Normalized = normalizeGovernedActions(predicate.GovernedActions.Actions)
		}
	}
	if predicate.ResultClass != "" {
		if predicate.SemanticsMode == "" {
			predicate.SemanticsMode = SemanticsModeExplicitV1
		}
		return
	}
	predicate.SemanticsMode = SemanticsModeLegacyDerived
	predicate.ResultClass, predicate.Denial = deriveLegacyResult(*predicate)
	predicate.Limitations = appendUnique(predicate.Limitations, "legacy_semantics_derived")
}

func deriveLegacyResult(predicate ExecutionReceiptPredicate) (ResultClass, *DenialSummary) {
	if strings.TrimSpace(predicate.ExecutionStatus) == "reconciled" || strings.TrimSpace(predicate.Outcome.Reason) == "recovered_on_boot" {
		return ResultClassReconciled, nil
	}
	if denial := deriveGovernedDenial(predicate.GovernedActions); denial != nil {
		return ResultClassDenied, denial
	}
	if denial := derivePolicyDenial(predicate.ExecutionStatus, predicate.Outcome.Reason, predicate.PointDecisions); denial != nil {
		return ResultClassDenied, denial
	}
	if isAbnormalTermination(predicate.ExecutionStatus, predicate.Outcome.Reason) {
		return ResultClassAbnormal, nil
	}
	return ResultClassCompleted, nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func hasGovernedActionDeny(summary *GovernedActionSummary) bool {
	if summary == nil {
		return false
	}
	for _, action := range summary.Actions {
		if strings.EqualFold(strings.TrimSpace(action.Decision), "deny") {
			return true
		}
	}
	return false
}

func hasPolicyDenial(predicate ExecutionReceiptPredicate) bool {
	status := strings.TrimSpace(predicate.ExecutionStatus)
	reason := strings.TrimSpace(predicate.Outcome.Reason)
	if strings.HasPrefix(status, "security_denied") || strings.HasPrefix(reason, "security_denied") {
		return true
	}
	return predicate.PointDecisions.DenyCount > 0 && (strings.HasPrefix(status, "policy_denied") || strings.HasPrefix(reason, "policy_denied"))
}

func normalizedGovernedActionSortKey(action NormalizedGovernedActionEntry) string {
	return governedActionSortKey(action)
}

func validateGovernedActionRecord(action GovernedActionRecord, semanticsMode SemanticsMode) error {
	if err := validateGovernedAction(action.ActionType, action.CapabilityPath, action.Decision, action.Used, action.Brokered, action.BrokeredCredentials, action.BindingName); err != nil {
		return err
	}
	if err := validateEscalationEvidence(action); err != nil {
		return err
	}
	if err := validateHostActionRecord(action); err != nil {
		return err
	}
	if err := validateApprovalCheck(action.Approval); err != nil {
		return err
	}
	if err := validateLeaseCheck(action.Lease); err != nil {
		return err
	}
	return validateCoveredActionLeaseRecord(action, semanticsMode)
}

func validateNormalizedGovernedAction(action NormalizedGovernedActionEntry) error {
	return validateGovernedAction(action.ActionType, action.CapabilityPath, action.Decision, action.Used, action.Brokered, action.BrokeredCredentials, action.BindingName)
}

func validateGovernedAction(actionType string, capabilityPath string, decision string, used bool, brokered bool, brokeredCredentials bool, bindingName string) error {
	if strings.TrimSpace(actionType) == "" {
		return fmt.Errorf("action_type is required")
	}
	switch strings.TrimSpace(capabilityPath) {
	case "", "broker", "direct_egress":
	default:
		return fmt.Errorf("unexpected capability_path: %s", capabilityPath)
	}
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "allow", "deny":
	default:
		return fmt.Errorf("unexpected decision: %s", decision)
	}
	if strings.EqualFold(strings.TrimSpace(decision), "deny") && used {
		return fmt.Errorf("denied action cannot be marked used")
	}
	if !brokered && brokeredCredentials {
		return fmt.Errorf("non-brokered action cannot inject brokered credentials")
	}
	if !brokered && strings.TrimSpace(bindingName) != "" {
		return fmt.Errorf("non-brokered action cannot include binding_name")
	}
	return nil
}

func validateEscalationEvidence(action GovernedActionRecord) error {
	if action.Escalation == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(action.Decision), "deny") {
		return fmt.Errorf("escalation evidence is only valid on denied governed actions")
	}
	if err := validateEscalationSignals(action.Escalation.Signals); err != nil {
		return fmt.Errorf("escalation signals invalid: %w", err)
	}
	return nil
}

func validateApprovalCheck(check *approval.Check) error {
	if check == nil {
		return nil
	}
	switch check.Result {
	case approval.VerificationVerified,
		approval.VerificationMissing,
		approval.VerificationExpired,
		approval.VerificationReused,
		approval.VerificationExecutionMismatch,
		approval.VerificationPolicyMismatch,
		approval.VerificationActionTypeMismatch,
		approval.VerificationResourceMismatch,
		approval.VerificationMalformed,
		approval.VerificationSignatureInvalid,
		approval.VerificationUnavailable:
	default:
		return fmt.Errorf("unexpected approval result: %s", check.Result)
	}
	if strings.TrimSpace(check.ResourceDigest) != "" && strings.TrimSpace(check.ResourceDigestAlgo) == "" {
		return fmt.Errorf("approval resource_digest_algo is required with resource_digest")
	}
	if strings.TrimSpace(check.ResourceDigestAlgo) != "" && strings.TrimSpace(check.ResourceDigest) == "" {
		return fmt.Errorf("approval resource_digest is required with resource_digest_algo")
	}
	if check.Consumed && check.Result != approval.VerificationVerified {
		return fmt.Errorf("approval consumed requires result=verified")
	}
	if check.Result == approval.VerificationVerified {
		if strings.TrimSpace(check.TicketID) == "" {
			return fmt.Errorf("approval ticket_id is required when result=verified")
		}
		if strings.TrimSpace(check.IssuerKeyID) == "" {
			return fmt.Errorf("approval issuer_key_id is required when result=verified")
		}
	}
	return nil
}

func validateLeaseCheck(check *lease.Check) error {
	if check == nil {
		return nil
	}
	switch check.Result {
	case lease.CheckVerified,
		lease.CheckMissing,
		lease.CheckExpired,
		lease.CheckMalformed,
		lease.CheckSignatureInvalid,
		lease.CheckExecutionMismatch,
		lease.CheckPolicyMismatch,
		lease.CheckAuthorityMismatch,
		lease.CheckActionMismatch,
		lease.CheckResourceMismatch,
		lease.CheckUnavailable:
	default:
		return fmt.Errorf("unexpected lease result: %s", check.Result)
	}
	switch check.BudgetResult {
	case lease.BudgetNotAttempted, lease.BudgetConsumed, lease.BudgetExhausted, lease.BudgetUnavailable:
	default:
		return fmt.Errorf("unexpected lease budget_result: %s", check.BudgetResult)
	}
	if check.Result == lease.CheckVerified {
		if strings.TrimSpace(check.LeaseID) == "" {
			return fmt.Errorf("lease lease_id is required when result=verified")
		}
		if strings.TrimSpace(check.Issuer) == "" {
			return fmt.Errorf("lease issuer is required when result=verified")
		}
		if strings.TrimSpace(check.IssuerKeyID) == "" {
			return fmt.Errorf("lease issuer_key_id is required when result=verified")
		}
		if strings.TrimSpace(check.GrantID) == "" {
			return fmt.Errorf("lease grant_id is required when result=verified")
		}
		if strings.TrimSpace(check.SelectorDigest) == "" {
			return fmt.Errorf("lease selector_digest is required when result=verified")
		}
		if strings.TrimSpace(check.SelectorDigestAlgo) == "" {
			return fmt.Errorf("lease selector_digest_algo is required when result=verified")
		}
	}
	if check.BudgetResult == lease.BudgetConsumed && check.RemainingCount == nil {
		return fmt.Errorf("lease remaining_count is required when budget_result=consumed")
	}
	if check.BudgetResult != lease.BudgetConsumed && check.RemainingCount != nil {
		return fmt.Errorf("lease remaining_count is only valid when budget_result=consumed")
	}
	return nil
}

func validateCoveredActionLeaseRecord(action GovernedActionRecord, semanticsMode SemanticsMode) error {
	covered := false
	switch strings.TrimSpace(action.ActionType) {
	case governance.ActionHTTPRequest, governance.ActionHostRepoApply:
		covered = true
	default:
		return nil
	}
	if action.Lease == nil {
		if semanticsMode == SemanticsModeExplicitV2 && strings.EqualFold(strings.TrimSpace(action.Decision), "allow") {
			return fmt.Errorf("covered allow actions require lease evidence")
		}
		return nil
	}
	if !covered {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(action.Decision), "allow") {
		if action.Lease.BudgetResult == lease.BudgetConsumed {
			return fmt.Errorf("denied covered actions must not consume lease budget")
		}
		return nil
	}
	if action.Lease.Result != lease.CheckVerified {
		return fmt.Errorf("covered allow actions require lease.result=verified")
	}
	if action.Used || strings.TrimSpace(action.Outcome) == "error" {
		if action.Lease.BudgetResult != lease.BudgetConsumed {
			return fmt.Errorf("covered attempted actions require lease.budget_result=consumed")
		}
	}
	return nil
}

func validateHostActionRecord(action GovernedActionRecord) error {
	if action.HostAction == nil {
		if strings.TrimSpace(action.ActionType) == governance.ActionHostRepoApply {
			return fmt.Errorf("host_repo_apply_patch actions require host_action evidence")
		}
		return nil
	}
	if strings.TrimSpace(action.ActionType) != governance.ActionHostRepoApply {
		return fmt.Errorf("host_action evidence is only valid for host_repo_apply_patch actions")
	}
	if action.HostAction.Class != hostaction.ClassRepoApplyPatchV1 {
		return fmt.Errorf("unexpected host_action.class: %s", action.HostAction.Class)
	}
	if action.HostAction.RepoApplyPatch == nil {
		return fmt.Errorf("repo_apply_patch evidence is required")
	}
	evidence := action.HostAction.RepoApplyPatch
	repoLabel := strings.ToLower(strings.TrimSpace(evidence.RepoLabel))
	if repoLabel == "" {
		return fmt.Errorf("host_action repo_label is required")
	}
	if strings.TrimSpace(action.Target) != "repo:"+repoLabel {
		return fmt.Errorf("host_action target must match repo label")
	}
	if strings.TrimSpace(action.Resource) != repoLabel {
		return fmt.Errorf("host_action resource must match repo label")
	}
	if strings.TrimSpace(action.Method) != "" {
		return fmt.Errorf("host_repo_apply_patch actions must not include method")
	}
	if !action.Brokered {
		return fmt.Errorf("host_repo_apply_patch actions must be brokered")
	}
	if action.BrokeredCredentials {
		return fmt.Errorf("host_repo_apply_patch actions must not inject brokered credentials")
	}
	if strings.TrimSpace(action.BindingName) != "" {
		return fmt.Errorf("host_repo_apply_patch actions must not include binding_name")
	}
	if strings.TrimSpace(evidence.PatchDigestAlgo) != approval.ResourceDigestAlgo {
		return fmt.Errorf("host_action patch_digest_algo must be %s", approval.ResourceDigestAlgo)
	}
	if !isHexDigest(evidence.PatchDigest) {
		return fmt.Errorf("host_action patch_digest must be a sha256 hex digest")
	}
	if strings.TrimSpace(evidence.BaseRevision) == "" {
		return fmt.Errorf("host_action base_revision is required")
	}
	if len(evidence.AffectedPaths) == 0 {
		return fmt.Errorf("host_action affected_paths are required")
	}
	if err := validateCanonicalRelativePaths(evidence.TargetScope, "host_action target_scope"); err != nil {
		return err
	}
	if err := validateCanonicalRelativePaths(evidence.AffectedPaths, "host_action affected_paths"); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(action.Decision), "allow") {
		if action.Approval == nil {
			return fmt.Errorf("host_repo_apply_patch allow actions require approval evidence")
		}
		if action.Approval.Result != approval.VerificationVerified {
			return fmt.Errorf("host_repo_apply_patch allow actions require approval.result=verified")
		}
		if strings.TrimSpace(action.Approval.TicketID) == "" {
			return fmt.Errorf("host_repo_apply_patch allow actions require approval.ticket_id")
		}
		if !action.Approval.Consumed {
			return fmt.Errorf("host_repo_apply_patch allow actions require approval.consumed=true")
		}
		if strings.TrimSpace(action.Outcome) == "error" && strings.TrimSpace(action.Error) == "" {
			return fmt.Errorf("host_repo_apply_patch error actions require error detail")
		}
	}
	return nil
}

func validateEscalationSignals(signals []escalation.Signal) error {
	if len(signals) == 0 {
		return fmt.Errorf("signals are required")
	}
	last := ""
	seen := map[escalation.Signal]struct{}{}
	for _, signal := range signals {
		if !escalation.IsValidSignal(signal) {
			return fmt.Errorf("unexpected signal: %s", signal)
		}
		if _, ok := seen[signal]; ok {
			return fmt.Errorf("signals must not contain duplicates")
		}
		seen[signal] = struct{}{}
		if last != "" && string(signal) < last {
			return fmt.Errorf("signals must be sorted")
		}
		last = string(signal)
	}
	return nil
}

func validateEscalationSample(sample escalation.Sample) error {
	if sample.Count <= 0 {
		return fmt.Errorf("count must be > 0")
	}
	if !escalation.IsValidSourceKind(sample.Source) {
		return fmt.Errorf("unexpected source: %s", sample.Source)
	}
	if err := validateEscalationSignals(sample.Signals); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("rule_id", sample.RuleID); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("action_type", sample.ActionType); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("capability_path", sample.CapabilityPath); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("target", sample.Target); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("resource", sample.Resource); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("mutation_field", sample.MutationField); err != nil {
		return err
	}
	if err := validateEscalationSummaryString("enforcement_point", sample.EnforcementPoint); err != nil {
		return err
	}
	switch sample.Source {
	case escalation.SourceAuthorityMutation:
		if strings.TrimSpace(sample.MutationField) == "" {
			return fmt.Errorf("authority_mutation samples require mutation_field")
		}
		if strings.TrimSpace(sample.EnforcementPoint) == "" {
			return fmt.Errorf("authority_mutation samples require enforcement_point")
		}
		if strings.TrimSpace(sample.RuleID) != "" || strings.TrimSpace(sample.ActionType) != "" || strings.TrimSpace(sample.CapabilityPath) != "" || strings.TrimSpace(sample.Target) != "" || strings.TrimSpace(sample.Resource) != "" || strings.TrimSpace(sample.HostActionClass) != "" {
			return fmt.Errorf("authority_mutation samples must not include governed-action fields")
		}
	case escalation.SourceGovernedAction:
		if strings.TrimSpace(sample.MutationField) != "" || strings.TrimSpace(sample.EnforcementPoint) != "" {
			return fmt.Errorf("governed_action samples must not include mutation fields")
		}
	default:
		return fmt.Errorf("unexpected source: %s", sample.Source)
	}
	if strings.TrimSpace(sample.HostActionClass) != "" {
		class, ok := escalation.MapHostActionClass(sample.HostActionClass)
		if !ok || string(class) != strings.TrimSpace(sample.HostActionClass) {
			return fmt.Errorf("unexpected host_action_class: %s", sample.HostActionClass)
		}
	}
	return nil
}

func validateEscalationSummaryString(field string, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

func escalationSampleSortKey(sample escalation.Sample) string {
	signals := make([]string, 0, len(sample.Signals))
	for _, signal := range sample.Signals {
		signals = append(signals, string(signal))
	}
	return strings.Join([]string{
		string(sample.Source),
		strings.Join(signals, ","),
		sample.ActionType,
		sample.CapabilityPath,
		sample.RuleID,
		sample.Target,
		sample.Resource,
		sample.HostActionClass,
		sample.MutationField,
		sample.EnforcementPoint,
	}, "|")
}

func validateRuntimePolicyTermination(predicate ExecutionReceiptPredicate) error {
	if predicate.Runtime == nil || predicate.Runtime.Policy == nil {
		return nil
	}
	reason := strings.TrimSpace(predicate.Runtime.Policy.TerminationReason)
	if reason == "" {
		return nil
	}
	switch reason {
	case "security_denied_authority_mutation":
		if predicate.Authority == nil || predicate.Authority.MutationAttempt == nil {
			return fmt.Errorf("security_denied_authority_mutation requires authority mutation evidence")
		}
	case escalation.TerminationReasonPrivilegeEscalation:
		if !hasTerminalGovernedEscalation(predicate.GovernedActions) {
			return fmt.Errorf("privilege_escalation_attempt requires underlying governed-action escalation evidence")
		}
	default:
		return fmt.Errorf("unexpected runtime.policy.termination_reason: %s", reason)
	}
	return nil
}

func hasTerminalGovernedEscalation(summary *GovernedActionSummary) bool {
	if summary == nil {
		return false
	}
	for _, action := range summary.Actions {
		if action.Escalation == nil {
			continue
		}
		for _, signal := range action.Escalation.Signals {
			switch signal {
			case escalation.SignalAuthorityBroadeningAttempt,
				escalation.SignalUnsupportedDestructiveClassAccess,
				escalation.SignalRepeatedProbingPattern:
				return true
			}
		}
	}
	return false
}

func validateCanonicalRelativePaths(values []string, field string) error {
	last := ""
	seen := map[string]struct{}{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return fmt.Errorf("%s must not contain blank values", field)
		}
		if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
			return fmt.Errorf("%s must contain relative slash-separated paths", field)
		}
		cleaned := path.Clean(value)
		if cleaned == "." || cleaned == "" || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return fmt.Errorf("%s must not contain path escapes", field)
		}
		for _, segment := range strings.Split(cleaned, "/") {
			if segment == ".git" {
				return fmt.Errorf("%s must not contain .git paths", field)
			}
		}
		if cleaned != value {
			return fmt.Errorf("%s must be canonical", field)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s must not contain duplicates", field)
		}
		seen[value] = struct{}{}
		if last != "" && value < last {
			return fmt.Errorf("%s must be sorted", field)
		}
		last = value
	}
	return nil
}

func isHexDigest(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) != 64 {
		return false
	}
	_, err := hex.DecodeString(trimmed)
	return err == nil
}

func validateNetworkAllowlistEnvelope(allowlist *NetworkAllowlistEnvelope) error {
	if allowlist == nil {
		return nil
	}
	for _, domain := range allowlist.FQDNs {
		if strings.TrimSpace(domain) == "" {
			return fmt.Errorf("blank fqdn")
		}
	}
	for _, cidr := range allowlist.CIDRs {
		if strings.TrimSpace(cidr) == "" {
			return fmt.Errorf("blank cidr")
		}
	}
	return nil
}

func validateBlockedEgressSummary(summary *BlockedEgressSummary) error {
	if summary == nil {
		return nil
	}
	if summary.TotalCount < 0 {
		return fmt.Errorf("total_count must be >= 0")
	}
	if summary.UniqueTargetCount < 0 {
		return fmt.Errorf("unique_target_count must be >= 0")
	}
	if summary.UniqueTargetCount > summary.TotalCount {
		return fmt.Errorf("unique_target_count cannot exceed total_count")
	}
	if len(summary.Sample) > 10 {
		return fmt.Errorf("sample may include at most 10 targets")
	}
	if summary.SampleTruncated {
		if summary.UniqueTargetCount <= len(summary.Sample) {
			return fmt.Errorf("sample_truncated requires additional unique targets beyond the sample")
		}
	} else if summary.UniqueTargetCount != len(summary.Sample) {
		return fmt.Errorf("sample must include every unique target when sample_truncated is false")
	}
	for idx, entry := range summary.Sample {
		if strings.TrimSpace(entry.Target) == "" {
			return fmt.Errorf("sample entry %d target is required", idx+1)
		}
		switch strings.TrimSpace(entry.Kind) {
		case "ip", "fqdn", "rfc1918":
		default:
			return fmt.Errorf("sample entry %d has unexpected kind %q", idx+1, entry.Kind)
		}
		if entry.FirstSeenAt.IsZero() {
			return fmt.Errorf("sample entry %d first_seen_at is required", idx+1)
		}
		if entry.Count <= 0 {
			return fmt.Errorf("sample entry %d count must be > 0", idx+1)
		}
	}
	return nil
}

func normalizeReceiptNetwork(mode string, presets []string, allowlist *NetworkAllowlistEnvelope) (string, *NetworkAllowlistEnvelope) {
	normalized := policycfg.NormalizeNetworkPolicy(policycfg.NetworkPolicy{
		Mode:    mode,
		Presets: presets,
		Allowlist: policycfg.NetworkAllowlist{
			FQDNs: allowlistFQDNs(allowlist),
			CIDRs: allowlistCIDRs(allowlist),
		},
	})
	if normalized.Mode == policycfg.NetworkModeNone {
		return normalized.Mode, nil
	}
	return normalized.Mode, &NetworkAllowlistEnvelope{
		FQDNs: append([]string(nil), normalized.Allowlist.FQDNs...),
		CIDRs: append([]string(nil), normalized.Allowlist.CIDRs...),
	}
}

func allowlistFQDNs(allowlist *NetworkAllowlistEnvelope) []string {
	if allowlist == nil {
		return nil
	}
	return append([]string(nil), allowlist.FQDNs...)
}

func allowlistCIDRs(allowlist *NetworkAllowlistEnvelope) []string {
	if allowlist == nil {
		return nil
	}
	return append([]string(nil), allowlist.CIDRs...)
}

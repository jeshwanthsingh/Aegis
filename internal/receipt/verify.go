package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	if len(receipt.Envelope.Signatures) == 0 {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "dsse envelope has no signatures")
	}
	payload, err := base64.StdEncoding.DecodeString(receipt.Envelope.Payload)
	if err != nil {
		return Statement{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "decode dsse payload: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(receipt.Envelope.Signatures[0].Sig)
	if err != nil {
		return Statement{}, verificationErrorWrap(FailureClassSignatureInvalid, err, "decode dsse signature: %v", err)
	}
	if !ed25519.Verify(publicKey, pae(receipt.Envelope.PayloadType, payload), sig) {
		return Statement{}, verificationError(FailureClassSignatureInvalid, "dsse signature verification failed")
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
	if statement.Predicate.SignerKeyID != receipt.Envelope.Signatures[0].KeyID {
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
	case "", SemanticsModeExplicitV1, SemanticsModeLegacyDerived:
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
	}
	if predicate.Policy != nil {
		if err := validatePolicyEnvelope(predicate.Policy); err != nil {
			return verificationError(FailureClassSemanticReceipt, "policy envelope invalid: %v", err)
		}
		if strings.TrimSpace(predicate.PolicyDigest) == "" {
			return verificationError(FailureClassSemanticReceipt, "policy_digest is required when policy evidence is present")
		}
	}
	if predicate.GovernedActions != nil {
		if predicate.GovernedActions.Count != len(predicate.GovernedActions.Actions) {
			return verificationError(FailureClassSemanticReceipt, "governed action raw count mismatch: count=%d actions=%d", predicate.GovernedActions.Count, len(predicate.GovernedActions.Actions))
		}
		for idx, action := range predicate.GovernedActions.Actions {
			if err := validateGovernedActionRecord(action); err != nil {
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
	}
	return nil
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

func validateGovernedActionRecord(action GovernedActionRecord) error {
	return validateGovernedAction(action.ActionType, action.CapabilityPath, action.Decision, action.Used, action.Brokered, action.BrokeredCredentials, action.BindingName)
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

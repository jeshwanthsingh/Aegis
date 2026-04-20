package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/models"
	policycfg "aegis/internal/policy"
	"aegis/internal/telemetry"
)

func BuildSignedReceipt(input Input, signer *Signer) (SignedReceipt, error) {
	if signer == nil {
		return SignedReceipt{}, fmt.Errorf("receipt signer is required")
	}
	predicate, runtimeEventCount, err := buildPredicate(input, signer)
	if err != nil {
		return SignedReceipt{}, err
	}
	statement := Statement{
		Type:          StatementType,
		Subject:       buildSubjects(input.OutputArtifacts),
		PredicateType: PredicateType,
		Predicate:     predicate,
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return SignedReceipt{}, fmt.Errorf("marshal receipt statement: %w", err)
	}
	preAuth := pae(PayloadType, statementBytes)
	signature := ed25519.Sign(signer.PrivateKey, preAuth)
	envelope := Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statementBytes),
		Signatures:  []Signature{{KeyID: signer.KeyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	}
	_ = runtimeEventCount
	return SignedReceipt{Envelope: envelope, Statement: statement}, nil
}

func buildPredicate(input Input, signer *Signer) (ExecutionReceiptPredicate, int, error) {
	intentDigest, intentAlgo := digestBytes(input.IntentRaw)
	evidenceDigest, runtimeEventCount, pointSummary, divergenceSummary, brokerSummary, governedSummary, err := summarizeTelemetry(input.TelemetryEvents)
	if err != nil {
		return ExecutionReceiptPredicate{}, 0, err
	}
	resultClass, denial := classifyResult(input, pointSummary, governedSummary)
	limitations := []string{"host attestation deferred"}
	if input.Outcome.OutputTruncated {
		limitations = append(limitations, "captured standard stream artifacts may be truncated")
	}
	if hasReadOnlyFileSemantics(input.TelemetryEvents) {
		limitations = append(limitations, "file.open semantics are read-only in RuntimeEvent v1")
	}
	metadata := cloneStringMap(input.Attributes)
	return ExecutionReceiptPredicate{
		Version:            PredicateVersion,
		ExecutionID:        input.ExecutionID,
		WorkflowID:         input.WorkflowID,
		Backend:            input.Backend,
		TaskClass:          input.TaskClass,
		DeclaredPurpose:    input.DeclaredPurpose,
		WorkspaceID:        input.WorkspaceID,
		ExecutionStatus:    input.ExecutionStatus,
		SemanticsMode:      SemanticsModeExplicitV1,
		ResultClass:        resultClass,
		Denial:             denial,
		PolicyDigest:       policyDigestForReceipt(input.Policy),
		IntentDigest:       intentDigest,
		IntentDigestAlgo:   intentAlgo,
		Policy:             clonePolicyEnvelope(input.Policy),
		EvidenceDigest:     evidenceDigest,
		EvidenceDigestAlgo: "sha256",
		RuntimeEventCount:  runtimeEventCount,
		PointDecisions:     pointSummary,
		Divergence:         divergenceSummary,
		Outcome:            input.Outcome,
		Runtime:            cloneRuntimeEnvelope(input.Runtime),
		BrokerSummary:      brokerSummary,
		GovernedActions:    governedSummary,
		Trust:              trustPostureForSigner(signer),
		Limitations:        limitations,
		StartedAt:          input.StartedAt.UTC(),
		FinishedAt:         input.FinishedAt.UTC(),
		SignerKeyID:        signer.KeyID,
		Metadata:           metadata,
	}, runtimeEventCount, nil
}

func clonePolicyEnvelope(policy *PolicyEnvelope) *PolicyEnvelope {
	if policy == nil {
		return nil
	}
	cloned := &PolicyEnvelope{
		Baseline: BaselinePolicy{
			Language:      policy.Baseline.Language,
			CodeSizeBytes: policy.Baseline.CodeSizeBytes,
			MaxCodeBytes:  policy.Baseline.MaxCodeBytes,
			TimeoutMs:     policy.Baseline.TimeoutMs,
			MaxTimeoutMs:  policy.Baseline.MaxTimeoutMs,
			Profile:       policy.Baseline.Profile,
		},
	}
	if policy.Baseline.Network != nil {
		mode := policycfg.NormalizeNetworkMode(policy.Baseline.Network.Mode)
		allowlist := cloneNetworkAllowlistEnvelope(policy.Baseline.Network.Allowlist)
		if mode == policycfg.NetworkModeNone {
			allowlist = nil
		}
		cloned.Baseline.Network = &BaselineNetworkPolicy{
			Mode:      mode,
			Presets:   []string{},
			Allowlist: allowlist,
		}
	}
	if policy.Intent != nil {
		cloned.Intent = &IntentPolicyDigest{
			Digest: policy.Intent.Digest,
			Source: policy.Intent.Source,
		}
	}
	return cloned
}

func cloneRuntimeEnvelope(runtime *RuntimeEnvelope) *RuntimeEnvelope {
	if runtime == nil {
		return nil
	}
	cloned := &RuntimeEnvelope{
		Profile:          runtime.Profile,
		VCPUCount:        runtime.VCPUCount,
		MemoryMB:         runtime.MemoryMB,
		AppliedOverrides: append([]string(nil), runtime.AppliedOverrides...),
	}
	if runtime.Cgroup != nil {
		cloned.Cgroup = &RuntimeCgroupEnvelope{
			MemoryMaxMB:  runtime.Cgroup.MemoryMaxMB,
			MemoryHighMB: runtime.Cgroup.MemoryHighMB,
			PidsMax:      runtime.Cgroup.PidsMax,
			CPUMax:       runtime.Cgroup.CPUMax,
			SwapMax:      runtime.Cgroup.SwapMax,
		}
	}
	if runtime.Network != nil {
		mode := policycfg.NormalizeNetworkMode(runtime.Network.Mode)
		allowlist := cloneNetworkAllowlistEnvelope(runtime.Network.Allowlist)
		if mode == policycfg.NetworkModeNone {
			allowlist = nil
		} else {
			allowlist = runtimeAllowlistForReceipt(allowlist)
		}
		cloned.Network = &RuntimeNetworkEnvelope{
			Enabled:   runtime.Network.Enabled,
			Mode:      mode,
			Presets:   []string{},
			Allowlist: allowlist,
		}
	}
	if runtime.Broker != nil {
		cloned.Broker = &RuntimeBrokerEnvelope{Enabled: runtime.Broker.Enabled}
	}
	return cloned
}

func policyDigestForReceipt(policy *PolicyEnvelope) string {
	if policy == nil {
		return ""
	}
	canonical, err := json.Marshal(clonePolicyEnvelope(policy))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func buildSubjects(artifacts []Artifact) []StatementSubject {
	if len(artifacts) == 0 {
		return []StatementSubject{}
	}
	subjects := make([]StatementSubject, 0, len(artifacts))
	for _, artifact := range artifacts {
		subjects = append(subjects, StatementSubject{Name: artifact.Name, Digest: cloneStringMap(artifact.Digest)})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Name < subjects[j].Name })
	return subjects
}

func summarizeTelemetry(events []telemetry.Event) (string, int, PointDecisionSummary, DivergenceSummary, *BrokerSummary, *GovernedActionSummary, error) {
	canonical := make([]map[string]any, 0, len(events))
	pointSummary := PointDecisionSummary{}
	divergenceSummary := DivergenceSummary{Verdict: models.DivergenceAllow, TriggeredRuleIDs: []string{}}
	runtimeEventCount := 0
	allowedDomainsSet := map[string]struct{}{}
	deniedDomainsSet := map[string]struct{}{}
	bindingsUsedSet := map[string]struct{}{}
	brokerReqCount, brokerAllowedCount, brokerDeniedCount := 0, 0, 0
	governedActions := make([]GovernedActionRecord, 0)
	for _, event := range events {
		if event.Kind == telemetry.KindReceipt {
			continue
		}
		canonical = append(canonical, map[string]any{"kind": event.Kind, "data": json.RawMessage(event.Data)})
		switch event.Kind {
		case telemetry.KindRuntimeEvent:
			runtimeEventCount++
		case telemetry.KindPolicyPointDecision:
			var point models.PolicyPointDecision
			if err := json.Unmarshal(event.Data, &point); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode point decision: %w", err)
			}
			switch point.Decision {
			case models.DecisionAllow:
				pointSummary.AllowCount++
			case models.DecisionDeny:
				pointSummary.DenyCount++
			case models.DecisionNotApplicable:
				pointSummary.NotApplicableCount++
			}
		case telemetry.KindPolicyDivergence:
			var divergence models.PolicyDivergenceResult
			if err := json.Unmarshal(event.Data, &divergence); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode divergence result: %w", err)
			}
			ruleIDs := make([]string, 0, len(divergence.TriggeredRules))
			for _, hit := range divergence.TriggeredRules {
				ruleIDs = append(ruleIDs, hit.RuleID)
			}
			sort.Strings(ruleIDs)
			divergenceSummary = DivergenceSummary{Verdict: divergence.CurrentVerdict, TriggeredRuleIDs: ruleIDs, RuleHitCount: len(ruleIDs)}
		case telemetry.KindGovernedAction:
			var action telemetry.GovernedActionData
			if err := json.Unmarshal(event.Data, &action); err != nil {
				return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("decode governed action: %w", err)
			}
			governedActions = append(governedActions, GovernedActionRecord{
				ActionType:          action.ActionType,
				Target:              action.Target,
				Resource:            action.Resource,
				Method:              action.Method,
				CapabilityPath:      action.CapabilityPath,
				Decision:            action.Decision,
				Outcome:             action.Outcome,
				Used:                action.Used,
				Reason:              action.Reason,
				RuleID:              action.RuleID,
				PolicyDigest:        action.PolicyDigest,
				Brokered:            action.Brokered,
				BrokeredCredentials: action.BrokeredCredentials,
				BindingName:         action.BindingName,
				ResponseDigest:      action.ResponseDigest,
				ResponseDigestAlgo:  action.ResponseDigestAlgo,
				DenialMarker:        action.DenialMarker,
				AuditPayload:        cloneStringMap(action.AuditPayload),
				Error:               action.Error,
			})
		case telemetry.KindCredentialAllowed:
			var bd telemetry.CredentialBrokerData
			if json.Unmarshal(event.Data, &bd) == nil {
				brokerReqCount++
				brokerAllowedCount++
				if bd.TargetDomain != "" {
					allowedDomainsSet[bd.TargetDomain] = struct{}{}
				}
				if bd.BindingName != "" {
					bindingsUsedSet[bd.BindingName] = struct{}{}
				}
			}
		case telemetry.KindCredentialDenied:
			var bd telemetry.CredentialBrokerData
			if json.Unmarshal(event.Data, &bd) == nil {
				brokerReqCount++
				brokerDeniedCount++
				if bd.TargetDomain != "" {
					deniedDomainsSet[bd.TargetDomain] = struct{}{}
				}
			}
		}
	}
	bytes, err := json.Marshal(canonical)
	if err != nil {
		return "", 0, PointDecisionSummary{}, DivergenceSummary{}, nil, nil, fmt.Errorf("marshal evidence summary: %w", err)
	}
	digest := sha256.Sum256(bytes)
	var bs *BrokerSummary
	if brokerReqCount > 0 {
		bs = &BrokerSummary{
			RequestCount:   brokerReqCount,
			AllowedCount:   brokerAllowedCount,
			DeniedCount:    brokerDeniedCount,
			DomainsAllowed: setToSortedSlice(allowedDomainsSet),
			DomainsDenied:  setToSortedSlice(deniedDomainsSet),
			BindingsUsed:   setToSortedSlice(bindingsUsedSet),
		}
	}
	var gs *GovernedActionSummary
	if len(governedActions) > 0 {
		gs = &GovernedActionSummary{
			Count:      len(governedActions),
			Actions:    governedActions,
			Normalized: normalizeGovernedActions(governedActions),
		}
	}
	return hex.EncodeToString(digest[:]), runtimeEventCount, pointSummary, divergenceSummary, bs, gs, nil
}

func classifyResult(input Input, pointSummary PointDecisionSummary, governedSummary *GovernedActionSummary) (ResultClass, *DenialSummary) {
	if strings.EqualFold(strings.TrimSpace(input.ExecutionStatus), "reconciled") || strings.TrimSpace(input.Outcome.Reason) == "recovered_on_boot" {
		return ResultClassReconciled, nil
	}
	if denial := deriveGovernedDenial(governedSummary); denial != nil {
		return ResultClassDenied, denial
	}
	if denial := derivePolicyDenial(input.ExecutionStatus, input.Outcome.Reason, pointSummary); denial != nil {
		return ResultClassDenied, denial
	}
	if isAbnormalTermination(input.ExecutionStatus, input.Outcome.Reason) {
		return ResultClassAbnormal, nil
	}
	return ResultClassCompleted, nil
}

func derivePolicyDenial(executionStatus string, outcomeReason string, pointSummary PointDecisionSummary) *DenialSummary {
	status := strings.TrimSpace(executionStatus)
	reason := strings.TrimSpace(outcomeReason)
	if strings.HasPrefix(status, "security_denied") || strings.HasPrefix(reason, "security_denied") {
		return &DenialSummary{Class: DenialClassPolicy}
	}
	if pointSummary.DenyCount > 0 && (strings.HasPrefix(status, "policy_denied") || strings.HasPrefix(reason, "policy_denied")) {
		return &DenialSummary{Class: DenialClassPolicy}
	}
	return nil
}

func deriveGovernedDenial(governedSummary *GovernedActionSummary) *DenialSummary {
	if governedSummary == nil {
		return nil
	}
	for _, action := range governedSummary.Actions {
		if !strings.EqualFold(strings.TrimSpace(action.Decision), "deny") {
			continue
		}
		return &DenialSummary{
			Class:  DenialClassGovernedAction,
			RuleID: strings.TrimSpace(action.RuleID),
			Marker: strings.TrimSpace(action.DenialMarker),
		}
	}
	return nil
}

func isAbnormalTermination(executionStatus string, outcomeReason string) bool {
	status := strings.TrimSpace(executionStatus)
	if status != "" && status != "completed" && status != "reconciled" {
		return true
	}
	reason := strings.TrimSpace(outcomeReason)
	switch reason {
	case "", "completed", "recovered_on_boot":
		return false
	case "sandbox_error", "timed_out", "teardown_failed":
		return true
	}
	return strings.HasPrefix(reason, "sandbox_")
}

func normalizeGovernedActions(actions []GovernedActionRecord) []NormalizedGovernedActionEntry {
	type aggregate struct {
		entry NormalizedGovernedActionEntry
		key   string
	}
	grouped := map[string]*aggregate{}
	for _, action := range actions {
		entry := normalizedGovernedAction(action)
		key := governedActionSortKey(entry)
		if existing, ok := grouped[key]; ok {
			existing.entry.Count++
			continue
		}
		grouped[key] = &aggregate{entry: entry, key: key}
	}
	aggregates := make([]aggregate, 0, len(grouped))
	for _, entry := range grouped {
		aggregates = append(aggregates, *entry)
	}
	sort.Slice(aggregates, func(i, j int) bool { return aggregates[i].key < aggregates[j].key })
	normalized := make([]NormalizedGovernedActionEntry, 0, len(aggregates))
	for _, entry := range aggregates {
		normalized = append(normalized, entry.entry)
	}
	return normalized
}

func cloneNetworkAllowlistEnvelope(src *NetworkAllowlistEnvelope) *NetworkAllowlistEnvelope {
	if src == nil {
		return nil
	}
	fqdns := append([]string{}, src.FQDNs...)
	cidrs := append([]string{}, src.CIDRs...)
	sort.Strings(fqdns)
	sort.Strings(cidrs)
	return &NetworkAllowlistEnvelope{
		FQDNs: fqdns,
		CIDRs: cidrs,
	}
}

func runtimeAllowlistForReceipt(src *NetworkAllowlistEnvelope) *NetworkAllowlistEnvelope {
	if src == nil {
		src = &NetworkAllowlistEnvelope{}
	}
	cloned := cloneNetworkAllowlistEnvelope(src)
	if cloned == nil {
		cloned = &NetworkAllowlistEnvelope{}
	}
	for _, cidr := range cloned.CIDRs {
		if cidr == "127.0.0.0/8" {
			return cloned
		}
	}
	cloned.CIDRs = append(cloned.CIDRs, "127.0.0.0/8")
	sort.Strings(cloned.CIDRs)
	return cloned
}

func normalizedGovernedAction(action GovernedActionRecord) NormalizedGovernedActionEntry {
	return NormalizedGovernedActionEntry{
		Count:               1,
		ActionType:          strings.TrimSpace(action.ActionType),
		Target:              strings.TrimSpace(action.Target),
		Resource:            strings.TrimSpace(action.Resource),
		Method:              strings.TrimSpace(action.Method),
		CapabilityPath:      strings.TrimSpace(action.CapabilityPath),
		Decision:            strings.TrimSpace(action.Decision),
		Outcome:             strings.TrimSpace(action.Outcome),
		Used:                action.Used,
		Reason:              strings.TrimSpace(action.Reason),
		RuleID:              strings.TrimSpace(action.RuleID),
		PolicyDigest:        strings.TrimSpace(action.PolicyDigest),
		Brokered:            action.Brokered,
		BrokeredCredentials: action.BrokeredCredentials,
		BindingName:         strings.TrimSpace(action.BindingName),
		ResponseDigest:      strings.TrimSpace(action.ResponseDigest),
		ResponseDigestAlgo:  strings.TrimSpace(action.ResponseDigestAlgo),
		DenialMarker:        strings.TrimSpace(action.DenialMarker),
		AuditPayload:        cloneStringMap(action.AuditPayload),
		Error:               strings.TrimSpace(action.Error),
	}
}

func governedActionSortKey(action NormalizedGovernedActionEntry) string {
	parts := []string{
		action.ActionType,
		action.Target,
		action.CapabilityPath,
		action.Method,
		action.Decision,
		strconv.FormatBool(action.Used),
		action.Resource,
		action.RuleID,
		action.BindingName,
		action.DenialMarker,
		strconv.FormatBool(action.Brokered),
		strconv.FormatBool(action.BrokeredCredentials),
		action.PolicyDigest,
		action.ResponseDigestAlgo,
		action.ResponseDigest,
		action.Outcome,
		action.Reason,
		action.Error,
	}
	if len(action.AuditPayload) == 0 {
		return strings.Join(parts, "\x00")
	}
	keys := make([]string, 0, len(action.AuditPayload))
	for key := range action.AuditPayload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+action.AuditPayload[key])
	}
	return strings.Join(parts, "\x00")
}

func hasReadOnlyFileSemantics(events []telemetry.Event) bool {
	for _, event := range events {
		if event.Kind != telemetry.KindPolicyPointDecision {
			continue
		}
		var point models.PolicyPointDecision
		if err := json.Unmarshal(event.Data, &point); err != nil {
			continue
		}
		if point.EventType == models.EventFileOpen {
			return true
		}
	}
	return false
}

func trustPostureForSigner(signer *Signer) TrustPosture {
	limitations := []string{"host_attestation_absent"}
	if signer.Mode == SigningModeDev {
		limitations = append(limitations, "dev_signing_mode")
	}
	if signer.KeySource == KeySourceDevFallback {
		limitations = append(limitations, "fallback_dev_seed")
	}
	return TrustPosture{
		SigningMode:          signer.Mode,
		KeySource:            signer.KeySource,
		Attestation:          "absent",
		VerificationMaterial: "ed25519_public_key",
		Limitations:          limitations,
	}
}

func digestBytes(raw []byte) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), "sha256"
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func trustLimitationsText(trust TrustPosture) string {
	if len(trust.Limitations) == 0 {
		return "none"
	}
	ordered := append([]string(nil), trust.Limitations...)
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func setToSortedSlice(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

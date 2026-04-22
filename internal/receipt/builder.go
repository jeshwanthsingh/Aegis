package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
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
	envelope, err := dsse.SignEnvelope(PayloadType, statementBytes, signer.PrivateKey)
	if err != nil {
		return SignedReceipt{}, err
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
	blockedEgress, err := summarizeBlockedEgress(input.TelemetryEvents)
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
	runtime := cloneRuntimeEnvelope(input.Runtime)
	if runtime != nil && runtime.Network != nil {
		runtime.Network.BlockedEgress = blockedEgress
	}
	if runtimePolicy := buildRuntimePolicySummary(governedSummary, input.Authority, input.Outcome.Reason); runtimePolicy != nil {
		if runtime == nil {
			runtime = &RuntimeEnvelope{}
		}
		runtime.Policy = runtimePolicy
	}
	return ExecutionReceiptPredicate{
		Version:            PredicateVersion,
		ExecutionID:        input.ExecutionID,
		WorkflowID:         input.WorkflowID,
		Backend:            input.Backend,
		TaskClass:          input.TaskClass,
		DeclaredPurpose:    input.DeclaredPurpose,
		WorkspaceID:        input.WorkspaceID,
		ExecutionStatus:    input.ExecutionStatus,
		SemanticsMode:      SemanticsModeExplicitV2,
		ResultClass:        resultClass,
		Denial:             denial,
		PolicyDigest:       PolicyDigest(input.Policy),
		IntentDigest:       intentDigest,
		IntentDigestAlgo:   intentAlgo,
		Policy:             clonePolicyEnvelope(input.Policy),
		Authority:          cloneAuthorityEnvelope(input.Authority),
		EvidenceDigest:     evidenceDigest,
		EvidenceDigestAlgo: "sha256",
		RuntimeEventCount:  runtimeEventCount,
		PointDecisions:     pointSummary,
		Divergence:         divergenceSummary,
		Outcome:            input.Outcome,
		Runtime:            runtime,
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

func cloneAuthorityEnvelope(authority *AuthorityEnvelope) *AuthorityEnvelope {
	if authority == nil {
		return nil
	}
	cloned := &AuthorityEnvelope{
		Digest:               authority.Digest,
		RootfsImage:          authority.RootfsImage,
		Mounts:               append([]AuthorityMountEnvelope(nil), authority.Mounts...),
		NetworkMode:          policycfg.NormalizeNetworkMode(authority.NetworkMode),
		ResolvedHosts:        append([]AuthorityResolvedHostEnvelope(nil), authority.ResolvedHosts...),
		BrokerAllowedDomains: append([]string(nil), authority.BrokerAllowedDomains...),
		BrokerRepoLabels:     append([]string(nil), authority.BrokerRepoLabels...),
		BrokerActionTypes:    append([]string(nil), authority.BrokerActionTypes...),
		ApprovalMode:         authority.ApprovalMode,
	}
	if authority.EgressAllowlist != nil {
		cloned.EgressAllowlist = cloneNetworkAllowlistEnvelope(authority.EgressAllowlist)
	}
	if authority.MutationAttempt != nil {
		cloned.MutationAttempt = &AuthorityMutationEnvelope{
			Field:            authority.MutationAttempt.Field,
			Expected:         authority.MutationAttempt.Expected,
			Observed:         authority.MutationAttempt.Observed,
			EnforcementPoint: authority.MutationAttempt.EnforcementPoint,
		}
	}
	for idx := range cloned.ResolvedHosts {
		cloned.ResolvedHosts[idx].IPv4 = append([]string(nil), authority.ResolvedHosts[idx].IPv4...)
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
			Enabled:       runtime.Network.Enabled,
			Mode:          mode,
			Presets:       []string{},
			Allowlist:     allowlist,
			BlockedEgress: cloneBlockedEgressSummary(runtime.Network.BlockedEgress),
		}
	}
	if runtime.Broker != nil {
		cloned.Broker = &RuntimeBrokerEnvelope{Enabled: runtime.Broker.Enabled}
	}
	if runtime.Policy != nil {
		cloned.Policy = cloneRuntimePolicyEnvelope(runtime.Policy)
	}
	return cloned
}

func cloneRuntimePolicyEnvelope(policy *escalation.RuntimePolicyEnvelope) *escalation.RuntimePolicyEnvelope {
	if policy == nil {
		return nil
	}
	cloned := &escalation.RuntimePolicyEnvelope{
		TerminationReason: strings.TrimSpace(policy.TerminationReason),
	}
	if policy.EscalationAttempts != nil {
		cloned.EscalationAttempts = &escalation.Summary{
			Count:           policy.EscalationAttempts.Count,
			SampleTruncated: policy.EscalationAttempts.SampleTruncated,
			Sample:          cloneEscalationSamples(policy.EscalationAttempts.Sample),
		}
	}
	if len(policy.DeniedDestructiveActions) > 0 {
		cloned.DeniedDestructiveActions = append([]escalation.DestructiveActionClass(nil), policy.DeniedDestructiveActions...)
	}
	return cloned
}

func PolicyDigest(policy *PolicyEnvelope) string {
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
				AuditPayload:        receiptAuditPayload(action.AuditPayload),
				Error:               action.Error,
				Approval:            cloneApprovalCheck(action.Approval),
				Lease:               cloneLeaseCheck(action.Lease),
				Escalation:          cloneEscalationEvidence(action.Escalation),
				HostAction:          cloneHostActionEvidence(action.HostAction),
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

func cloneBlockedEgressSummary(src *BlockedEgressSummary) *BlockedEgressSummary {
	if src == nil {
		return nil
	}
	sample := make([]BlockedEgressEntry, 0, len(src.Sample))
	for _, entry := range src.Sample {
		sample = append(sample, BlockedEgressEntry{
			Target:      strings.TrimSpace(entry.Target),
			Kind:        strings.TrimSpace(entry.Kind),
			FirstSeenAt: entry.FirstSeenAt.UTC(),
			Count:       entry.Count,
		})
	}
	return &BlockedEgressSummary{
		TotalCount:        src.TotalCount,
		UniqueTargetCount: src.UniqueTargetCount,
		Sample:            sample,
		SampleTruncated:   src.SampleTruncated,
	}
}

func summarizeBlockedEgress(events []telemetry.Event) (*BlockedEgressSummary, error) {
	const sampleLimit = 10

	summary := &BlockedEgressSummary{Sample: []BlockedEgressEntry{}}
	connectEvents := map[uint64]models.RuntimeEvent{}
	for _, event := range events {
		if event.Kind != telemetry.KindRuntimeEvent {
			continue
		}
		var runtimeEvent models.RuntimeEvent
		if err := json.Unmarshal(event.Data, &runtimeEvent); err != nil {
			return nil, fmt.Errorf("decode runtime event for blocked egress: %w", err)
		}
		if runtimeEvent.Type == models.EventNetConnect {
			connectEvents[runtimeEvent.Seq] = runtimeEvent
		}
	}

	type sampleState struct {
		index int
	}
	states := map[string]sampleState{}

	addSample := func(target string, kind string, firstSeenAt time.Time) {
		target = strings.TrimSpace(target)
		kind = strings.TrimSpace(kind)
		if target == "" || kind == "" {
			return
		}
		summary.TotalCount++
		if state, ok := states[target]; ok {
			if state.index >= 0 {
				summary.Sample[state.index].Count++
			}
			return
		}
		summary.UniqueTargetCount++
		if len(summary.Sample) >= sampleLimit {
			summary.SampleTruncated = true
			states[target] = sampleState{index: -1}
			return
		}
		summary.Sample = append(summary.Sample, BlockedEgressEntry{
			Target:      target,
			Kind:        kind,
			FirstSeenAt: firstSeenAt.UTC(),
			Count:       1,
		})
		states[target] = sampleState{index: len(summary.Sample) - 1}
	}

	for _, event := range events {
		switch event.Kind {
		case telemetry.KindPolicyPointDecision:
			var point models.PolicyPointDecision
			if err := json.Unmarshal(event.Data, &point); err != nil {
				return nil, fmt.Errorf("decode point decision for blocked egress: %w", err)
			}
			if point.Decision != models.DecisionDeny || point.EventType != models.EventNetConnect {
				continue
			}
			target, kind, ok := blockedConnectTarget(point, connectEvents[point.EventSeq])
			if !ok {
				continue
			}
			addSample(target, kind, blockedEventTime(event, connectEvents[point.EventSeq]))
		case telemetry.KindDNSQuery:
			var dns telemetry.DNSQueryData
			if err := json.Unmarshal(event.Data, &dns); err != nil {
				return nil, fmt.Errorf("decode dns query for blocked egress: %w", err)
			}
			if !strings.EqualFold(strings.TrimSpace(dns.Action), "deny") {
				continue
			}
			domain := strings.TrimSpace(dns.Domain)
			if domain == "" {
				continue
			}
			addSample("dns:"+domain, "fqdn", blockedEventTime(event, models.RuntimeEvent{}))
		}
	}

	return summary, nil
}

func blockedEventTime(event telemetry.Event, runtimeEvent models.RuntimeEvent) time.Time {
	if runtimeEvent.TsUnixNano > 0 {
		return time.Unix(0, runtimeEvent.TsUnixNano).UTC()
	}
	if event.Timestamp > 0 {
		return time.UnixMilli(event.Timestamp).UTC()
	}
	return time.UnixMilli(0).UTC()
}

func blockedConnectTarget(point models.PolicyPointDecision, runtimeEvent models.RuntimeEvent) (string, string, bool) {
	dstIP := strings.TrimSpace(runtimeEvent.DstIP)
	if dstIP == "" {
		dstIP = strings.TrimSpace(point.Metadata["dst_ip"])
	}
	if dstIP == "" {
		return "", "", false
	}
	if cidr, ok := blockedHardDenyCIDR(dstIP); ok {
		return "tcp://" + cidr, "rfc1918", true
	}
	port := runtimeEvent.DstPort
	if port == 0 {
		if raw := strings.TrimSpace(point.Metadata["dst_port"]); raw != "" {
			if parsed, err := strconv.ParseUint(raw, 10, 16); err == nil {
				port = uint16(parsed)
			}
		}
	}
	return fmt.Sprintf("tcp://%s:%d", dstIP, port), "ip", true
}

func blockedHardDenyCIDR(target string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return "", false
	}
	switch {
	case netip.MustParsePrefix("10.0.0.0/8").Contains(addr):
		return "10.0.0.0/8", true
	case netip.MustParsePrefix("172.16.0.0/12").Contains(addr):
		return "172.16.0.0/12", true
	case netip.MustParsePrefix("192.168.0.0/16").Contains(addr):
		return "192.168.0.0/16", true
	case addr == netip.MustParseAddr("169.254.169.254"):
		return "169.254.169.254/32", true
	default:
		return "", false
	}
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

func cloneApprovalCheck(src *approval.Check) *approval.Check {
	if src == nil {
		return nil
	}
	cloned := *src
	return &cloned
}

func cloneLeaseCheck(src *lease.Check) *lease.Check {
	if src == nil {
		return nil
	}
	cloned := *src
	if src.RemainingCount != nil {
		value := *src.RemainingCount
		cloned.RemainingCount = &value
	}
	return &cloned
}

func cloneEscalationEvidence(src *escalation.Evidence) *escalation.Evidence {
	if src == nil {
		return nil
	}
	return &escalation.Evidence{Signals: append([]escalation.Signal(nil), src.Signals...)}
}

func cloneHostActionEvidence(src *hostaction.Evidence) *hostaction.Evidence {
	if src == nil {
		return nil
	}
	cloned := &hostaction.Evidence{
		Class: src.Class,
	}
	if src.RepoApplyPatch != nil {
		cloned.RepoApplyPatch = &hostaction.RepoApplyPatchEvidence{
			RepoLabel:       src.RepoApplyPatch.RepoLabel,
			TargetScope:     append([]string(nil), src.RepoApplyPatch.TargetScope...),
			AffectedPaths:   append([]string(nil), src.RepoApplyPatch.AffectedPaths...),
			PatchDigest:     src.RepoApplyPatch.PatchDigest,
			PatchDigestAlgo: src.RepoApplyPatch.PatchDigestAlgo,
			BaseRevision:    src.RepoApplyPatch.BaseRevision,
		}
	}
	return cloned
}

func cloneEscalationSamples(samples []escalation.Sample) []escalation.Sample {
	if len(samples) == 0 {
		return nil
	}
	cloned := make([]escalation.Sample, 0, len(samples))
	for _, sample := range samples {
		cloned = append(cloned, escalation.Sample{
			Count:            sample.Count,
			Source:           sample.Source,
			Signals:          append([]escalation.Signal(nil), sample.Signals...),
			RuleID:           sample.RuleID,
			ActionType:       sample.ActionType,
			CapabilityPath:   sample.CapabilityPath,
			Target:           sample.Target,
			Resource:         sample.Resource,
			HostActionClass:  sample.HostActionClass,
			MutationField:    sample.MutationField,
			EnforcementPoint: sample.EnforcementPoint,
		})
	}
	return cloned
}

func receiptAuditPayload(src map[string]string) map[string]string {
	cloned := cloneStringMap(src)
	if len(cloned) == 0 {
		return cloned
	}
	for _, key := range []string{"repo_root", "path", "old_path", "new_path"} {
		delete(cloned, key)
	}
	if rawURL := strings.TrimSpace(cloned["resource_url"]); rawURL != "" {
		delete(cloned, "resource_url")
		if publicURL, err := approval.PublicHTTPURLForDisplay(rawURL); err == nil {
			cloned["resource_url_scheme"] = publicURL.Scheme
			cloned["resource_url_host"] = publicURL.Host
			cloned["resource_url_path"] = publicURL.Path
			if publicURL.QueryPresent {
				cloned["resource_url_query_present"] = "true"
				cloned["resource_url_query_key_count"] = strconv.Itoa(publicURL.QueryKeyCount)
			}
		}
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func buildRuntimePolicySummary(governedSummary *GovernedActionSummary, authority *AuthorityEnvelope, outcomeReason string) *escalation.RuntimePolicyEnvelope {
	attempts := make([]escalation.Attempt, 0)
	if governedSummary != nil {
		for _, action := range governedSummary.Actions {
			if action.Escalation == nil || len(action.Escalation.Signals) == 0 {
				continue
			}
			attempts = append(attempts, escalation.Attempt{
				Source:          escalation.SourceGovernedAction,
				Signals:         append([]escalation.Signal(nil), action.Escalation.Signals...),
				RuleID:          strings.TrimSpace(action.RuleID),
				ActionType:      strings.TrimSpace(action.ActionType),
				CapabilityPath:  strings.TrimSpace(action.CapabilityPath),
				Target:          strings.TrimSpace(action.Target),
				Resource:        strings.TrimSpace(action.Resource),
				HostActionClass: runtimePolicyHostActionClass(action),
			})
		}
	}
	if authority != nil && authority.MutationAttempt != nil {
		attempts = append(attempts, escalation.Attempt{
			Source:           escalation.SourceAuthorityMutation,
			Signals:          []escalation.Signal{escalation.SignalAuthorityBroadeningAttempt},
			MutationField:    strings.TrimSpace(authority.MutationAttempt.Field),
			EnforcementPoint: strings.TrimSpace(authority.MutationAttempt.EnforcementPoint),
		})
	}
	return escalation.Summarize(attempts, outcomeReason)
}

func runtimePolicyHostActionClass(action GovernedActionRecord) string {
	if action.HostAction != nil {
		return escalation.PublicHostActionClass(string(action.HostAction.Class))
	}
	return escalation.PublicHostActionClass(action.AuditPayload["host_action_class"])
}

func pae(payloadType string, payload []byte) []byte {
	return dsse.PAE(payloadType, payload)
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

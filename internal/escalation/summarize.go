package escalation

import (
	"sort"
	"strings"
)

const terminationReasonAuthorityMutation = "security_denied_authority_mutation"

func Summarize(attempts []Attempt, outcomeReason string) *RuntimePolicyEnvelope {
	escalationAttempts := make([]Attempt, 0, len(attempts))
	deniedClasses := map[DestructiveActionClass]struct{}{}
	for _, attempt := range attempts {
		normalizedSignals := normalizeAttemptSignals(attempt.Signals)
		if len(normalizedSignals) == 0 {
			continue
		}
		attempt.Signals = normalizedSignals
		escalationAttempts = append(escalationAttempts, attempt)
		if class, ok := destructiveActionForAttempt(attempt); ok {
			deniedClasses[class] = struct{}{}
		}
	}

	if len(escalationAttempts) == 0 {
		return nil
	}

	summary := &RuntimePolicyEnvelope{
		EscalationAttempts: summarizeAttempts(escalationAttempts),
	}
	if len(deniedClasses) > 0 {
		classes := make([]DestructiveActionClass, 0, len(deniedClasses))
		for class := range deniedClasses {
			classes = append(classes, class)
		}
		sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
		summary.DeniedDestructiveActions = classes
	}

	reason := strings.TrimSpace(outcomeReason)
	switch reason {
	case terminationReasonAuthorityMutation:
		if hasAuthorityMutationAttempt(escalationAttempts) {
			summary.TerminationReason = reason
		}
	case TerminationReasonPrivilegeEscalation:
		if hasTerminalGovernedAttempt(escalationAttempts) {
			summary.TerminationReason = reason
		}
	}

	return summary
}

func summarizeAttempts(attempts []Attempt) *Summary {
	aggregated := make(map[string]Sample, len(attempts))
	order := make([]string, 0, len(attempts))
	total := 0
	for _, attempt := range attempts {
		total++
		sample := Sample{
			Count:            1,
			Source:           attempt.Source,
			Signals:          append([]Signal(nil), attempt.Signals...),
			RuleID:           strings.TrimSpace(attempt.RuleID),
			ActionType:       strings.TrimSpace(attempt.ActionType),
			CapabilityPath:   strings.TrimSpace(attempt.CapabilityPath),
			Target:           strings.TrimSpace(attempt.Target),
			Resource:         strings.TrimSpace(attempt.Resource),
			HostActionClass:  PublicHostActionClass(attempt.HostActionClass),
			MutationField:    strings.TrimSpace(attempt.MutationField),
			EnforcementPoint: strings.TrimSpace(attempt.EnforcementPoint),
		}
		key := sampleSortKey(sample)
		if existing, ok := aggregated[key]; ok {
			existing.Count++
			aggregated[key] = existing
			continue
		}
		aggregated[key] = sample
		order = append(order, key)
	}

	sort.Strings(order)
	samples := make([]Sample, 0, len(order))
	for _, key := range order {
		samples = append(samples, aggregated[key])
	}
	truncated := len(samples) > SampleLimit
	if truncated {
		samples = samples[:SampleLimit]
	}
	return &Summary{
		Count:           total,
		Sample:          samples,
		SampleTruncated: truncated,
	}
}

func sampleSortKey(sample Sample) string {
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

func normalizeAttemptSignals(signals []Signal) []Signal {
	seen := make(map[Signal]struct{}, len(signals))
	normalized := make([]Signal, 0, len(signals))
	for _, signal := range signals {
		if !IsValidSignal(signal) {
			continue
		}
		if _, ok := seen[signal]; ok {
			continue
		}
		seen[signal] = struct{}{}
		normalized = append(normalized, signal)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i] < normalized[j]
	})
	return normalized
}

func destructiveActionForAttempt(attempt Attempt) (DestructiveActionClass, bool) {
	if class, ok := MapHostActionClass(attempt.HostActionClass); ok {
		return class, true
	}
	if strings.TrimSpace(attempt.ActionType) == string(DestructiveActionHostRepoApplyPatch) {
		return DestructiveActionHostRepoApplyPatch, true
	}
	return "", false
}

func hasAuthorityMutationAttempt(attempts []Attempt) bool {
	for _, attempt := range attempts {
		if attempt.Source == SourceAuthorityMutation {
			return true
		}
	}
	return false
}

func hasTerminalGovernedAttempt(attempts []Attempt) bool {
	for _, attempt := range attempts {
		if attempt.Source != SourceGovernedAction {
			continue
		}
		if hasTerminalSignal(attempt.Signals) {
			return true
		}
	}
	return false
}

func hasTerminalSignal(signals []Signal) bool {
	for _, signal := range signals {
		switch signal {
		case SignalAuthorityBroadeningAttempt, SignalUnsupportedDestructiveClassAccess, SignalRepeatedProbingPattern:
			return true
		}
	}
	return false
}

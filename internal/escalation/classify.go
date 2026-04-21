package escalation

import (
	"sort"
	"strings"
	"sync"
)

const (
	actionHTTPRequest   = "http_request"
	actionHostRepoApply = "host_repo_apply_patch"
)

type Tracker struct {
	mu                     sync.Mutex
	probeCandidateCount    int
	probeFingerprints      map[string]int
	unsupportedClassCounts map[DestructiveActionClass]int
}

func NewTracker() *Tracker {
	return &Tracker{
		probeFingerprints:      make(map[string]int),
		unsupportedClassCounts: make(map[DestructiveActionClass]int),
	}
}

func (t *Tracker) Classify(observation Observation) *Evidence {
	if !strings.EqualFold(strings.TrimSpace(observation.Decision), "deny") {
		return nil
	}
	signals := classifyBaseSignals(observation)
	if repeated := t.markRepeatedProbe(observation); repeated {
		signals = append(signals, SignalRepeatedProbingPattern)
	}
	return normalizeEvidence(signals)
}

func classifyBaseSignals(observation Observation) []Signal {
	ruleID := strings.TrimSpace(observation.RuleID)
	actionType := strings.TrimSpace(observation.ActionType)
	switch {
	case ruleID == "governance.action_type_denied":
		return []Signal{SignalAuthorityBroadeningAttempt}
	case ruleID == "broker.lease_action_kind_unsupported":
		return []Signal{SignalAuthorityBroadeningAttempt}
	case ruleID == "broker.host_action_unsupported":
		return []Signal{SignalUnsupportedDestructiveClassAccess}
	case ruleID == "broker.host_action_path_escape":
		return []Signal{SignalDestructiveBoundaryProbe}
	case ruleID == "broker.host_action_symlink_escape":
		return []Signal{SignalDestructiveBoundaryProbe}
	case ruleID == "broker.repo_label_denied" && actionType == actionHostRepoApply:
		return []Signal{SignalAuthorityBroadeningAttempt, SignalDestructiveBoundaryProbe}
	case ruleID == "broker.lease_resource_mismatch" && actionType == actionHostRepoApply:
		return []Signal{SignalAuthorityBroadeningAttempt, SignalDestructiveBoundaryProbe}
	case strings.HasPrefix(ruleID, "broker.approval_ticket_") &&
		ruleID != "broker.approval_ticket_unavailable" &&
		actionType == actionHostRepoApply:
		return []Signal{SignalDestructiveBoundaryProbe}
	default:
		return nil
	}
}

func (t *Tracker) markRepeatedProbe(observation Observation) bool {
	if t == nil {
		return false
	}
	fingerprint, sameUnsupportedClass, ok := probeCandidateFingerprint(observation)
	if !ok {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.probeCandidateCount++
	t.probeFingerprints[fingerprint]++
	sameUnsupportedCount := 0
	if sameUnsupportedClass != "" {
		t.unsupportedClassCounts[sameUnsupportedClass]++
		sameUnsupportedCount = t.unsupportedClassCounts[sameUnsupportedClass]
	}
	return (t.probeCandidateCount >= 3 && len(t.probeFingerprints) >= 2) || sameUnsupportedCount >= 3
}

func probeCandidateFingerprint(observation Observation) (string, DestructiveActionClass, bool) {
	ruleID := strings.TrimSpace(observation.RuleID)
	actionType := strings.TrimSpace(observation.ActionType)
	hostActionClass, _ := MapHostActionClass(observation.HostActionClass)

	switch {
	case ruleID == "broker.domain_denied":
	case ruleID == "governance.direct_egress_disabled":
	case ruleID == "governance.direct_egress_target_denied":
	case ruleID == "governance.direct_egress_denied":
	case ruleID == "broker.lease_resource_mismatch" && actionType == actionHTTPRequest:
	case ruleID == "governance.action_type_denied":
	case ruleID == "broker.lease_action_kind_unsupported":
	case ruleID == "broker.host_action_unsupported":
	default:
		return "", "", false
	}

	fingerprint := strings.Join([]string{
		strings.TrimSpace(observation.CapabilityPath),
		ruleID,
		actionType,
		strings.TrimSpace(observation.Target),
		strings.TrimSpace(observation.Resource),
		PublicHostActionClass(observation.HostActionClass),
	}, "|")
	if ruleID == "broker.host_action_unsupported" {
		return fingerprint, hostActionClass, true
	}
	return fingerprint, "", true
}

func normalizeEvidence(signals []Signal) *Evidence {
	if len(signals) == 0 {
		return nil
	}
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
	if len(normalized) == 0 {
		return nil
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i] < normalized[j]
	})
	return &Evidence{Signals: normalized}
}

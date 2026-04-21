package escalation

import "strings"

const (
	TerminationReasonPrivilegeEscalation = "privilege_escalation_attempt"
	SampleLimit                          = 10
)

type Signal string

const (
	SignalAuthorityBroadeningAttempt        Signal = "authority_broadening_attempt"
	SignalDestructiveBoundaryProbe          Signal = "destructive_boundary_probe"
	SignalUnsupportedDestructiveClassAccess Signal = "unsupported_destructive_class_access"
	SignalRepeatedProbingPattern            Signal = "repeated_probing_pattern"
)

type SourceKind string

const (
	SourceGovernedAction    SourceKind = "governed_action"
	SourceAuthorityMutation SourceKind = "authority_mutation"
)

type DestructiveActionClass string

const (
	DestructiveActionHostRepoApplyPatch DestructiveActionClass = "host_repo_apply_patch"
	DestructiveActionHostFileDelete     DestructiveActionClass = "host_file_delete"
	DestructiveActionHostConfigMove     DestructiveActionClass = "host_config_move"
	DestructiveActionHostPackageManager DestructiveActionClass = "host_package_manager"
	DestructiveActionHostDockerSocket   DestructiveActionClass = "host_docker_socket"
	DestructiveActionHostSystemResource DestructiveActionClass = "host_system_resource"
)

type Evidence struct {
	Signals []Signal `json:"signals"`
}

type Summary struct {
	Count           int      `json:"count"`
	Sample          []Sample `json:"sample,omitempty"`
	SampleTruncated bool     `json:"sample_truncated,omitempty"`
}

type Sample struct {
	Count            int        `json:"count"`
	Source           SourceKind `json:"source"`
	Signals          []Signal   `json:"signals"`
	RuleID           string     `json:"rule_id,omitempty"`
	ActionType       string     `json:"action_type,omitempty"`
	CapabilityPath   string     `json:"capability_path,omitempty"`
	Target           string     `json:"target,omitempty"`
	Resource         string     `json:"resource,omitempty"`
	HostActionClass  string     `json:"host_action_class,omitempty"`
	MutationField    string     `json:"mutation_field,omitempty"`
	EnforcementPoint string     `json:"enforcement_point,omitempty"`
}

type RuntimePolicyEnvelope struct {
	EscalationAttempts       *Summary                 `json:"escalation_attempts,omitempty"`
	DeniedDestructiveActions []DestructiveActionClass `json:"denied_destructive_actions,omitempty"`
	TerminationReason        string                   `json:"termination_reason,omitempty"`
}

type Observation struct {
	ActionType      string
	CapabilityPath  string
	Decision        string
	RuleID          string
	Target          string
	Resource        string
	HostActionClass string
}

type Attempt struct {
	Source           SourceKind
	Signals          []Signal
	RuleID           string
	ActionType       string
	CapabilityPath   string
	Target           string
	Resource         string
	HostActionClass  string
	MutationField    string
	EnforcementPoint string
}

func IsValidSignal(value Signal) bool {
	switch value {
	case SignalAuthorityBroadeningAttempt,
		SignalDestructiveBoundaryProbe,
		SignalUnsupportedDestructiveClassAccess,
		SignalRepeatedProbingPattern:
		return true
	default:
		return false
	}
}

func IsValidSourceKind(value SourceKind) bool {
	switch value {
	case SourceGovernedAction, SourceAuthorityMutation:
		return true
	default:
		return false
	}
}

func IsValidDestructiveActionClass(value DestructiveActionClass) bool {
	switch value {
	case DestructiveActionHostRepoApplyPatch,
		DestructiveActionHostFileDelete,
		DestructiveActionHostConfigMove,
		DestructiveActionHostPackageManager,
		DestructiveActionHostDockerSocket,
		DestructiveActionHostSystemResource:
		return true
	default:
		return false
	}
}

func PublicHostActionClass(raw string) string {
	class, ok := MapHostActionClass(raw)
	if !ok {
		return ""
	}
	return string(class)
}

func MapHostActionClass(raw string) (DestructiveActionClass, bool) {
	switch strings.TrimSpace(raw) {
	case string(DestructiveActionHostRepoApplyPatch), "repo_apply_patch_v1":
		return DestructiveActionHostRepoApplyPatch, true
	case string(DestructiveActionHostFileDelete), "host_file_delete_v1":
		return DestructiveActionHostFileDelete, true
	case string(DestructiveActionHostConfigMove), "host_config_move_v1":
		return DestructiveActionHostConfigMove, true
	case string(DestructiveActionHostPackageManager), "host_package_manager_v1":
		return DestructiveActionHostPackageManager, true
	case string(DestructiveActionHostDockerSocket), "host_docker_socket_v1":
		return DestructiveActionHostDockerSocket, true
	case string(DestructiveActionHostSystemResource), "host_system_resource_v1":
		return DestructiveActionHostSystemResource, true
	default:
		return "", false
	}
}

func HasSignal(evidence *Evidence, signal Signal) bool {
	if evidence == nil {
		return false
	}
	for _, candidate := range evidence.Signals {
		if candidate == signal {
			return true
		}
	}
	return false
}

func IsTerminalEvidence(evidence *Evidence) bool {
	return HasSignal(evidence, SignalAuthorityBroadeningAttempt) ||
		HasSignal(evidence, SignalUnsupportedDestructiveClassAccess) ||
		HasSignal(evidence, SignalRepeatedProbingPattern)
}

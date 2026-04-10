package models

import "time"

type DivergenceVerdict string

const (
	DivergenceAllow         DivergenceVerdict = "allow"
	DivergenceWarn          DivergenceVerdict = "warn"
	DivergenceKillCandidate DivergenceVerdict = "kill_candidate"
)

type DivergenceSeverity string

const (
	DivergenceSeverityWarn          DivergenceSeverity = "warn"
	DivergenceSeverityKillCandidate DivergenceSeverity = "kill_candidate"
)

type DivergenceRuleHit struct {
	RuleID   string             `json:"rule_id"`
	Category string             `json:"category"`
	Severity DivergenceSeverity `json:"severity"`
	Message  string             `json:"message"`
	EventSeq uint64             `json:"event_seq"`
	Metadata map[string]string  `json:"metadata,omitempty"`
}

type DivergenceCounters struct {
	ExecCount                  int `json:"exec_count"`
	ForkCount                  int `json:"fork_count"`
	ExitCount                  int `json:"exit_count"`
	FileOpenCount              int `json:"file_open_count"`
	FileReadCount              int `json:"file_read_count"`
	FileWriteIntentCount       int `json:"file_write_intent_count"`
	ConnectCount               int `json:"connect_count"`
	DistinctBinaryCount        int `json:"distinct_binary_count"`
	DistinctPathCount          int `json:"distinct_path_count"`
	DistinctConnectDestCount   int `json:"distinct_connect_dest_count"`
	ChildProcessCount          int `json:"child_process_count"`
	ShellExecCount             int `json:"shell_exec_count"`
	PackageInstallCount        int `json:"package_install_count"`
	DeniedFileOpenCount        int `json:"denied_file_open_count"`
	DeniedWriteIntentCount     int `json:"denied_write_intent_count"`
	DeniedConnectCount         int `json:"denied_connect_count"`
	AllowDecisionCount         int `json:"allow_decision_count"`
	DenyDecisionCount          int `json:"deny_decision_count"`
	NotApplicableDecisionCount int `json:"not_applicable_decision_count"`
	BrokerRequestCount         int `json:"broker_request_count,omitempty"`
	BrokerDeniedCount          int `json:"broker_denied_count,omitempty"`
}

type PolicyDivergenceResult struct {
	ExecutionID    string              `json:"execution_id"`
	Backend        RuntimeBackend      `json:"backend"`
	StartedAt      time.Time           `json:"started_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
	LastSeq        uint64              `json:"last_seq"`
	CurrentVerdict DivergenceVerdict   `json:"current_verdict"`
	TriggeredRules []DivergenceRuleHit `json:"triggered_rules"`
	Reasons        []string            `json:"reasons"`
	Counters       DivergenceCounters  `json:"counters"`
	Metadata       map[string]string   `json:"metadata,omitempty"`
}

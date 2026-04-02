package models

import "encoding/json"

type Payload struct {
	Lang               string `json:"lang"`
	Code               string `json:"code"`
	TimeoutMs          int    `json:"timeout_ms"`
	PidsLimit          int    `json:"pids_limit,omitempty"`
	WorkspaceRequested bool   `json:"workspace_requested,omitempty"`
	NetworkRequested   bool   `json:"network_requested,omitempty"`
	GuestIP            string `json:"guest_ip,omitempty"`
	GatewayIP          string `json:"gateway_ip,omitempty"`
	DNSServer          string `json:"dns_server,omitempty"`
}

type GuestChunk struct {
	Type       string          `json:"type"`
	Name       string          `json:"name,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Chunk      string          `json:"chunk,omitempty"`
	ExitCode   int             `json:"exit_code,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	DurationMs int64           `json:"duration_ms,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	ExitReason      string `json:"exit_reason,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	StdoutBytes     int    `json:"stdout_bytes"`
	StderrBytes     int    `json:"stderr_bytes"`
}

// ContainmentReceipt is the final summary of an execution's containment state.
type ContainmentReceipt struct {
	ExecID     string         `json:"exec_id"`
	StartedAt  string         `json:"started_at"`
	EndedAt    string         `json:"ended_at"`
	DurationMs int64          `json:"duration_ms"`
	Language   string         `json:"language"`
	Policy     ReceiptPolicy  `json:"policy"`
	Network    ReceiptNetwork `json:"network"`
	Exit       ReceiptExit    `json:"exit"`
	Cleanup    ReceiptCleanup `json:"cleanup"`
	Verdict    string         `json:"verdict"`
}

// ReceiptPolicy captures the policy context used for an execution.
type ReceiptPolicy struct {
	Version        string              `json:"version"`
	Profile        string              `json:"profile,omitempty"`
	NetworkMode    string              `json:"network_mode"`
	AllowedDomains []string            `json:"allowed_domains,omitempty"`
	CgroupLimits   ReceiptCgroupLimits `json:"cgroup_limits"`
}

// ReceiptCgroupLimits captures the configured cgroup constraints.
type ReceiptCgroupLimits struct {
	MemoryMax string `json:"memory_max"`
	PidsMax   string `json:"pids_max"`
	CpuQuota  string `json:"cpu_quota"`
	Swap      string `json:"swap"`
}

// ReceiptExit captures the final execution exit state.
type ReceiptExit struct {
	Code            int    `json:"code"`
	Reason          string `json:"reason"`
	OutputTruncated bool   `json:"output_truncated"`
}

// ReceiptCleanup captures teardown results.
type ReceiptCleanup struct {
	TapRemoved     bool `json:"tap_removed"`
	CgroupRemoved  bool `json:"cgroup_removed"`
	ScratchRemoved bool `json:"scratch_removed"`
	SocketRemoved  bool `json:"socket_removed"`
	AllClean       bool `json:"all_clean"`
}

// ReceiptNetwork summarizes network containment decisions observed during execution.
type ReceiptNetwork struct {
	DNSQueriesTotal    int      `json:"dns_queries_total"`
	DNSQueriesAllowed  int      `json:"dns_queries_allowed"`
	DNSQueriesDenied   int      `json:"dns_queries_denied"`
	IptablesRulesAdded int      `json:"iptables_rules_added"`
	NetworkMode        string   `json:"network_mode"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
}

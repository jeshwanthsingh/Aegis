package telemetry

import "encoding/json"

type Event struct {
	ExecID    string          `json:"exec_id"`
	Timestamp int64           `json:"ts"`
	Kind      string          `json:"kind"`
	Data      json.RawMessage `json:"data"`
}

const (
	KindVMBootStart         = "vm.boot.start"
	KindVMBootReady         = "vm.boot.ready"
	KindCgroupConfigured    = "cgroup.configured"
	KindCgroupSample        = "cgroup.sample"
	KindDNSQuery            = "dns.query"
	KindNetRuleAdd          = "net.rule.add"
	KindNetRuleDrop         = "net.rule.drop"
	KindGuestProcSample     = "guest.proc.sample"
	KindRuntimeEvent        = "runtime.event.v1"
	KindPolicyPointDecision = "policy.point.decision"
	KindPolicyDivergence    = "policy.divergence.v1"
	KindPolicyEnforcement   = "policy.enforcement.v1"
	KindRuntimeSensorStatus = "runtime.sensor.status"
	KindExecStdout          = "exec.stdout"
	KindExecStderr          = "exec.stderr"
	KindExecExit            = "exec.exit"
	KindCleanupStart        = "cleanup.start"
	KindCleanupDone         = "cleanup.done"
	KindReceipt             = "containment.receipt"
	KindCredentialRequest   = "credential.request"
	KindCredentialAllowed   = "credential.allowed"
	KindCredentialDenied    = "credential.denied"
	KindCredentialError     = "credential.error"
	KindGovernedAction      = "governed.action.v1"
)

type CgroupConfiguredData struct {
	MemoryMax  string `json:"memory_max"`
	MemoryHigh string `json:"memory_high"`
	PidsMax    string `json:"pids_max"`
	CpuMax     string `json:"cpu_max"`
	SwapMax    string `json:"swap_max"`
}

type CgroupSampleData struct {
	MemoryCurrent int64   `json:"memory_current"`
	MemoryMax     int64   `json:"memory_max"`
	PidsCurrent   int64   `json:"pids_current"`
	PidsMax       int64   `json:"pids_max"`
	MemoryPct     float64 `json:"memory_pct"`
	PidsPct       float64 `json:"pids_pct"`
}

type GuestProcSampleData struct {
	PidsCurrent int `json:"pids_current"`
	PidsLimit   int `json:"pids_limit"`
	PidsPct     int `json:"pids_pct"`
}

type RuntimeSensorStatusData struct {
	DroppedEvents uint64 `json:"dropped_events"`
	FloodDetected bool   `json:"flood_detected"`
	QueueCapacity int    `json:"queue_capacity,omitempty"`
	BatchEvents   int    `json:"batch_events,omitempty"`
	Source        string `json:"source,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type DNSQueryData struct {
	Domain   string   `json:"domain"`
	Action   string   `json:"action"`
	Resolved []string `json:"resolved,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

type NetRuleData struct {
	Rule      string `json:"rule"`
	Chain     string `json:"chain,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Ports     string `json:"ports,omitempty"`
	Direction string `json:"direction,omitempty"`
}

type ExecExitData struct {
	ExitCode int    `json:"exit_code"`
	Reason   string `json:"reason,omitempty"`
}

type PolicyEnforcementData struct {
	ExecutionID string `json:"execution_id"`
	Seq         uint64 `json:"seq"`
	Verdict     string `json:"verdict"`
	Action      string `json:"action"`
	RuleID      string `json:"rule_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type CleanupDoneData struct {
	TapRemoved     bool `json:"tap_removed"`
	CgroupRemoved  bool `json:"cgroup_removed"`
	ScratchRemoved bool `json:"scratch_removed"`
	SocketRemoved  bool `json:"socket_removed"`
	AllClean       bool `json:"all_clean"`
}

type CredentialBrokerData struct {
	ExecutionID  string `json:"execution_id"`
	BindingName  string `json:"binding_name,omitempty"`
	TargetDomain string `json:"target_domain"`
	Method       string `json:"method"`
	ActionType   string `json:"action_type"`
	Outcome      string `json:"outcome"`
	DenialReason string `json:"denial_reason,omitempty"`
}

type GovernedActionData struct {
	ExecutionID         string            `json:"execution_id"`
	ActionType          string            `json:"action_type"`
	Target              string            `json:"target"`
	Resource            string            `json:"resource,omitempty"`
	Method              string            `json:"method,omitempty"`
	Decision            string            `json:"decision"`
	Outcome             string            `json:"outcome,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	RuleID              string            `json:"rule_id,omitempty"`
	PolicyDigest        string            `json:"policy_digest,omitempty"`
	Brokered            bool              `json:"brokered"`
	BrokeredCredentials bool              `json:"brokered_credentials"`
	BindingName         string            `json:"binding_name,omitempty"`
	ResponseDigest      string            `json:"response_digest,omitempty"`
	ResponseDigestAlgo  string            `json:"response_digest_algo,omitempty"`
	DenialMarker        string            `json:"denial_marker,omitempty"`
	AuditPayload        map[string]string `json:"audit_payload,omitempty"`
	Error               string            `json:"error,omitempty"`
	CapabilityPath      string            `json:"capability_path,omitempty"`
	Used                bool              `json:"used"`
}

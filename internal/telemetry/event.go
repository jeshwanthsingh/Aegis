package telemetry

import "encoding/json"

// Event represents a single telemetry event emitted during execution.
type Event struct {
	ExecID    string          `json:"exec_id"`
	Timestamp int64           `json:"ts"`
	Kind      string          `json:"kind"`
	Data      json.RawMessage `json:"data"`
}

// Telemetry event kinds emitted by the execution pipeline.
const (
	KindVMBootStart      = "vm.boot.start"
	KindVMBootReady      = "vm.boot.ready"
	KindCgroupConfigured = "cgroup.configured"
	KindCgroupSample     = "cgroup.sample"
	KindDNSQuery         = "dns.query"
	KindNetRuleAdd       = "net.rule.add"
	KindNetRuleDrop      = "net.rule.drop"
	KindGuestProcSample  = "guest.proc.sample"
	KindExecStdout       = "exec.stdout"
	KindExecStderr       = "exec.stderr"
	KindExecExit         = "exec.exit"
	KindCleanupStart     = "cleanup.start"
	KindCleanupDone      = "cleanup.done"
	KindReceipt          = "containment.receipt"
)

// CgroupConfiguredData describes the configured cgroup limits for an execution.
type CgroupConfiguredData struct {
	MemoryMax  string `json:"memory_max"`
	MemoryHigh string `json:"memory_high"`
	PidsMax    string `json:"pids_max"`
	CpuMax     string `json:"cpu_max"`
	SwapMax    string `json:"swap_max"`
}

// CgroupSampleData captures a sampled view of host-side Firecracker cgroup usage.
// PidsCurrent/PidsMax reflect the VM process on the host, not guest process count.
type CgroupSampleData struct {
	MemoryCurrent int64   `json:"memory_current"`
	MemoryMax     int64   `json:"memory_max"`
	PidsCurrent   int64   `json:"pids_current"`
	PidsMax       int64   `json:"pids_max"`
	MemoryPct     float64 `json:"memory_pct"`
	PidsPct       float64 `json:"pids_pct"`
}

// GuestProcSampleData captures guest-side process tree pressure.
type GuestProcSampleData struct {
	PidsCurrent int `json:"pids_current"`
	PidsLimit   int `json:"pids_limit"`
	PidsPct     int `json:"pids_pct"`
}

// DNSQueryData describes an allowlist DNS decision.
type DNSQueryData struct {
	Domain   string   `json:"domain"`
	Action   string   `json:"action"`
	Resolved []string `json:"resolved,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// NetRuleData describes an emitted network rule action.
type NetRuleData struct {
	Rule      string `json:"rule"`
	Chain     string `json:"chain,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Ports     string `json:"ports,omitempty"`
	Direction string `json:"direction,omitempty"`
}

// ExecExitData describes the final execution exit state.
type ExecExitData struct {
	ExitCode int    `json:"exit_code"`
	Reason   string `json:"reason,omitempty"`
}

// CleanupDoneData describes teardown cleanup results.
type CleanupDoneData struct {
	TapRemoved     bool `json:"tap_removed"`
	CgroupRemoved  bool `json:"cgroup_removed"`
	ScratchRemoved bool `json:"scratch_removed"`
	SocketRemoved  bool `json:"socket_removed"`
	AllClean       bool `json:"all_clean"`
}

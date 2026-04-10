package models

import "strings"

type RuntimeBackend string

const (
	BackendFirecracker RuntimeBackend = "firecracker"
	BackendGVisor      RuntimeBackend = "gvisor"
)

type EventType string

const (
	EventProcessExec     EventType = "process.exec"
	EventProcessFork     EventType = "process.fork"
	EventProcessExit     EventType = "process.exit"
	EventFileOpen        EventType = "file.open"
	EventFileDelete      EventType = "file.delete"
	EventNetConnect      EventType = "net.connect"
	EventDNSQuery        EventType = "dns.query"
	EventBrokerRequest   EventType = "broker.request"
	EventBrokerResult    EventType = "broker.result"
	EventBudgetHit       EventType = "budget.hit"
	EventPolicyViolation EventType = "policy.violation"
	EventCleanupDone     EventType = "cleanup.done"
)

// RuntimeEvent is the normalized Phase 2 execution event emitted by Aegis.
type RuntimeEvent struct {
	ExecutionID      string            `json:"execution_id"`
	Backend          RuntimeBackend    `json:"backend"`
	Seq              uint64            `json:"seq"`
	TsUnixNano       int64             `json:"ts_unix_nano"`
	DroppedSinceLast uint32            `json:"dropped_since_last"`
	Type             EventType         `json:"type"`
	PID              int               `json:"pid"`
	PPID             int               `json:"ppid"`
	Comm             string            `json:"comm"`
	Exe              string            `json:"exe"`
	Path             string            `json:"path"`
	Flags            uint64            `json:"flags"`
	DstIP            string            `json:"dst_ip"`
	DstPort          uint16            `json:"dst_port"`
	Domain           string            `json:"domain"`
	ExitCode         int               `json:"exit_code"`
	Metadata         map[string]string `json:"metadata"`
}

const (
	linuxOpenWriteOnly = 0x1
	linuxOpenReadWrite = 0x2
	linuxOpenCreate    = 0x40
	linuxOpenTruncate  = 0x200
	linuxOpenAppend    = 0x400
)

func FileOpenHasWriteIntent(flags uint64) bool {
	return flags&linuxOpenWriteOnly != 0 || flags&linuxOpenReadWrite != 0 || flags&linuxOpenCreate != 0 || flags&linuxOpenTruncate != 0 || flags&linuxOpenAppend != 0
}

func FileOpenHasDestructiveFlags(flags uint64) bool {
	return flags&linuxOpenCreate != 0 || flags&linuxOpenTruncate != 0 || flags&linuxOpenAppend != 0
}

func FileOpenAccessMode(flags uint64) string {
	if FileOpenHasWriteIntent(flags) {
		return "write-intent"
	}
	return "read-only"
}

func FileOpenFlagSummary(flags uint64) string {
	names := make([]string, 0, 5)
	if flags&linuxOpenWriteOnly != 0 {
		names = append(names, "O_WRONLY")
	}
	if flags&linuxOpenReadWrite != 0 {
		names = append(names, "O_RDWR")
	}
	if flags&linuxOpenCreate != 0 {
		names = append(names, "O_CREAT")
	}
	if flags&linuxOpenTruncate != 0 {
		names = append(names, "O_TRUNC")
	}
	if flags&linuxOpenAppend != 0 {
		names = append(names, "O_APPEND")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

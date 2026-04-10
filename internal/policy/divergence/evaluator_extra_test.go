package divergence

import (
	"testing"

	"aegis/internal/models"
)

func TestObserveBrokerDenialEscalatesKillCandidateAndTracksRule(t *testing.T) {
	intent := testIntent()
	intent.BrokerScope.AllowedDomains = []string{"api.example.com"}
	eval := New(intent)

	result := eval.ObserveBrokerDenial("api.example.com", "testtoken", "broker.domain_denied").Result
	assertRule(t, result, models.DivergenceWarn, "broker.request_denied")
	if result.Counters.BrokerDeniedCount != 1 {
		t.Fatalf("BrokerDeniedCount = %d", result.Counters.BrokerDeniedCount)
	}
}

func TestRepeatedDeniedFileOpenEscalatesWarn(t *testing.T) {
	eval := New(testIntent())
	var result models.PolicyDivergenceResult
	for seq := uint64(1); seq <= 3; seq++ {
		result = eval.Observe(
			models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: seq, TsUnixNano: int64(seq), Type: models.EventFileOpen, PID: 10, Path: "/workspace/.git/config"},
			point(models.EventFileOpen, seq, models.ActionRead, models.DecisionDeny, "path matches deny_paths"),
		).Result
	}
	assertRule(t, result, models.DivergenceWarn, "file.denied_repeated")
}

func TestShellSpawnDeniedEscalatesWarn(t *testing.T) {
	intent := testIntent()
	intent.ProcessScope.AllowShell = true
	eval := New(intent)
	eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
		point(models.EventProcessExec, 1, models.ActionExec, models.DecisionAllow, "allowed"),
	)
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventProcessExec, PID: 11, PPID: 10, Exe: "/usr/bin/ruby", Comm: "ruby"},
		point(models.EventProcessExec, 2, models.ActionExec, models.DecisionDeny, "binary is outside allowed_binaries"),
	).Result
	assertRule(t, result, models.DivergenceKillCandidate, "process.shell_spawn_denied")
}

func TestWriteDeniedEscalatesWarnForDenyPaths(t *testing.T) {
	eval := New(testIntent())
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventFileOpen, PID: 10, Path: "/workspace/.git/config", Flags: 0x241},
		point(models.EventFileOpen, 1, models.ActionWrite, models.DecisionDeny, "path matches deny_paths"),
	).Result
	assertRule(t, result, models.DivergenceKillCandidate, "file.write_denied")
}

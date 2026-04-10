package divergence

import (
	"testing"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

func TestCleanExecutionStaysAllow(t *testing.T) {
	eval := New(testIntent())
	events := []struct {
		event    models.RuntimeEvent
		decision *models.PolicyPointDecision
	}{
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/python3", Comm: "python3"}, point(models.EventProcessExec, 1, models.ActionExec, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventFileOpen, PID: 10, Path: "/workspace/report.pdf"}, point(models.EventFileOpen, 2, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 3, TsUnixNano: 3, Type: models.EventNetConnect, PID: 10, DstIP: "127.0.0.1", DstPort: 443}, point(models.EventNetConnect, 3, models.ActionConnect, models.DecisionAllow, "allowed")},
	}

	var result models.PolicyDivergenceResult
	for _, item := range events {
		result = eval.Observe(item.event, item.decision).Result
	}

	if result.CurrentVerdict != models.DivergenceAllow {
		t.Fatalf("CurrentVerdict = %q, want allow", result.CurrentVerdict)
	}
	if len(result.TriggeredRules) != 0 {
		t.Fatalf("unexpected rules: %+v", result.TriggeredRules)
	}
}

func TestShellDisallowedEscalatesKillCandidate(t *testing.T) {
	intent := testIntent()
	intent.ProcessScope.AllowShell = false
	eval := New(intent)
	outcome := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
		point(models.EventProcessExec, 1, models.ActionExec, models.DecisionDeny, "shell execution is not allowed"),
	)
	assertRule(t, outcome.Result, models.DivergenceKillCandidate, "process.shell_disallowed")
}

func TestPackageInstallDisallowedEscalatesKillCandidate(t *testing.T) {
	eval := New(testIntent())
	outcome := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/pip", Comm: "pip"},
		point(models.EventProcessExec, 1, models.ActionExec, models.DecisionDeny, "package installation tooling is not allowed"),
	)
	assertRule(t, outcome.Result, models.DivergenceKillCandidate, "process.package_install_disallowed")
}

func TestRepeatedDeniedConnectEscalatesKillCandidate(t *testing.T) {
	eval := New(testIntent())
	var result models.PolicyDivergenceResult
	for seq := uint64(1); seq <= 2; seq++ {
		result = eval.Observe(
			models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: seq, TsUnixNano: int64(seq), Type: models.EventNetConnect, PID: 10, DstIP: "10.0.0.5", DstPort: 80},
			point(models.EventNetConnect, seq, models.ActionConnect, models.DecisionDeny, "destination is outside network allowlists"),
		).Result
	}
	assertRule(t, result, models.DivergenceKillCandidate, "network.denied_repeated")
}

func TestPathScanLikeBehaviorWarns(t *testing.T) {
	eval := New(testIntent())
	var result models.PolicyDivergenceResult
	paths := []string{"/workspace/a.txt", "/workspace/b.txt", "/workspace/c.txt", "/workspace/d.txt"}
	for i, path := range paths {
		seq := uint64(i + 1)
		result = eval.Observe(
			models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: seq, TsUnixNano: int64(seq), Type: models.EventFileOpen, PID: 10, Path: path},
			point(models.EventFileOpen, seq, models.ActionRead, models.DecisionAllow, "allowed"),
		).Result
	}
	assertRule(t, result, models.DivergenceWarn, "file.workspace_scan_before_target")
}

func TestProcessFanoutBeyondThresholdEscalatesKillCandidate(t *testing.T) {
	intent := testIntent()
	intent.ProcessScope.MaxChildProcesses = 1
	eval := New(intent)
	var result models.PolicyDivergenceResult
	forks := []models.RuntimeEvent{
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessFork, PID: 11, PPID: 10},
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventProcessFork, PID: 12, PPID: 10},
	}
	for _, event := range forks {
		result = eval.Observe(event, nil).Result
	}
	assertRule(t, result, models.DivergenceKillCandidate, "process.child_limit_exceeded")
}

func TestFileRuleExposesWriteIntentSemantics(t *testing.T) {
	eval := New(testIntent())
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventFileOpen, PID: 10, Path: "/workspace/outside.txt", Flags: 0x241},
		point(models.EventFileOpen, 1, models.ActionWrite, models.DecisionDeny, "path is outside write_paths"),
	).Result
	if got := result.Metadata["file_semantics"]; got != "read-and-write-intent-file-open" {
		t.Fatalf("file_semantics = %q", got)
	}
}

func TestDeniedWriteEscalatesKillCandidate(t *testing.T) {
	eval := New(testIntent())
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventFileOpen, PID: 10, Path: "/workspace/report.pdf", Flags: 0x241},
		point(models.EventFileOpen, 1, models.ActionWrite, models.DecisionDeny, "path is outside write_paths"),
	).Result
	assertRule(t, result, models.DivergenceKillCandidate, "file.write_outside_scope")
	if result.Counters.DeniedWriteIntentCount != 1 {
		t.Fatalf("DeniedWriteIntentCount = %d", result.Counters.DeniedWriteIntentCount)
	}
}

func TestAllowedWriteDoesNotEscalate(t *testing.T) {
	intent := testIntent()
	intent.ResourceScope.WritePaths = []string{"/workspace/summary.md"}
	eval := New(intent)
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventFileOpen, PID: 10, Path: "/workspace/summary.md", Flags: 0x241},
		point(models.EventFileOpen, 1, models.ActionWrite, models.DecisionAllow, "allowed"),
	).Result
	if result.CurrentVerdict != models.DivergenceAllow {
		t.Fatalf("CurrentVerdict = %q, want allow", result.CurrentVerdict)
	}
}

func TestNoFalseEscalationOnNormalAllowedPath(t *testing.T) {
	intent := testIntent()
	intent.ProcessScope.AllowShell = true
	eval := New(intent)
	events := []struct {
		event    models.RuntimeEvent
		decision *models.PolicyPointDecision
	}{
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/python3", Comm: "python3"}, point(models.EventProcessExec, 1, models.ActionExec, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventFileOpen, PID: 10, Path: "/workspace/report.pdf"}, point(models.EventFileOpen, 2, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 3, TsUnixNano: 3, Type: models.EventNetConnect, PID: 10, DstIP: "127.0.0.1", DstPort: 443}, point(models.EventNetConnect, 3, models.ActionConnect, models.DecisionAllow, "allowed")},
	}
	var result models.PolicyDivergenceResult
	for _, item := range events {
		result = eval.Observe(item.event, item.decision).Result
	}
	if result.CurrentVerdict != models.DivergenceAllow {
		t.Fatalf("CurrentVerdict = %q, want allow", result.CurrentVerdict)
	}
}

func TestVerdictProgressionWarnThenKillCandidate(t *testing.T) {
	intent := testIntent()
	intent.ProcessScope.AllowShell = true
	eval := New(intent)

	warnEvents := []models.RuntimeEvent{
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 3, TsUnixNano: 3, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
		{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 4, TsUnixNano: 4, Type: models.EventProcessExec, PID: 10, Exe: "/bin/bash", Comm: "bash"},
	}
	var outcome ObserveOutcome
	for _, event := range warnEvents {
		outcome = eval.Observe(event, point(models.EventProcessExec, event.Seq, models.ActionExec, models.DecisionAllow, "allowed"))
	}
	if outcome.Result.CurrentVerdict != models.DivergenceWarn {
		t.Fatalf("CurrentVerdict after warn path = %q, want warn", outcome.Result.CurrentVerdict)
	}
	if !containsRule(outcome.Result.TriggeredRules, "process.shell_fanout") {
		t.Fatalf("expected process.shell_fanout rule, got %+v", outcome.Result.TriggeredRules)
	}

	outcome = eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 5, TsUnixNano: 5, Type: models.EventNetConnect, PID: 10, DstIP: "10.0.0.5", DstPort: 443},
		point(models.EventNetConnect, 5, models.ActionConnect, models.DecisionDeny, "destination is outside network allowlists"),
	)
	outcome = eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 6, TsUnixNano: 6, Type: models.EventNetConnect, PID: 10, DstIP: "10.0.0.6", DstPort: 443},
		point(models.EventNetConnect, 6, models.ActionConnect, models.DecisionDeny, "destination is outside network allowlists"),
	)
	if outcome.Result.CurrentVerdict != models.DivergenceKillCandidate {
		t.Fatalf("CurrentVerdict after kill path = %q, want kill_candidate", outcome.Result.CurrentVerdict)
	}
	if !containsRule(outcome.Result.TriggeredRules, "network.denied_repeated") {
		t.Fatalf("expected network.denied_repeated rule, got %+v", outcome.Result.TriggeredRules)
	}
}

func TestDeclaredTargetTouchSuppressesWorkspaceScanEscalation(t *testing.T) {
	eval := New(testIntent())
	steps := []struct {
		event    models.RuntimeEvent
		decision *models.PolicyPointDecision
	}{
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventFileOpen, PID: 10, Path: "/workspace/report.pdf"}, point(models.EventFileOpen, 1, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventFileOpen, PID: 10, Path: "/workspace/a.txt"}, point(models.EventFileOpen, 2, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 3, TsUnixNano: 3, Type: models.EventFileOpen, PID: 10, Path: "/workspace/b.txt"}, point(models.EventFileOpen, 3, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 4, TsUnixNano: 4, Type: models.EventFileOpen, PID: 10, Path: "/workspace/c.txt"}, point(models.EventFileOpen, 4, models.ActionRead, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 5, TsUnixNano: 5, Type: models.EventFileOpen, PID: 10, Path: "/workspace/d.txt"}, point(models.EventFileOpen, 5, models.ActionRead, models.DecisionAllow, "allowed")},
	}
	var result models.PolicyDivergenceResult
	for _, step := range steps {
		result = eval.Observe(step.event, step.decision).Result
	}
	if result.CurrentVerdict != models.DivergenceAllow {
		t.Fatalf("CurrentVerdict = %q, want allow", result.CurrentVerdict)
	}
	if containsRule(result.TriggeredRules, "file.workspace_scan_before_target") {
		t.Fatalf("unexpected workspace scan rule hit: %+v", result.TriggeredRules)
	}
}

func TestRuleMessagesAreSpecificAndGrepFriendly(t *testing.T) {
	eval := New(testIntent())
	result := eval.Observe(
		models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/pip", Comm: "pip"},
		point(models.EventProcessExec, 1, models.ActionExec, models.DecisionDeny, "package installation tooling is not allowed"),
	).Result
	var hit models.DivergenceRuleHit
	for _, candidate := range result.TriggeredRules {
		if candidate.RuleID == "process.package_install_disallowed" {
			hit = candidate
			break
		}
	}
	if hit.RuleID == "" {
		t.Fatalf("expected package install rule hit, got %+v", result.TriggeredRules)
	}
	if hit.Message != "package installer pip executed while allow_package_install=false" {
		t.Fatalf("unexpected message: %q", hit.Message)
	}
}

func TestIntegrationMixedEventsAndPointDecisions(t *testing.T) {
	intent := testIntent()
	intent.NetworkScope.AllowNetwork = false
	intent.NetworkScope.MaxOutboundConns = 0
	eval := New(intent)
	steps := []struct {
		event    models.RuntimeEvent
		decision *models.PolicyPointDecision
	}{
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 1, TsUnixNano: 1, Type: models.EventProcessExec, PID: 10, Exe: "/usr/bin/python3", Comm: "python3"}, point(models.EventProcessExec, 1, models.ActionExec, models.DecisionAllow, "allowed")},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 2, TsUnixNano: 2, Type: models.EventProcessFork, PID: 11, PPID: 10}, nil},
		{models.RuntimeEvent{ExecutionID: "exec_123", Backend: models.BackendFirecracker, Seq: 3, TsUnixNano: 3, Type: models.EventNetConnect, PID: 11, DstIP: "127.0.0.1", DstPort: 80}, point(models.EventNetConnect, 3, models.ActionConnect, models.DecisionDeny, "network access is disabled by intent contract")},
	}
	var result models.PolicyDivergenceResult
	for _, step := range steps {
		result = eval.Observe(step.event, step.decision).Result
	}
	assertRule(t, result, models.DivergenceKillCandidate, "network.connect_disabled")
	if result.Counters.ForkCount != 1 || result.Counters.ConnectCount != 1 {
		t.Fatalf("unexpected counters: %+v", result.Counters)
	}
}

func point(eventType models.EventType, seq uint64, action models.CedarAction, decision models.PointDecision, reason string) *models.PolicyPointDecision {
	return &models.PolicyPointDecision{ExecutionID: "exec_123", EventSeq: seq, EventType: eventType, CedarAction: action, Decision: decision, Reason: reason, Metadata: map[string]string{}}
}

func testIntent() contract.IntentContract {
	return contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "summarize_document",
		DeclaredPurpose: "Summarize report.pdf into summary.md",
		Language:        "python",
		BackendHint:     models.BackendFirecracker,
		ResourceScope: contract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace/report.pdf"},
			WritePaths:       []string{"/workspace/summary.md"},
			DenyPaths:        []string{"/workspace/.git"},
			MaxDistinctFiles: 5,
		},
		NetworkScope: contract.NetworkScope{
			AllowNetwork:     true,
			AllowedDomains:   []string{},
			AllowedIPs:       []string{"127.0.0.1"},
			MaxDNSQueries:    0,
			MaxOutboundConns: 1,
		},
		ProcessScope: contract.ProcessScope{
			AllowedBinaries:     []string{"python3", "cat"},
			AllowShell:          false,
			AllowPackageInstall: false,
			MaxChildProcesses:   2,
		},
		BrokerScope: contract.BrokerScope{},
		Budgets:     contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
}

func assertRule(t *testing.T, result models.PolicyDivergenceResult, verdict models.DivergenceVerdict, ruleID string) {
	t.Helper()
	if result.CurrentVerdict != verdict {
		t.Fatalf("CurrentVerdict = %q, want %q", result.CurrentVerdict, verdict)
	}
	for _, hit := range result.TriggeredRules {
		if hit.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("rule %q not found in %+v", ruleID, result.TriggeredRules)
}

func containsRule(hits []models.DivergenceRuleHit, ruleID string) bool {
	for _, hit := range hits {
		if hit.RuleID == ruleID {
			return true
		}
	}
	return false
}

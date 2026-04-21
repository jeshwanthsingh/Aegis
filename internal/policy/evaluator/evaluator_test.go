package evaluator

import (
	"testing"

	"aegis/internal/governance"
	"aegis/internal/models"
	"aegis/internal/policy/contract"
	"golang.org/x/sys/unix"
)

func TestEvaluatePointDecisions(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "summarize_document",
		DeclaredPurpose: "Summarize report.pdf",
		Language:        "python",
		BackendHint:     models.BackendFirecracker,
		ResourceScope: contract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace/report.pdf", "/workspace/input"},
			WritePaths:       []string{"/workspace/summary.md"},
			DenyPaths:        []string{"/workspace/.git"},
			MaxDistinctFiles: 5,
		},
		NetworkScope: contract.NetworkScope{
			AllowNetwork:     true,
			AllowedDomains:   []string{"example.com"},
			AllowedIPs:       []string{"127.0.0.1"},
			MaxDNSQueries:    1,
			MaxOutboundConns: 1,
		},
		ProcessScope: contract.ProcessScope{
			AllowedBinaries:     []string{"python3", "cat"},
			AllowShell:          false,
			AllowPackageInstall: false,
			MaxChildProcesses:   2,
		},
		BrokerScope: contract.BrokerScope{},
		Budgets: contract.BudgetLimits{
			TimeoutSec:  20,
			MemoryMB:    256,
			CPUQuota:    100,
			StdoutBytes: 4096,
		},
	}
	eval := New(intent)

	tests := []struct {
		name     string
		event    models.RuntimeEvent
		decision models.PointDecision
		reason   string
		action   models.CedarAction
	}{
		{
			name:     "allowed exec",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 1, Type: models.EventProcessExec, Exe: "/usr/bin/python3", Comm: "python3"},
			decision: models.DecisionAllow,
			reason:   "allowed by intent contract",
			action:   models.ActionExec,
		},
		{
			name:     "denied exec",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 2, Type: models.EventProcessExec, Exe: "/bin/bash", Comm: "bash"},
			decision: models.DecisionDeny,
			reason:   "shell execution is not allowed",
			action:   models.ActionExec,
		},
		{
			name:     "allowed file open",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 3, Type: models.EventFileOpen, Path: "/workspace/input/report.pdf"},
			decision: models.DecisionAllow,
			reason:   "allowed by intent contract",
			action:   models.ActionRead,
		},
		{
			name:     "denied file open",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 4, Type: models.EventFileOpen, Path: "/workspace/.git/config"},
			decision: models.DecisionDeny,
			reason:   "path matches deny_paths",
			action:   models.ActionRead,
		},
		{
			name:     "allowed connect",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 5, Type: models.EventNetConnect, DstIP: "127.0.0.1", DstPort: 80},
			decision: models.DecisionAllow,
			reason:   "allowed by runtime baseline",
			action:   models.ActionConnect,
		},
		{
			name:     "denied connect",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 6, Type: models.EventNetConnect, DstIP: "203.0.113.8", DstPort: 443},
			decision: models.DecisionDeny,
			reason:   "destination is outside network allowlists",
			action:   models.ActionConnect,
		},
		{
			name:     "allowed write open",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 7, Type: models.EventFileOpen, Path: "/workspace/summary.md", Flags: 0x241},
			decision: models.DecisionAllow,
			reason:   "allowed by intent contract",
			action:   models.ActionWrite,
		},
		{
			name:     "denied write open",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 8, Type: models.EventFileOpen, Path: "/workspace/report.pdf", Flags: 0x201},
			decision: models.DecisionDeny,
			reason:   "path is outside write_paths",
			action:   models.ActionWrite,
		},
		{
			name:     "not applicable",
			event:    models.RuntimeEvent{ExecutionID: "exec_123", Seq: 9, Type: models.EventProcessExit},
			decision: models.DecisionNotApplicable,
			reason:   "event type not mapped to point decision",
			action:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eval.Evaluate(tt.event)
			if got.Decision != tt.decision {
				t.Fatalf("Decision = %q, want %q", got.Decision, tt.decision)
			}
			if got.Reason != tt.reason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tt.reason)
			}
			if got.CedarAction != tt.action {
				t.Fatalf("CedarAction = %q, want %q", got.CedarAction, tt.action)
			}
		})
	}
}

func TestEvaluateDeniedWhenNetworkDisabled(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "no_network",
		DeclaredPurpose: "offline task",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		NetworkScope:    contract.NetworkScope{},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := New(intent).Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 10, Type: models.EventNetConnect, DstIP: "127.0.0.1"})
	if got.Decision != models.DecisionDeny {
		t.Fatalf("Decision = %q, want deny", got.Decision)
	}
	if got.Reason != "network access is disabled by intent contract" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestEvaluateIncludesProvidedPolicyDigestMetadata(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "task",
		DeclaredPurpose: "prove metadata",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, MaxDistinctFiles: 1},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := NewWithPolicyDigest(intent, "policy-digest").Evaluate(models.RuntimeEvent{
		ExecutionID: "exec_123",
		Seq:         1,
		Type:        models.EventProcessExec,
		Exe:         "/usr/bin/python3",
		Comm:        "python3",
	})
	if got.Metadata["policy_digest"] != "policy-digest" {
		t.Fatalf("policy_digest metadata = %q", got.Metadata["policy_digest"])
	}
	if got.Metadata["intent_digest"] != governance.DigestIntent(intent) {
		t.Fatalf("intent_digest metadata = %q", got.Metadata["intent_digest"])
	}
}

func TestEvaluateDeniedWhenEgressAllowlistIsEmpty(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "deny_all_networked",
		DeclaredPurpose: "networked namespace with deny-all outbound",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		NetworkScope: contract.NetworkScope{
			AllowNetwork: true,
		},
		ProcessScope: contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:      contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := New(intent).Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 11, Type: models.EventNetConnect, DstIP: "203.0.113.10", DstPort: 443})
	if got.Decision != models.DecisionDeny {
		t.Fatalf("Decision = %q, want deny", got.Decision)
	}
	if got.Reason != "destination is outside network allowlists" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestLoopbackTrafficIsAllowedRegardlessOfAllowlist(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "deny_all_networked",
		DeclaredPurpose: "networked namespace with deny-all external outbound",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		NetworkScope: contract.NetworkScope{
			AllowNetwork: true,
		},
		ProcessScope: contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:      contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	eval := New(intent)

	loopback := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 12, Type: models.EventNetConnect, DstIP: "127.0.0.1", DstPort: 8888})
	if loopback.Decision != models.DecisionAllow {
		t.Fatalf("loopback decision = %q, want allow", loopback.Decision)
	}

	public := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 13, Type: models.EventNetConnect, DstIP: "8.8.8.8", DstPort: 443})
	if public.Decision != models.DecisionDeny {
		t.Fatalf("public decision = %q, want deny", public.Decision)
	}
}

func TestEvaluateFileReadAllowsNarrowRuntimeBaseline(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "clean_run",
		DeclaredPurpose: "run python cleanly",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, DenyPaths: []string{"/etc"}, MaxDistinctFiles: 5},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := New(intent).Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 11, Type: models.EventFileOpen, Path: "/tmp/exec-abcd.py"})
	if got.Decision != models.DecisionAllow {
		t.Fatalf("Decision = %q, want allow", got.Decision)
	}
	if got.Reason != "allowed by runtime baseline" {
		t.Fatalf("Reason = %q", got.Reason)
	}
	if got.Metadata["baseline"] != "runtime_launcher" {
		t.Fatalf("baseline metadata = %q", got.Metadata["baseline"])
	}
}

func TestEvaluateFileReadAllowsPythonRuntimeMetadataBaseline(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "clean_run",
		DeclaredPurpose: "run python cleanly",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := New(intent).Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 12, Type: models.EventFileOpen, Path: "/usr/bin/pyvenv.cfg"})
	if got.Decision != models.DecisionAllow {
		t.Fatalf("Decision = %q, want allow", got.Decision)
	}
	if got.Reason != "allowed by runtime baseline" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestEvaluateFileWriteDoesNotUseRuntimeBaseline(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "clean_run",
		DeclaredPurpose: "write output cleanly",
		Language:        "python",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out.txt"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"python3"}, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	got := New(intent).Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 12, Type: models.EventFileOpen, Path: "/tmp/launcher-abcd.sh", Flags: 0x201})
	if got.Decision != models.DecisionDeny {
		t.Fatalf("Decision = %q, want deny", got.Decision)
	}
	if got.CedarAction != models.ActionWrite {
		t.Fatalf("CedarAction = %q, want write", got.CedarAction)
	}
	if got.Reason != "path is outside write_paths" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestEvaluateWriteIntentMatrix(t *testing.T) {
	intent := contract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "write_matrix",
		DeclaredPurpose: "verify write-intent flags",
		Language:        "bash",
		ResourceScope:   contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace", "/tmp"}, WritePaths: []string{"/workspace/out.txt"}, DenyPaths: []string{}, MaxDistinctFiles: 5},
		ProcessScope:    contract.ProcessScope{AllowedBinaries: []string{"bash"}, AllowShell: true, MaxChildProcesses: 1},
		Budgets:         contract.BudgetLimits{TimeoutSec: 20, MemoryMB: 256, CPUQuota: 100, StdoutBytes: 4096},
	}
	eval := New(intent)
	cases := []struct {
		name  string
		flags uint64
	}{
		{name: "o_wronly", flags: unix.O_WRONLY},
		{name: "o_rdwr", flags: unix.O_RDWR},
		{name: "o_creat", flags: unix.O_WRONLY | unix.O_CREAT},
		{name: "o_trunc", flags: unix.O_WRONLY | unix.O_TRUNC},
		{name: "o_append", flags: unix.O_WRONLY | unix.O_APPEND},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec_123", Seq: 20, Type: models.EventFileOpen, Path: "/tmp/readonly.txt", Flags: tc.flags})
			if got.CedarAction != models.ActionWrite {
				t.Fatalf("CedarAction = %q, want write", got.CedarAction)
			}
			if got.Decision != models.DecisionDeny {
				t.Fatalf("Decision = %q, want deny", got.Decision)
			}
			if got.Reason != "path is outside write_paths" {
				t.Fatalf("Reason = %q", got.Reason)
			}
			if got.Metadata["flags"] == "" {
				t.Fatal("expected flags metadata for write-intent open")
			}
		})
	}
}

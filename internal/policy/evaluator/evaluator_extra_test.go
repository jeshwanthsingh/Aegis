package evaluator

import (
	"testing"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

func TestEvaluateExecBranches(t *testing.T) {
	tests := []struct {
		name   string
		intent contract.IntentContract
		event  models.RuntimeEvent
		reason string
	}{
		{
			name: "package installer denied",
			intent: contract.IntentContract{
				Version:       "v1",
				ResourceScope: contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}},
				ProcessScope:  contract.ProcessScope{AllowedBinaries: []string{"python3"}, AllowPackageInstall: false},
			},
			event:  models.RuntimeEvent{ExecutionID: "exec", Seq: 1, Type: models.EventProcessExec, Exe: "/usr/bin/pip"},
			reason: "package installation tooling is not allowed",
		},
		{
			name: "no binaries allowlisted",
			intent: contract.IntentContract{
				Version:       "v1",
				ResourceScope: contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}},
				ProcessScope:  contract.ProcessScope{},
			},
			event:  models.RuntimeEvent{ExecutionID: "exec", Seq: 1, Type: models.EventProcessExec, Exe: "/usr/bin/python3"},
			reason: "no binaries are allowlisted",
		},
		{
			name: "binary outside allowlist",
			intent: contract.IntentContract{
				Version:       "v1",
				ResourceScope: contract.ResourceScope{WorkspaceRoot: "/workspace", ReadPaths: []string{"/workspace"}, WritePaths: []string{"/workspace/out"}},
				ProcessScope:  contract.ProcessScope{AllowedBinaries: []string{"python3"}},
			},
			event:  models.RuntimeEvent{ExecutionID: "exec", Seq: 1, Type: models.EventProcessExec, Exe: "/usr/bin/ruby"},
			reason: "binary is outside allowed_binaries",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := New(tc.intent).Evaluate(tc.event)
			if got.Decision != models.DecisionDeny {
				t.Fatalf("Decision = %q, want deny", got.Decision)
			}
			if got.Reason != tc.reason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tc.reason)
			}
		})
	}
}

func TestEvaluateReadAndConnectBranches(t *testing.T) {
	intent := contract.IntentContract{
		Version: "v1",
		ResourceScope: contract.ResourceScope{
			WorkspaceRoot: "/workspace",
			ReadPaths:     []string{"/workspace/input"},
			WritePaths:    []string{"/workspace/out"},
			DenyPaths:     []string{"/workspace/deny"},
		},
		NetworkScope: contract.NetworkScope{
			AllowNetwork:   true,
			AllowedDomains: []string{"api.example.com"},
		},
		ProcessScope: contract.ProcessScope{AllowedBinaries: []string{"python3"}},
	}
	eval := New(intent)

	if got := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec", Seq: 1, Type: models.EventFileOpen}); got.Reason != "file path is missing" {
		t.Fatalf("missing path reason = %q", got.Reason)
	}
	if got := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec", Seq: 2, Type: models.EventFileOpen, Path: "/workspace/other"}); got.Reason != "path is outside read_paths" {
		t.Fatalf("outside read paths reason = %q", got.Reason)
	}
	if got := eval.Evaluate(models.RuntimeEvent{ExecutionID: "exec", Seq: 3, Type: models.EventNetConnect, Domain: "api.example.com", DstIP: "10.0.0.5"}); got.Decision != models.DecisionAllow {
		t.Fatalf("domain allow decision = %q", got.Decision)
	}
}

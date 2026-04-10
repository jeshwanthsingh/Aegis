package cedar

import (
	"testing"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

func TestCompile(t *testing.T) {
	compiled := Compile(contract.IntentContract{
		ExecutionID:     "exec_123",
		WorkflowID:      "wf_9",
		TaskClass:       "summarize_document",
		DeclaredPurpose: "Summarize report.pdf",
		Language:        "python",
		BackendHint:     models.BackendFirecracker,
		ResourceScope: contract.ResourceScope{
			ReadPaths:  []string{"/workspace/report.pdf"},
			WritePaths: []string{"/workspace/summary.md"},
			DenyPaths:  []string{"/workspace/.git"},
		},
		NetworkScope: contract.NetworkScope{
			AllowNetwork:   false,
			AllowedDomains: []string{"example.com"},
			AllowedIPs:     []string{"127.0.0.1"},
		},
		ProcessScope: contract.ProcessScope{
			AllowedBinaries:     []string{"python3"},
			AllowShell:          false,
			AllowPackageInstall: false,
		},
		BrokerScope: contract.BrokerScope{
			AllowedDelegations: []string{"artifact.fetch"},
			RequireHostConsent: true,
		},
		Budgets: contract.BudgetLimits{
			TimeoutSec:  20,
			MemoryMB:    256,
			CPUQuota:    100,
			StdoutBytes: 4096,
		},
		Attributes: map[string]string{"mode": "test"},
	})

	if compiled.Principal.ExecutionID != "exec_123" {
		t.Fatalf("ExecutionID = %q", compiled.Principal.ExecutionID)
	}
	if !compiled.Context.RequireHostConsent {
		t.Fatal("RequireHostConsent = false, want true")
	}
	if got := compiled.Principal.AllowedBinaries[0]; got != "python3" {
		t.Fatalf("AllowedBinaries[0] = %q", got)
	}
}

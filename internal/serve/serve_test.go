package serve

import (
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/config"
	"aegis/internal/setup"
)

func TestBuildPlanUsesDelegatedScopeWhenCgroupWarns(t *testing.T) {
	cfg := config.Default("/repo")
	plan, err := BuildPlan(cfg, []setup.CheckResult{{ID: "cgroup", Label: "cgroup parent", Status: setup.StatusWarn, Detail: "delegated scope required"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.Mode != ModeDelegatedScope {
		t.Fatalf("plan mode = %s", plan.Mode)
	}
}

func TestBuildPlanFailsOnBlockingResult(t *testing.T) {
	cfg := config.Default("/repo")
	_, err := BuildPlan(cfg, []setup.CheckResult{{Label: "KVM", Status: setup.StatusFail, Detail: "missing", Blocking: true}})
	if err == nil || !strings.Contains(err.Error(), "KVM: missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommandUsesSystemdRunForDelegatedScope(t *testing.T) {
	cfg := config.Default("/repo")
	cfg.Runtime.OrchestratorBin = filepath.Join("/repo", ".aegis/bin/orchestrator")
	plan, err := BuildPlan(cfg, []setup.CheckResult{{ID: "cgroup", Label: "cgroup parent", Status: setup.StatusWarn, Detail: "delegated scope required"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	cmd := Command(plan)
	if filepath.Base(cmd.Path) != "systemd-run" {
		t.Fatalf("command path = %q", cmd.Path)
	}
}

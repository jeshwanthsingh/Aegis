package setup

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis/internal/config"
)

func TestEnsureSigningSeedIsIdempotent(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "seed.b64")
	created, keyID1, err := EnsureSigningSeed(seedPath)
	if err != nil {
		t.Fatalf("EnsureSigningSeed create: %v", err)
	}
	if !created {
		t.Fatal("expected seed to be created")
	}
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err != nil {
		t.Fatalf("seed file is not valid base64: %v", err)
	}
	created, keyID2, err := EnsureSigningSeed(seedPath)
	if err != nil {
		t.Fatalf("EnsureSigningSeed reuse: %v", err)
	}
	if created {
		t.Fatal("expected existing seed to be reused")
	}
	if keyID1 != keyID2 {
		t.Fatalf("key ids differ: %q vs %q", keyID1, keyID2)
	}
}

func TestRenderSummary(t *testing.T) {
	summary := RenderSummary([]CheckResult{
		{Label: "KVM", Status: StatusOK, Detail: "ready", Blocking: true},
		{Label: "Network", Status: StatusWarn, Detail: "optional setup missing", Action: "Install iptables.", Blocking: false},
		{Label: "Database", Status: StatusFail, Detail: "connect failed", Action: "Start postgres.", Blocking: true},
	})
	for _, needle := range []string{"[OK] KVM", "[WARN] Network", "action: Install iptables.", "[FAIL] Database", "Overall status: not ready for local serve"} {
		if !strings.Contains(summary, needle) {
			t.Fatalf("summary missing %q: %s", needle, summary)
		}
	}
}

func TestEvaluateBrokerEnvOptional(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	cfg.Demo.BrokerEnv = []string{"AEGIS_CRED_GITHUB_TOKEN"}
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	found := false
	for _, result := range results {
		if result.ID == "broker-env" {
			found = true
			if result.Status != StatusWarn {
				t.Fatalf("broker-env status = %s", result.Status)
			}
		}
	}
	if !found {
		t.Fatal("broker-env result missing")
	}
}

func tempRepoRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "ai"))
	mustMkdir(t, filepath.Join(root, "assets"))
	mustMkdir(t, filepath.Join(root, "configs"))
	mustMkdir(t, filepath.Join(root, "db"))
	mustMkdir(t, filepath.Join(root, "guest-runner"))
	mustMkdir(t, filepath.Join(root, "cmd", "orchestrator"))
	mustMkdir(t, filepath.Join(root, "cmd", "aegis-cli"))
	mustMkdir(t, filepath.Join(root, "cmd", "aegis-mcp"))
	mustWrite(t, filepath.Join(root, "go.mod"), "module aegis\n\ngo 1.22.5\n")
	mustWrite(t, filepath.Join(root, "go.sum"), "")
	mustWrite(t, filepath.Join(root, "cmd", "orchestrator", "main.go"), "package main\nfunc main() {}\n")
	mustWrite(t, filepath.Join(root, "cmd", "aegis-cli", "main.go"), "package main\nfunc main() {}\n")
	mustWrite(t, filepath.Join(root, "cmd", "aegis-mcp", "main.go"), "package main\nfunc main() {}\n")
	mustWrite(t, filepath.Join(root, "assets", "vmlinux"), "kernel")
	mustWrite(t, filepath.Join(root, "assets", "alpine-base.ext4"), "rootfs")
	mustWrite(t, filepath.Join(root, "configs", "default-policy.yaml"), "allowed_languages: [bash]\n")
	mustWrite(t, filepath.Join(root, "db", "schema.sql"), "CREATE TABLE IF NOT EXISTS executions (execution_id TEXT PRIMARY KEY);\n")
	return root
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func TestEvaluateWarnsWhenAPIAuthUnset(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	for _, result := range results {
		if result.ID == "api-auth" {
			if result.Status != StatusWarn {
				t.Fatalf("api-auth status = %s", result.Status)
			}
			return
		}
	}
	t.Fatal("api-auth result missing")
}

func TestEvaluateWarnsWhenNetCapabilityMissing(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")

	previous := getcapOutputFunc
	getcapOutputFunc = func(string) (string, error) {
		return "", nil
	}
	defer func() {
		getcapOutputFunc = previous
	}()

	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	checks := map[string]CheckResult{}
	for _, result := range results {
		checks[result.ID] = result
	}

	for _, id := range []string{"orchestrator-cap", "aegis-cap"} {
		result, ok := checks[id]
		if !ok {
			t.Fatalf("%s result missing", id)
		}
		if result.Status != StatusWarn {
			t.Fatalf("%s status = %s", id, result.Status)
		}
		if !strings.Contains(result.Detail, "missing cap_net_admin") {
			t.Fatalf("%s detail = %q", id, result.Detail)
		}
		if !strings.Contains(result.Detail, "make setcap") {
			t.Fatalf("%s detail = %q", id, result.Detail)
		}
	}
}

func TestEvaluateWarnsWhenSigningModeIsExplicitDev(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	cfg.Receipt.SigningMode = "dev"
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")
	if _, _, err := EnsureSigningSeed(cfg.Receipt.SeedFile); err != nil {
		t.Fatalf("EnsureSigningSeed: %v", err)
	}
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	for _, result := range results {
		if result.ID == "signing-mode" {
			if result.Status != StatusWarn {
				t.Fatalf("signing-mode status = %s", result.Status)
			}
			if !strings.Contains(result.Detail, "explicit non-production dev signing") {
				t.Fatalf("unexpected detail: %s", result.Detail)
			}
			return
		}
	}
	t.Fatal("signing-mode result missing")
}

func TestEvaluateFailsWhenSigningSeedIsMalformed(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")
	if err := os.MkdirAll(filepath.Dir(cfg.Receipt.SeedFile), 0o755); err != nil {
		t.Fatalf("MkdirAll seed dir: %v", err)
	}
	mustWrite(t, cfg.Receipt.SeedFile, "not-base64")
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	for _, result := range results {
		if result.ID == "signing-mode" {
			if result.Status != StatusFail {
				t.Fatalf("signing-mode status = %s", result.Status)
			}
			if !strings.Contains(result.Detail, "decode receipt signing seed") {
				t.Fatalf("unexpected detail: %s", result.Detail)
			}
			return
		}
	}
	t.Fatal("signing-mode result missing")
}

func TestEvaluateFailsWhenOrchestratorBinaryIsStale(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")
	staleTime := mustTime(t, filepath.Join(repo, "cmd", "orchestrator"))
	older := staleTime.Add(-2 * time.Hour)
	if err := os.Chtimes(cfg.Runtime.OrchestratorBin, older, older); err != nil {
		t.Fatalf("Chtimes orchestrator: %v", err)
	}
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	for _, result := range results {
		if result.ID == "orchestrator-freshness" {
			if result.Status != StatusFail {
				t.Fatalf("orchestrator-freshness status = %s", result.Status)
			}
			return
		}
	}
	t.Fatal("orchestrator-freshness result missing")
}

func TestEvaluateWarnsWhenAegisCommandPathIsNonCanonical(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg := config.Default(repo)
	mustMkdir(t, filepath.Dir(cfg.Runtime.OrchestratorBin))
	mustMkdir(t, filepath.Dir(cfg.Runtime.CLIBin))
	mustWrite(t, cfg.Runtime.OrchestratorBin, "orchestrator")
	mustWrite(t, cfg.Runtime.CLIBin, "cli")
	mustWrite(t, config.MCPBinPath(repo), "mcp")
	t.Setenv("PATH", t.TempDir())
	results := Evaluate(repo, cfg, BootstrapArtifacts{})
	for _, result := range results {
		if result.ID == "aegis-command" {
			if result.Status != StatusWarn {
				t.Fatalf("aegis-command status = %s", result.Status)
			}
			return
		}
	}
	t.Fatal("aegis-command result missing")
}

func mustTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	return info.ModTime()
}

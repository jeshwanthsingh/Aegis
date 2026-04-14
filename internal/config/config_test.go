package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCreatesStarterConfig(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg, path, created, err := Ensure(repo, "")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !created {
		t.Fatal("expected config to be created")
	}
	if path != filepath.Join(repo, DefaultConfigRelPath) {
		t.Fatalf("config path = %q", path)
	}
	if cfg.Runtime.RootfsPath != filepath.Join(repo, "assets", "alpine-base.ext4") {
		t.Fatalf("unexpected rootfs path: %q", cfg.Runtime.RootfsPath)
	}
	if MCPBinPath(repo) != filepath.Join(repo, DefaultMCPBinRel) {
		t.Fatalf("unexpected MCP bin path: %q", MCPBinPath(repo))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), "signing_mode: \"strict\"") {
		t.Fatalf("starter config missing strict signing mode: %s", string(raw))
	}
}

func TestLoadAppliesEnvOverrides(t *testing.T) {
	repo := tempRepoRoot(t)
	cfg, path, _, err := Ensure(repo, "")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	t.Setenv("AEGIS_URL", "http://127.0.0.1:9090")
	t.Setenv("AEGIS_PROOF_ROOT", "/tmp/custom-proofs")
	loaded, err := Load(repo, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.API.URL != "http://127.0.0.1:9090" {
		t.Fatalf("API.URL = %q", loaded.API.URL)
	}
	if loaded.Runtime.ProofRoot != "/tmp/custom-proofs" {
		t.Fatalf("ProofRoot = %q", loaded.Runtime.ProofRoot)
	}
	if loaded.Runtime.OrchestratorBin != cfg.Runtime.OrchestratorBin {
		t.Fatalf("orchestrator bin changed unexpectedly: %q", loaded.Runtime.OrchestratorBin)
	}
}

func TestFindRepoRoot(t *testing.T) {
	repo := tempRepoRoot(t)
	nested := filepath.Join(repo, "internal", "config")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	got, err := FindRepoRoot(nested)
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	if got != repo {
		t.Fatalf("repo root = %q want %q", got, repo)
	}
}

func tempRepoRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ai"), 0o755); err != nil {
		t.Fatalf("MkdirAll ai: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module aegis\n\ngo 1.22.5\n"), 0o644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}
	return root
}

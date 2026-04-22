package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/config"
)

func TestDemoPrepareCommand(t *testing.T) {
	repoRoot, err := config.FindRepoRoot("")
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	tempDir := t.TempDir()
	assetsDir := filepath.Join(tempDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(assets): %v", err)
	}
	rootfsPath := filepath.Join(tempDir, "alpine-base.ext4")
	if err := os.WriteFile(rootfsPath, []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	seedPath := filepath.Join(tempDir, "receipt_seed.b64")
	if err := os.WriteFile(seedPath, []byte("c2VlZA==\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(seed): %v", err)
	}
	configPath := filepath.Join(tempDir, "config.yaml")
	configBody := strings.Join([]string{
		"version: v1",
		"api:",
		"  url: http://127.0.0.1:8080",
		"database:",
		"  url: postgres://demo@localhost/aegis?sslmode=disable",
		"runtime:",
		"  assets_dir: " + quoteYAMLPath(assetsDir),
		"  policy_path: " + quoteYAMLPath(filepath.Join(repoRoot, "configs", "default-policy.yaml")),
		"  rootfs_path: " + quoteYAMLPath(rootfsPath),
		"  firecracker_bin: firecracker",
		"  orchestrator_bin: " + quoteYAMLPath(filepath.Join(repoRoot, ".aegis", "bin", "orchestrator")),
		"  cli_bin: " + quoteYAMLPath(filepath.Join(repoRoot, ".aegis", "bin", "aegis")),
		"  cgroup_parent: " + quoteYAMLPath("/tmp/aegis-demo-test"),
		"  proof_root: " + quoteYAMLPath(filepath.Join(tempDir, "proofs")),
		"  log_path: " + quoteYAMLPath(filepath.Join(tempDir, "orchestrator.log")),
		"  ui_dir: " + quoteYAMLPath(filepath.Join(repoRoot, "ui")),
		"  warm_pool_size: 0",
		"  warm_pool_max_age: 300",
		"receipt:",
		"  signing_mode: strict",
		"  seed_file: " + quoteYAMLPath(seedPath),
		"demo:",
		"  broker_env: []",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	codePath := filepath.Join(tempDir, "demo.py")
	if err := os.WriteFile(codePath, []byte("print('demo')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(code): %v", err)
	}
	intentPath := filepath.Join(tempDir, "intent.json")
	intent := `{"version":"v1","execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b","workflow_id":"wf_demo","task_class":"demo","declared_purpose":"preview demo admission","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace"],"deny_paths":[],"max_distinct_files":16},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":4},"broker_scope":{"allowed_delegations":["demo"],"allowed_domains":["127.0.0.1"],"allowed_repo_labels":["demo"],"allowed_action_types":["http_request","host_repo_apply_patch"],"require_host_consent":true},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`
	if err := os.WriteFile(intentPath, []byte(intent), 0o644); err != nil {
		t.Fatalf("WriteFile(intent): %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := demoPrepare(&stdout, &stderr, []string{
		"--config", configPath,
		"--lang", "python",
		"--file", codePath,
		"--intent-file", intentPath,
		"--timeout", "1000",
		"--profile", "standard",
	})
	if code != 0 {
		t.Fatalf("demoPrepare exit=%d stderr=%s", code, stderr.String())
	}
	for _, needle := range []string{
		"status=prepared",
		"execution_id=30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
		"policy_digest=",
		"authority_digest=",
		"approval_mode=require_host_consent",
		"broker_action_types=host_repo_apply_patch,http_request",
		"broker_repo_labels=demo",
	} {
		if !strings.Contains(stdout.String(), needle) {
			t.Fatalf("stdout missing %q:\n%s", needle, stdout.String())
		}
	}
}

func quoteYAMLPath(path string) string {
	return `"` + strings.ReplaceAll(path, `\`, `\\`) + `"`
}

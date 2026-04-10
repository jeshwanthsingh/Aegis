package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"aegis/internal/executor"

	"gopkg.in/yaml.v3"
)

const (
	Version              = "v1"
	DefaultConfigRelPath = ".aegis/config.yaml"
	DefaultEnvExample    = ".aegis/env.example"
	DefaultAegisBinRel   = ".aegis/bin/aegis"
	DefaultOrchBinRel    = ".aegis/bin/orchestrator"
	DefaultSeedRel       = ".aegis/receipt_signing_seed.b64"
	DefaultAPIURL        = "http://localhost:8080"
	ConfigEnvVar         = "AEGIS_CONFIG"
)

type Config struct {
	Version  string         `yaml:"version"`
	API      APIConfig      `yaml:"api"`
	Database DatabaseConfig `yaml:"database"`
	Runtime  RuntimeConfig  `yaml:"runtime"`
	Receipt  ReceiptConfig  `yaml:"receipt"`
	Demo     DemoConfig     `yaml:"demo"`
}

type APIConfig struct {
	URL string `yaml:"url"`
}

type DatabaseConfig struct {
	URL string `yaml:"url"`
}

type RuntimeConfig struct {
	AssetsDir       string `yaml:"assets_dir"`
	PolicyPath      string `yaml:"policy_path"`
	RootfsPath      string `yaml:"rootfs_path"`
	FirecrackerBin  string `yaml:"firecracker_bin"`
	OrchestratorBin string `yaml:"orchestrator_bin"`
	CLIBin          string `yaml:"cli_bin"`
	CgroupParent    string `yaml:"cgroup_parent"`
	ProofRoot       string `yaml:"proof_root"`
	LogPath         string `yaml:"log_path"`
	UIDir           string `yaml:"ui_dir"`
	WarmPoolSize    int    `yaml:"warm_pool_size"`
	WarmPoolMaxAge  int    `yaml:"warm_pool_max_age"`
}

type ReceiptConfig struct {
	SigningMode string `yaml:"signing_mode"`
	SeedFile    string `yaml:"seed_file"`
}

type DemoConfig struct {
	BrokerEnv []string `yaml:"broker_env"`
}

func FindRepoRoot(start string) (string, error) {
	if strings.TrimSpace(start) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		start = cwd
	}
	dir := filepath.Clean(start)
	for {
		if fileExists(filepath.Join(dir, "go.mod")) && dirExists(filepath.Join(dir, "ai")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not locate Aegis repo root from current directory")
		}
		dir = parent
	}
}

func Default(repoRoot string) Config {
	repoRoot = filepath.Clean(repoRoot)
	return Config{
		Version:  Version,
		API:      APIConfig{URL: DefaultAPIURL},
		Database: DatabaseConfig{URL: "postgres://postgres:postgres@localhost/aegis?sslmode=disable"},
		Runtime: RuntimeConfig{
			AssetsDir:       filepath.Join(repoRoot, "assets"),
			PolicyPath:      filepath.Join(repoRoot, "configs", "default-policy.yaml"),
			RootfsPath:      filepath.Join(repoRoot, "assets", "alpine-base.ext4"),
			FirecrackerBin:  "firecracker",
			OrchestratorBin: filepath.Join(repoRoot, DefaultOrchBinRel),
			CLIBin:          filepath.Join(repoRoot, DefaultAegisBinRel),
			CgroupParent:    executor.DefaultCgroupParent(),
			ProofRoot:       "/tmp/aegis/proofs",
			LogPath:         "/tmp/aegis-local-orchestrator.log",
			UIDir:           filepath.Join(repoRoot, "ui"),
			WarmPoolSize:    0,
			WarmPoolMaxAge:  300,
		},
		Receipt: ReceiptConfig{
			SigningMode: "strict",
			SeedFile:    filepath.Join(repoRoot, DefaultSeedRel),
		},
		Demo: DemoConfig{BrokerEnv: []string{"AEGIS_CRED_GITHUB_TOKEN"}},
	}
}

func ConfigPath(repoRoot string, explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(ConfigEnvVar)); v != "" {
		return v
	}
	return filepath.Join(repoRoot, DefaultConfigRelPath)
}

func Ensure(repoRoot string, explicit string) (Config, string, bool, error) {
	path := ConfigPath(repoRoot, explicit)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Config{}, path, false, fmt.Errorf("create config dir: %w", err)
	}
	if !fileExists(path) {
		cfg := Default(repoRoot)
		if err := os.WriteFile(path, []byte(RenderStarterConfig(cfg)), 0o644); err != nil {
			return Config{}, path, false, fmt.Errorf("write starter config: %w", err)
		}
		return cfg, path, true, nil
	}
	cfg, err := Load(repoRoot, path)
	return cfg, path, false, err
}

func Load(repoRoot string, path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Default(repoRoot)
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	cfg = ApplyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ApplyEnvOverrides(cfg Config) Config {
	apply := func(dst *string, env string) {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			*dst = v
		}
	}
	apply(&cfg.API.URL, "AEGIS_URL")
	apply(&cfg.Database.URL, "AEGIS_DB_URL")
	apply(&cfg.Runtime.AssetsDir, "AEGIS_ASSETS_DIR")
	apply(&cfg.Runtime.PolicyPath, "AEGIS_POLICY_PATH")
	apply(&cfg.Runtime.RootfsPath, "AEGIS_ROOTFS_PATH")
	apply(&cfg.Runtime.FirecrackerBin, "AEGIS_FIRECRACKER_BIN")
	apply(&cfg.Runtime.CgroupParent, "AEGIS_CGROUP_PARENT")
	apply(&cfg.Runtime.ProofRoot, "AEGIS_PROOF_ROOT")
	apply(&cfg.Runtime.LogPath, "AEGIS_LOG_PATH")
	apply(&cfg.Runtime.UIDir, "AEGIS_UI_DIR")
	if v := strings.TrimSpace(os.Getenv("AEGIS_WARM_POOL_SIZE")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Runtime.WarmPoolSize = parsed
		}
	}
	if v := strings.TrimSpace(os.Getenv("AEGIS_WARM_POOL_MAX_AGE")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Runtime.WarmPoolMaxAge = parsed
		}
	}
	apply(&cfg.Receipt.SigningMode, "AEGIS_RECEIPT_SIGNING_MODE")
	apply(&cfg.Receipt.SeedFile, "AEGIS_RECEIPT_SIGNING_SEED_FILE")
	return cfg
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Version) == "" {
		c.Version = Version
	}
	if c.Version != Version {
		return fmt.Errorf("config version must be %s", Version)
	}
	if strings.TrimSpace(c.API.URL) == "" {
		return fmt.Errorf("api.url is required")
	}
	if strings.TrimSpace(c.Database.URL) == "" {
		return fmt.Errorf("database.url is required")
	}
	if strings.TrimSpace(c.Runtime.AssetsDir) == "" {
		return fmt.Errorf("runtime.assets_dir is required")
	}
	if strings.TrimSpace(c.Runtime.PolicyPath) == "" {
		return fmt.Errorf("runtime.policy_path is required")
	}
	if strings.TrimSpace(c.Runtime.RootfsPath) == "" {
		return fmt.Errorf("runtime.rootfs_path is required")
	}
	if strings.TrimSpace(c.Runtime.FirecrackerBin) == "" {
		return fmt.Errorf("runtime.firecracker_bin is required")
	}
	if strings.TrimSpace(c.Runtime.OrchestratorBin) == "" {
		return fmt.Errorf("runtime.orchestrator_bin is required")
	}
	if strings.TrimSpace(c.Runtime.CLIBin) == "" {
		return fmt.Errorf("runtime.cli_bin is required")
	}
	if strings.TrimSpace(c.Runtime.CgroupParent) == "" {
		return fmt.Errorf("runtime.cgroup_parent is required")
	}
	if strings.TrimSpace(c.Runtime.ProofRoot) == "" {
		return fmt.Errorf("runtime.proof_root is required")
	}
	if c.Runtime.WarmPoolSize < 0 {
		return fmt.Errorf("runtime.warm_pool_size must be >= 0")
	}
	if c.Runtime.WarmPoolMaxAge <= 0 {
		return fmt.Errorf("runtime.warm_pool_max_age must be > 0")
	}
	if strings.TrimSpace(c.Receipt.SigningMode) == "" {
		return fmt.Errorf("receipt.signing_mode is required")
	}
	if strings.TrimSpace(c.Receipt.SeedFile) == "" {
		return fmt.Errorf("receipt.seed_file is required")
	}
	return nil
}

func RenderStarterConfig(cfg Config) string {
	return fmt.Sprintf(`# Aegis local config
# Loading order: --config, AEGIS_CONFIG, .aegis/config.yaml
# Environment overrides: AEGIS_URL, AEGIS_DB_URL, AEGIS_ASSETS_DIR, AEGIS_POLICY_PATH,
# AEGIS_ROOTFS_PATH, AEGIS_FIRECRACKER_BIN, AEGIS_CGROUP_PARENT, AEGIS_PROOF_ROOT,
# AEGIS_LOG_PATH, AEGIS_UI_DIR, AEGIS_WARM_POOL_SIZE, AEGIS_WARM_POOL_MAX_AGE,
# AEGIS_RECEIPT_SIGNING_MODE, AEGIS_RECEIPT_SIGNING_SEED_FILE
version: %s

api:
  # Base URL used by aegis run/health/receipt commands when AEGIS_URL is unset.
  url: %s

database:
  # Postgres connection string used by the orchestrator.
  url: %s

runtime:
  # Assets directory containing vmlinux and rootfs images.
  assets_dir: %s
  # Policy file loaded by the orchestrator.
  policy_path: %s
  # Default rootfs image for local Firecracker runs.
  rootfs_path: %s
  # Firecracker binary name or absolute path.
  firecracker_bin: %s
  # Repo-local orchestrator binary built by aegis setup.
  orchestrator_bin: %s
  # Repo-local aegis CLI binary built by aegis setup.
  cli_bin: %s
  # cgroup subtree used for local executions.
  cgroup_parent: %s
  # Directory where proof bundles are written.
  proof_root: %s
  # Local orchestrator log path used by helper scripts.
  log_path: %s
  # UI directory served by the orchestrator when present.
  ui_dir: %s
  # Number of prebooted paused microVMs to keep warm; 0 disables the pool.
  warm_pool_size: %d
  # Maximum age in seconds for a paused warm VM before it is recycled.
  warm_pool_max_age: %d

receipt:
  # Signing mode used for local receipts. strict requires a real seed file.
  signing_mode: %s
  # Base64-encoded Ed25519 seed file created by aegis setup if missing.
  seed_file: %s

demo:
  # Optional env vars used for broker-capable demos.
  broker_env:
%s`,
		cfg.Version,
		yamlQuote(cfg.API.URL),
		yamlQuote(cfg.Database.URL),
		yamlQuote(cfg.Runtime.AssetsDir),
		yamlQuote(cfg.Runtime.PolicyPath),
		yamlQuote(cfg.Runtime.RootfsPath),
		yamlQuote(cfg.Runtime.FirecrackerBin),
		yamlQuote(cfg.Runtime.OrchestratorBin),
		yamlQuote(cfg.Runtime.CLIBin),
		yamlQuote(cfg.Runtime.CgroupParent),
		yamlQuote(cfg.Runtime.ProofRoot),
		yamlQuote(cfg.Runtime.LogPath),
		yamlQuote(cfg.Runtime.UIDir),
		cfg.Runtime.WarmPoolSize,
		cfg.Runtime.WarmPoolMaxAge,
		yamlQuote(cfg.Receipt.SigningMode),
		yamlQuote(cfg.Receipt.SeedFile),
		renderList(cfg.Demo.BrokerEnv),
	)
}

func ResolveFirecrackerBinary(bin string) (string, error) {
	if filepath.IsAbs(bin) {
		if !fileExists(bin) {
			return "", fmt.Errorf("firecracker binary not found at %s", bin)
		}
		return bin, nil
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("firecracker binary %q not found on PATH", bin)
	}
	return resolved, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func yamlQuote(v string) string {
	return fmt.Sprintf("%q", v)
}

func renderList(values []string) string {
	if len(values) == 0 {
		return "    []"
	}
	lines := make([]string, 0, len(values))
	for _, value := range values {
		lines = append(lines, "    - "+yamlQuote(value))
	}
	return strings.Join(lines, "\n")
}

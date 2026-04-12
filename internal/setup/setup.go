package setup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"aegis/internal/config"
	"aegis/internal/executor"
	"aegis/internal/receipt"

	_ "github.com/lib/pq"
)

type Status string

const (
	StatusOK   Status = "OK"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

type CheckResult struct {
	ID       string
	Label    string
	Status   Status
	Detail   string
	Action   string
	Blocking bool
}

type Report struct {
	Config        config.Config
	ConfigPath    string
	Created       []string
	Reused        []string
	Results       []CheckResult
	ReadyForServe bool
}

type Options struct {
	Stdout io.Writer
	Stderr io.Writer
}

type BootstrapArtifacts struct {
	AegisBuilt        bool
	OrchestratorBuilt bool
	GuestRunnerBuilt  bool
	RootfsRebaked     bool
	SigningSeedKeyID  string
}

func Run(ctx context.Context, repoRoot string, explicitConfig string, opts Options) (Report, error) {
	cfg, path, createdConfig, err := config.Ensure(repoRoot, explicitConfig)
	if err != nil {
		return Report{}, err
	}
	report := Report{Config: cfg, ConfigPath: path}
	if createdConfig {
		report.Created = append(report.Created, path)
	} else {
		report.Reused = append(report.Reused, path)
	}

	created, reused, artifacts, bootstrapErr := Bootstrap(ctx, repoRoot, cfg)
	report.Created = append(report.Created, created...)
	report.Reused = append(report.Reused, reused...)
	if bootstrapErr != nil {
		report.Results = append(report.Results, CheckResult{
			ID:       "bootstrap",
			Label:    "bootstrap",
			Status:   StatusFail,
			Detail:   bootstrapErr.Error(),
			Action:   "Fix the reported bootstrap failure and rerun aegis setup.",
			Blocking: true,
		})
	}
	report.Results = append(report.Results, Evaluate(repoRoot, cfg, artifacts)...)
	report.ReadyForServe = readyForServe(report.Results)
	return report, nil
}

func Bootstrap(ctx context.Context, repoRoot string, cfg config.Config) (created []string, reused []string, artifacts BootstrapArtifacts, err error) {
	dirs := []string{
		filepath.Join(repoRoot, ".aegis"),
		filepath.Join(repoRoot, ".aegis", "bin"),
		cfg.Runtime.ProofRoot,
		"/tmp/aegis",
		executor.WorkspacesDir,
	}
	for _, dir := range dirs {
		if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
			reused = append(reused, dir)
			continue
		}
		if mkdirErr := os.MkdirAll(dir, 0o755); mkdirErr != nil {
			return created, reused, artifacts, fmt.Errorf("create directory %s: %w", dir, mkdirErr)
		}
		created = append(created, dir)
	}

	envPath := filepath.Join(repoRoot, config.DefaultEnvExample)
	if _, statErr := os.Stat(envPath); statErr == nil {
		reused = append(reused, envPath)
	} else {
		content := "# Optional broker/demo env\nAEGIS_CRED_GITHUB_TOKEN=\nAEGIS_API_KEY=\n"
		if writeErr := os.WriteFile(envPath, []byte(content), 0o644); writeErr != nil {
			return created, reused, artifacts, fmt.Errorf("write env example: %w", writeErr)
		}
		created = append(created, envPath)
	}

	seedCreated, keyID, seedErr := EnsureSigningSeed(cfg.Receipt.SeedFile)
	if seedErr != nil {
		return created, reused, artifacts, seedErr
	}
	artifacts.SigningSeedKeyID = keyID
	if seedCreated {
		created = append(created, cfg.Receipt.SeedFile)
	} else {
		reused = append(reused, cfg.Receipt.SeedFile)
	}

	goBin, goErr := findGoBinary()
	if goErr != nil {
		return created, reused, artifacts, goErr
	}

	cliBuilt, err := buildIfNeeded(ctx, repoRoot, goBin, cfg.Runtime.CLIBin, []string{"./cmd/aegis-cli"}, binarySourceRoots(repoRoot, "cli"), nil)
	if err != nil {
		return created, reused, artifacts, err
	}
	artifacts.AegisBuilt = cliBuilt

	orchBuilt, err := buildIfNeeded(ctx, repoRoot, goBin, cfg.Runtime.OrchestratorBin, []string{"./cmd/orchestrator"}, binarySourceRoots(repoRoot, "orchestrator"), nil)
	if err != nil {
		return created, reused, artifacts, err
	}
	artifacts.OrchestratorBuilt = orchBuilt

	guestBinary := filepath.Join(repoRoot, "guest-runner", "guest-runner")
	guestBuilt, err := buildIfNeeded(ctx, filepath.Join(repoRoot, "guest-runner"), goBin, guestBinary, []string{"."}, binarySourceRoots(repoRoot, "guest-runner"), []string{
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	})
	if err != nil {
		return created, reused, artifacts, err
	}
	artifacts.GuestRunnerBuilt = guestBuilt

	if _, statErr := os.Stat(cfg.Runtime.RootfsPath); statErr == nil {
		rebaked, rebakeErr := rebakeGuestRunner(ctx, repoRoot, guestBuilt)
		if rebakeErr != nil {
			return created, reused, artifacts, rebakeErr
		}
		artifacts.RootfsRebaked = rebaked
	}

	if err := EnsureDatabase(cfg.Database.URL, filepath.Join(repoRoot, "db", "schema.sql")); err != nil {
		return created, reused, artifacts, err
	}
	return created, reused, artifacts, nil
}

func Evaluate(repoRoot string, cfg config.Config, artifacts BootstrapArtifacts) []CheckResult {
	results := []CheckResult{
		statusResult("os", "Linux host", runtime.GOOS == "linux", fmt.Sprintf("running on %s", runtime.GOOS), "Run Aegis on Linux with KVM support.", true),
	}

	if _, err := os.Stat("/dev/kvm"); err != nil {
		results = append(results, CheckResult{ID: "kvm", Label: "/dev/kvm access", Status: StatusFail, Detail: "/dev/kvm is missing", Action: "Enable KVM on the host and ensure /dev/kvm exists.", Blocking: true})
	} else if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		_ = f.Close()
		results = append(results, CheckResult{ID: "kvm", Label: "/dev/kvm access", Status: StatusOK, Detail: "current user can read and write /dev/kvm", Blocking: true})
	} else {
		results = append(results, CheckResult{ID: "kvm", Label: "/dev/kvm access", Status: StatusFail, Detail: err.Error(), Action: "Add the user to the kvm group or run within a context that can access /dev/kvm.", Blocking: true})
	}

	if resolved, err := config.ResolveFirecrackerBinary(cfg.Runtime.FirecrackerBin); err == nil {
		results = append(results, CheckResult{ID: "firecracker", Label: "Firecracker", Status: StatusOK, Detail: resolved, Blocking: true})
	} else {
		results = append(results, CheckResult{ID: "firecracker", Label: "Firecracker", Status: StatusFail, Detail: err.Error(), Action: "Install Firecracker or set runtime.firecracker_bin to a valid binary.", Blocking: true})
	}

	results = append(results, fileCheck("kernel", "Kernel image", filepath.Join(cfg.Runtime.AssetsDir, "vmlinux"), true, "Build or install the guest kernel into assets/.")...)
	results = append(results, fileCheck("rootfs", "Rootfs image", cfg.Runtime.RootfsPath, true, "Build or install the rootfs image, then rerun aegis setup.")...)
	results = append(results, fileCheck("policy", "Policy file", cfg.Runtime.PolicyPath, true, "Point runtime.policy_path at a valid policy YAML.")...)
	results = append(results, fileCheck("orchestrator-bin", "Orchestrator binary", cfg.Runtime.OrchestratorBin, true, "Rerun aegis setup to build the orchestrator binary.")...)
	results = append(results, fileCheck("cli-bin", "Aegis CLI binary", cfg.Runtime.CLIBin, false, "Rerun aegis setup to build the CLI binary.")...)
	results = append(results,
		binaryFreshnessCheck("orchestrator-freshness", "Orchestrator freshness", cfg.Runtime.OrchestratorBin, binarySourceRoots(repoRoot, "orchestrator"), true, "Rerun `go run ./cmd/aegis-cli setup` to rebuild the repo-local orchestrator binary from current source."),
		binaryFreshnessCheck("cli-freshness", "Aegis CLI freshness", cfg.Runtime.CLIBin, binarySourceRoots(repoRoot, "cli"), false, "Rerun `go run ./cmd/aegis-cli setup` before using .aegis/bin/aegis so the generated CLI matches current source."),
	)
	results = append(results, fileCheck("signing-seed", "Receipt signing seed", cfg.Receipt.SeedFile, true, "Rerun aegis setup to generate a strict signing seed.")...)

	if err := executor.InitWorkspacesDir(); err != nil {
		results = append(results, CheckResult{ID: "workspaces", Label: "Workspace directory", Status: StatusFail, Detail: err.Error(), Action: "Ensure /tmp/aegis and /tmp/aegis/workspaces are writable.", Blocking: true})
	} else {
		results = append(results, CheckResult{ID: "workspaces", Label: "Workspace directory", Status: StatusOK, Detail: executor.WorkspacesDir, Blocking: true})
	}
	if err := os.MkdirAll(cfg.Runtime.ProofRoot, 0o755); err != nil {
		results = append(results, CheckResult{ID: "proof-root", Label: "Proof directory", Status: StatusFail, Detail: err.Error(), Action: "Ensure runtime.proof_root is writable.", Blocking: true})
	} else {
		results = append(results, CheckResult{ID: "proof-root", Label: "Proof directory", Status: StatusOK, Detail: cfg.Runtime.ProofRoot, Blocking: true})
	}

	if err := EnsureDatabase(cfg.Database.URL, filepath.Join(repoRoot, "db", "schema.sql")); err != nil {
		results = append(results, CheckResult{ID: "database", Label: "Database", Status: StatusFail, Detail: err.Error(), Action: "Start Postgres and ensure database.url is reachable for schema bootstrap.", Blocking: true})
	} else {
		results = append(results, CheckResult{ID: "database", Label: "Database", Status: StatusOK, Detail: "connection and schema ready", Blocking: true})
	}

	if directErr := executor.ValidateCgroupParent(cfg.Runtime.CgroupParent); directErr == nil {
		results = append(results, CheckResult{ID: "cgroup", Label: "cgroup parent", Status: StatusOK, Detail: cfg.Runtime.CgroupParent, Blocking: true})
	} else if scopeReady() {
		results = append(results, CheckResult{ID: "cgroup", Label: "cgroup parent", Status: StatusWarn, Detail: fmt.Sprintf("direct write unavailable: %v", directErr), Action: "aegis serve will use a delegated user scope via systemd-run.", Blocking: false})
	} else {
		results = append(results, CheckResult{ID: "cgroup", Label: "cgroup parent", Status: StatusFail, Detail: directErr.Error(), Action: "Provide a writable delegated cgroup subtree or install systemd-run user scope support.", Blocking: true})
	}

	networkDetail := []string{}
	if _, err := exec.LookPath("ip"); err != nil {
		networkDetail = append(networkDetail, "missing ip")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		networkDetail = append(networkDetail, "missing iptables")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		networkDetail = append(networkDetail, "missing /dev/net/tun")
	}
	if apiKey := strings.TrimSpace(os.Getenv("AEGIS_API_KEY")); apiKey == "" {
		results = append(results, CheckResult{ID: "api-auth", Label: "API auth", Status: StatusWarn, Detail: "AEGIS_API_KEY is unset; serve will run in unauthenticated local dev mode", Action: "Set AEGIS_API_KEY before exposing the API beyond local development.", Blocking: false})
	} else {
		results = append(results, CheckResult{ID: "api-auth", Label: "API auth", Status: StatusOK, Detail: "AEGIS_API_KEY is configured", Blocking: false})
	}

	startupMode := "direct foreground orchestrator"
	if scopeReady() {
		startupMode = "delegated_user_scope via systemd-run --user --scope"
	}
	results = append(results, CheckResult{ID: "startup-mode", Label: "Serve startup mode", Status: StatusOK, Detail: startupMode, Blocking: false})

	if len(networkDetail) == 0 {
		results = append(results, CheckResult{ID: "network", Label: "TAP / network demos", Status: StatusWarn, Detail: "required binaries exist; CAP_NET_ADMIN still depends on host privileges", Action: "If allowlist or broker demos fail, run under a context with CAP_NET_ADMIN or explicit privileged network setup.", Blocking: false})
	} else {
		results = append(results, CheckResult{ID: "network", Label: "TAP / network demos", Status: StatusWarn, Detail: strings.Join(networkDetail, ", "), Action: "Install the missing network prerequisites before running networked demos.", Blocking: false})
	}

	missingBroker := []string{}
	for _, envName := range cfg.Demo.BrokerEnv {
		if strings.TrimSpace(os.Getenv(envName)) == "" {
			missingBroker = append(missingBroker, envName)
		}
	}
	if len(cfg.Demo.BrokerEnv) == 0 {
		results = append(results, CheckResult{ID: "broker-env", Label: "Broker demo env", Status: StatusWarn, Detail: "no optional broker env vars configured", Action: "Set demo.broker_env if you want setup to report broker demo readiness.", Blocking: false})
	} else if len(missingBroker) == 0 {
		results = append(results, CheckResult{ID: "broker-env", Label: "Broker demo env", Status: StatusOK, Detail: strings.Join(cfg.Demo.BrokerEnv, ", "), Blocking: false})
	} else {
		results = append(results, CheckResult{ID: "broker-env", Label: "Broker demo env", Status: StatusWarn, Detail: "missing: " + strings.Join(missingBroker, ", "), Action: "Export the broker env vars before running broker-capable demos.", Blocking: false})
	}

	detail := cfg.Receipt.SigningMode
	if artifacts.SigningSeedKeyID != "" {
		detail = fmt.Sprintf("%s (%s)", cfg.Receipt.SigningMode, artifacts.SigningSeedKeyID)
	}
	results = append(results, CheckResult{ID: "signing-mode", Label: "Signing posture", Status: StatusOK, Detail: detail, Blocking: true})
	return results
}

func EnsureSigningSeed(path string) (bool, string, error) {
	if data, err := os.ReadFile(path); err == nil {
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return false, "", fmt.Errorf("decode signing seed %s: %w", path, err)
		}
		signer, err := receipt.NewSignerFromSeed(seed)
		if err != nil {
			return false, "", fmt.Errorf("load signing seed %s: %w", path, err)
		}
		return false, signer.KeyID, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, "", fmt.Errorf("create signing seed dir: %w", err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return false, "", fmt.Errorf("generate signing seed: %w", err)
	}
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		return false, "", fmt.Errorf("build signer from generated seed: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(seed)
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return false, "", fmt.Errorf("write signing seed: %w", err)
	}
	return true, signer.KeyID, nil
}

func RenderSummary(results []CheckResult) string {
	okCount, warnCount, failCount := 0, 0, 0
	lines := []string{"Readiness summary:"}
	for _, result := range results {
		switch result.Status {
		case StatusOK:
			okCount++
		case StatusWarn:
			warnCount++
		case StatusFail:
			failCount++
		}
		lines = append(lines, fmt.Sprintf("- [%s] %s: %s", result.Status, result.Label, result.Detail))
		if result.Action != "" && result.Status != StatusOK {
			lines = append(lines, fmt.Sprintf("  action: %s", result.Action))
		}
	}
	overall := "ready for local serve"
	if failCount > 0 {
		overall = "not ready for local serve"
	} else if warnCount > 0 {
		overall = "ready for local serve with warnings"
	}
	lines = append(lines,
		fmt.Sprintf("Summary counts: ok=%d warn=%d fail=%d", okCount, warnCount, failCount),
		fmt.Sprintf("Overall status: %s", overall),
	)
	return strings.Join(lines, "\n") + "\n"
}

func EnsureDatabase(targetURL string, schemaPath string) error {
	targetDB, targetErr := sql.Open("postgres", targetURL)
	if targetErr == nil {
		defer targetDB.Close()
		if pingErr := targetDB.Ping(); pingErr == nil {
			return applySchema(targetDB, schemaPath)
		}
	}

	adminURL, dbName, err := adminDatabaseURL(targetURL)
	if err != nil {
		if targetErr != nil {
			return fmt.Errorf("open target db: %w", targetErr)
		}
		return err
	}
	adminDB, err := sql.Open("postgres", adminURL)
	if err != nil {
		return fmt.Errorf("open admin db: %w", err)
	}
	defer adminDB.Close()
	if err := adminDB.Ping(); err != nil {
		return fmt.Errorf("ping admin db: %w", err)
	}
	var exists bool
	if err := adminDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
		return fmt.Errorf("check database existence: %w", err)
	}
	if !exists {
		if _, err := adminDB.Exec(`CREATE DATABASE ` + quoteIdentifier(dbName)); err != nil {
			return fmt.Errorf("create database %s: %w", dbName, err)
		}
	}
	targetDB, err = sql.Open("postgres", targetURL)
	if err != nil {
		return fmt.Errorf("open target db: %w", err)
	}
	defer targetDB.Close()
	if err := targetDB.Ping(); err != nil {
		return fmt.Errorf("ping target db: %w", err)
	}
	return applySchema(targetDB, schemaPath)
}

func fileCheck(id string, label string, path string, blocking bool, action string) []CheckResult {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return []CheckResult{{ID: id, Label: label, Status: StatusOK, Detail: path, Blocking: blocking}}
	}
	return []CheckResult{{ID: id, Label: label, Status: StatusFail, Detail: path + " is missing", Action: action, Blocking: blocking}}
}

func statusResult(id, label string, ok bool, detail, action string, blocking bool) CheckResult {
	if ok {
		return CheckResult{ID: id, Label: label, Status: StatusOK, Detail: detail, Blocking: blocking}
	}
	return CheckResult{ID: id, Label: label, Status: StatusFail, Detail: detail, Action: action, Blocking: blocking}
}

func readyForServe(results []CheckResult) bool {
	for _, result := range results {
		if result.Blocking && result.Status == StatusFail {
			return false
		}
	}
	return true
}

func binarySourceRoots(repoRoot string, kind string) []string {
	roots := []string{filepath.Join(repoRoot, "internal")}
	switch kind {
	case "cli":
		roots = append(roots, filepath.Join(repoRoot, "cmd", "aegis-cli"))
	case "orchestrator":
		roots = append(roots, filepath.Join(repoRoot, "cmd", "orchestrator"))
	case "guest-runner":
		roots = append(roots, filepath.Join(repoRoot, "guest-runner"))
	}
	roots = append(roots, filepath.Join(repoRoot, "go.mod"), filepath.Join(repoRoot, "go.sum"))
	return roots
}

func binaryFreshnessCheck(id string, label string, target string, sourceRoots []string, blocking bool, action string) CheckResult {
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		return CheckResult{ID: id, Label: label, Status: StatusFail, Detail: target + " is missing", Action: action, Blocking: blocking}
	}
	stale, err := targetMissingOrStale(target, sourceRoots)
	if err != nil {
		return CheckResult{ID: id, Label: label, Status: StatusWarn, Detail: err.Error(), Action: action, Blocking: false}
	}
	if stale {
		return CheckResult{ID: id, Label: label, Status: StatusFail, Detail: target + " is older than current source", Action: action, Blocking: blocking}
	}
	return CheckResult{ID: id, Label: label, Status: StatusOK, Detail: "generated binary matches current source timestamps", Blocking: blocking}
}

func findGoBinary() (string, error) {
	candidates := []string{"go", filepath.Join(os.Getenv("HOME"), "local/go/bin/go"), "/usr/local/go/bin/go"}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if filepath.IsAbs(candidate) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("go toolchain not found; install Go or add it to PATH before running aegis setup")
}

func buildIfNeeded(ctx context.Context, dir string, goBin string, target string, packages []string, sourceRoots []string, extraEnv []string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return false, fmt.Errorf("create bin dir for %s: %w", target, err)
	}
	needsBuild, err := targetMissingOrStale(target, sourceRoots)
	if err != nil {
		return false, err
	}
	if !needsBuild {
		return false, nil
	}
	args := append([]string{"build", "-buildvcs=false", "-o", target}, packages...)
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = dir
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("build %s: %w: %s", target, err, strings.TrimSpace(string(output)))
	}
	return true, nil
}

func rebakeGuestRunner(ctx context.Context, repoRoot string, guestRunnerBuilt bool) (bool, error) {
	rootfsPath := filepath.Join(repoRoot, "assets", "alpine-base.ext4")
	if _, err := os.Stat(rootfsPath); err != nil {
		return false, nil
	}
	rootfsInfo, err := os.Stat(rootfsPath)
	if err != nil {
		return false, fmt.Errorf("stat rootfs: %w", err)
	}
	guestInfo, err := os.Stat(filepath.Join(repoRoot, "guest-runner", "guest-runner"))
	if err != nil {
		return false, fmt.Errorf("stat guest-runner binary: %w", err)
	}
	if !guestRunnerBuilt && !guestInfo.ModTime().After(rootfsInfo.ModTime()) {
		return false, nil
	}
	cmd := exec.CommandContext(ctx, filepath.Join(repoRoot, "scripts", "rebake-guest-runner.sh"))
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("rebake guest-runner: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return true, nil
}

func targetMissingOrStale(target string, sourceRoots []string) (bool, error) {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat target %s: %w", target, err)
	}
	targetTime := info.ModTime()
	for _, root := range sourceRoots {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return false, fmt.Errorf("stat source root %s: %w", root, err)
		}
		walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info == nil || info.IsDir() {
				return nil
			}
			if info.ModTime().After(targetTime) {
				return io.EOF
			}
			return nil
		})
		if errors.Is(walkErr, io.EOF) {
			return true, nil
		}
		if walkErr != nil {
			return false, fmt.Errorf("scan sources under %s: %w", root, walkErr)
		}
	}
	return false, nil
}

func applySchema(db *sql.DB, schemaPath string) error {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	if _, err := db.Exec(string(raw)); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

func adminDatabaseURL(targetURL string) (string, string, error) {
	parts := strings.SplitN(targetURL, "?", 2)
	base := parts[0]
	query := ""
	if len(parts) == 2 {
		query = "?" + parts[1]
	}
	slash := strings.LastIndex(base, "/")
	if slash < 0 || slash == len(base)-1 {
		return "", "", fmt.Errorf("database.url must include a database name")
	}
	dbName := base[slash+1:]
	return base[:slash+1] + "postgres" + query, dbName, nil
}

func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func scopeReady() bool {
	_, runErr := exec.LookPath("systemd-run")
	_, ctlErr := exec.LookPath("systemctl")
	return runErr == nil && ctlErr == nil
}

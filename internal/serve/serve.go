package serve

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aegis/internal/config"
	"aegis/internal/setup"
)

type Mode string

const (
	ModeDirect         Mode = "direct"
	ModeDelegatedScope Mode = "delegated_user_scope"
)

type Plan struct {
	Mode     Mode
	Args     []string
	Env      []string
	Warnings []string
}

func BuildPlan(cfg config.Config, checks []setup.CheckResult) (Plan, error) {
	blockers := []string{}
	for _, result := range checks {
		if result.Blocking && result.Status == setup.StatusFail {
			blockers = append(blockers, fmt.Sprintf("%s: %s", result.Label, result.Detail))
		}
	}
	if len(blockers) > 0 {
		return Plan{}, fmt.Errorf("serve prerequisites failed: %s", strings.Join(blockers, "; "))
	}

	envMap := map[string]string{
		"AEGIS_CGROUP_PARENT":            cfg.Runtime.CgroupParent,
		"AEGIS_ROOTFS_PATH":              cfg.Runtime.RootfsPath,
		"AEGIS_PROOF_ROOT":               cfg.Runtime.ProofRoot,
		"AEGIS_UI_DIR":                   cfg.Runtime.UIDir,
		"AEGIS_FIRECRACKER_BIN":          cfg.Runtime.FirecrackerBin,
		"AEGIS_WARM_POOL_SIZE":           fmt.Sprintf("%d", cfg.Runtime.WarmPoolSize),
		"AEGIS_WARM_POOL_MAX_AGE":        fmt.Sprintf("%d", cfg.Runtime.WarmPoolMaxAge),
		"AEGIS_RECEIPT_SIGNING_MODE":     cfg.Receipt.SigningMode,
		"AEGIS_RECEIPT_SIGNING_SEED_B64": mustReadSeed(cfg.Receipt.SeedFile),
	}
	pathValue := os.Getenv("PATH")
	if filepath.IsAbs(cfg.Runtime.FirecrackerBin) {
		envMap["PATH"] = filepath.Dir(cfg.Runtime.FirecrackerBin) + string(os.PathListSeparator) + pathValue
	} else {
		envMap["PATH"] = pathValue
	}
	if apiKey := strings.TrimSpace(os.Getenv("AEGIS_API_KEY")); apiKey != "" {
		envMap["AEGIS_API_KEY"] = apiKey
	}
	for _, envName := range cfg.Demo.BrokerEnv {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			envMap[envName] = value
		}
	}
	env := make([]string, 0, len(envMap))
	for key, value := range envMap {
		env = append(env, key+"="+value)
	}

	plan := Plan{
		Mode: ModeDirect,
		Args: []string{cfg.Runtime.OrchestratorBin, "--db", cfg.Database.URL, "--assets-dir", cfg.Runtime.AssetsDir, "--policy", cfg.Runtime.PolicyPath, "--rootfs-path", cfg.Runtime.RootfsPath},
		Env:  env,
	}
	if haveDelegatedScopeSupport() {
		plan.Mode = ModeDelegatedScope
		plan.Warnings = append(plan.Warnings, "using systemd-run --user --scope for delegated cgroup compatibility")
	}
	for _, result := range checks {
		if result.ID == "cgroup" && result.Status == setup.StatusWarn {
			plan.Mode = ModeDelegatedScope
			plan.Warnings = append(plan.Warnings, result.Detail)
			break
		}
	}
	return plan, nil
}

func Command(plan Plan) *exec.Cmd {
	if plan.Mode == ModeDelegatedScope {
		args := []string{"--user", "--scope", "--property=Delegate=yes", "--quiet"}
		args = append(args, plan.Args...)
		cmd := exec.Command("systemd-run", args...)
		cmd.Env = append(os.Environ(), plan.Env...)
		return cmd
	}
	cmd := exec.Command(plan.Args[0], plan.Args[1:]...)
	cmd.Env = append(os.Environ(), plan.Env...)
	return cmd
}

func mustReadSeed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func haveDelegatedScopeSupport() bool {
	_, runErr := exec.LookPath("systemd-run")
	_, ctlErr := exec.LookPath("systemctl")
	return runErr == nil && ctlErr == nil
}

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aegis/internal/config"
	"aegis/internal/executor"
	"aegis/internal/receipt"

	_ "github.com/lib/pq"
)

type doctorStatus string

const (
	doctorPass doctorStatus = "PASS"
	doctorFail doctorStatus = "FAIL"
	doctorWarn doctorStatus = "WARN"
	doctorSkip doctorStatus = "SKIP"
)

const doctorSelfTestCode = "echo doctor-self-test"

type doctorCheck struct {
	Bucket string
	Label  string
	Status doctorStatus
	Detail string
}

type doctorReadyResponse struct {
	Status               string `json:"status"`
	DBOK                 bool   `json:"db_ok"`
	WorkerSlotsAvailable int    `json:"worker_slots_available"`
	WorkerSlotsTotal     int    `json:"worker_slots_total"`
}

var (
	doctorLoadConfigFunc        = loadServeConfig
	doctorStaticChecksFunc      = doctorStaticChecks
	doctorVerifyBundlePathsFunc = receipt.VerifyBundlePaths
	doctorHTTPClient            = http.DefaultClient
	doctorExecCommandContext    = exec.CommandContext
)

func doctorCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to config yaml")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	repoRoot, err := config.FindRepoRoot("")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cfg, resolvedConfigPath, err := doctorLoadConfigFunc(repoRoot, *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	runtimeURL := doctorRuntimeURL(cfg)
	checks := doctorStaticChecksFunc(repoRoot, cfg)

	healthURL := strings.TrimRight(runtimeURL, "/") + "/v1/health"
	healthReq, err := newRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		checks = append(checks,
			doctorCheck{Bucket: "runtime", Label: "runtime health", Status: doctorFail, Detail: err.Error()},
			doctorCheck{Bucket: "runtime", Label: "runtime ready", Status: doctorSkip, Detail: "skipped because runtime health request could not be constructed"},
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorSkip, Detail: "skipped because runtime is not reachable"},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not run"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}

	var healthOut healthResponse
	if err := doctorDoJSON(healthReq, &healthOut); err != nil {
		checks = append(checks,
			doctorCheck{Bucket: "runtime", Label: "runtime health", Status: doctorFail, Detail: err.Error()},
			doctorCheck{Bucket: "runtime", Label: "runtime ready", Status: doctorSkip, Detail: "skipped because runtime health failed"},
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorSkip, Detail: "skipped because runtime is not reachable"},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not run"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	checks = append(checks, doctorCheck{
		Bucket: "runtime",
		Label:  "runtime health",
		Status: doctorPass,
		Detail: fmt.Sprintf("status=%s workers=%d/%d available", healthOut.Status, healthOut.WorkerSlotsAvailable, healthOut.WorkerSlotsTotal),
	})

	readyReq, err := newRequest(http.MethodGet, strings.TrimRight(runtimeURL, "/")+"/ready", nil)
	if err != nil {
		checks = append(checks,
			doctorCheck{Bucket: "runtime", Label: "runtime ready", Status: doctorFail, Detail: err.Error()},
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorSkip, Detail: "skipped because runtime ready request could not be constructed"},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not run"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}

	var readyOut doctorReadyResponse
	if err := doctorDoJSON(readyReq, &readyOut); err != nil {
		checks = append(checks,
			doctorCheck{Bucket: "runtime", Label: "runtime ready", Status: doctorFail, Detail: err.Error()},
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorSkip, Detail: "skipped because runtime readiness could not be determined"},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not run"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}

	if readyOut.Status != "ready" || !readyOut.DBOK || readyOut.WorkerSlotsAvailable <= 0 {
		checks = append(checks,
			doctorCheck{
				Bucket: "runtime",
				Label:  "runtime ready",
				Status: doctorFail,
				Detail: fmt.Sprintf("status=%s db_ok=%t workers=%d/%d available", readyOut.Status, readyOut.DBOK, readyOut.WorkerSlotsAvailable, readyOut.WorkerSlotsTotal),
			},
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorSkip, Detail: "skipped because runtime is not ready"},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not run"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	checks = append(checks, doctorCheck{
		Bucket: "runtime",
		Label:  "runtime ready",
		Status: doctorPass,
		Detail: fmt.Sprintf("status=%s db_ok=%t workers=%d/%d available", readyOut.Status, readyOut.DBOK, readyOut.WorkerSlotsAvailable, readyOut.WorkerSlotsTotal),
	})

	execResp, execErr := doctorExecuteSelfTest(runtimeURL)
	if execErr != nil {
		checks = append(checks,
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorFail, Detail: execErr.Error()},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test failed before producing a proof bundle"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	if strings.TrimSpace(execResp.Error) != "" || execResp.ExitCode != 0 || !strings.Contains(execResp.Stdout, "doctor-self-test") {
		detail := fmt.Sprintf("execution_id=%s error=%q exit_code=%d", execResp.ExecutionID, execResp.Error, execResp.ExitCode)
		if execResp.ProofDir != "" {
			detail += " proof_dir=" + execResp.ProofDir
		}
		checks = append(checks,
			doctorCheck{Bucket: "execution", Label: "execute self-test", Status: doctorFail, Detail: detail},
			doctorCheck{Bucket: "receipt", Label: "receipt verify", Status: doctorSkip, Detail: "skipped because execution self-test did not succeed cleanly"},
		)
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	checks = append(checks, doctorCheck{
		Bucket: "execution",
		Label:  "execute self-test",
		Status: doctorPass,
		Detail: fmt.Sprintf("execution_id=%s stdout=%q proof_dir=%s", execResp.ExecutionID, strings.TrimSpace(execResp.Stdout), execResp.ProofDir),
	})

	if strings.TrimSpace(execResp.ProofDir) == "" {
		checks = append(checks, doctorCheck{
			Bucket: "receipt",
			Label:  "receipt verify",
			Status: doctorFail,
			Detail: "proof_dir missing from execute response",
		})
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}

	paths, err := receipt.ResolveBundlePaths(os.Getenv("AEGIS_PROOF_ROOT"), "", execResp.ProofDir)
	if err != nil {
		checks = append(checks, doctorCheck{
			Bucket: "receipt",
			Label:  "receipt verify",
			Status: doctorFail,
			Detail: err.Error(),
		})
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	statement, err := doctorVerifyBundlePathsFunc(paths)
	if err != nil {
		checks = append(checks, doctorCheck{
			Bucket: "receipt",
			Label:  "receipt verify",
			Status: doctorFail,
			Detail: err.Error(),
		})
		return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
	}
	checks = append(checks, doctorCheck{
		Bucket: "receipt",
		Label:  "receipt verify",
		Status: doctorPass,
		Detail: fmt.Sprintf("verified execution_id=%s outcome=%s exit_code=%d", statement.Predicate.ExecutionID, statement.Predicate.Outcome.Reason, statement.Predicate.Outcome.ExitCode),
	})

	return renderDoctorReport(stdout, resolvedConfigPath, runtimeURL, checks)
}

func doctorStaticChecks(repoRoot string, cfg config.Config) []doctorCheck {
	checks := []doctorCheck{{
		Bucket: "host",
		Label:  "linux host",
	}}
	if runtime.GOOS == "linux" {
		checks[0].Status = doctorPass
		checks[0].Detail = "running on linux"
	} else {
		checks[0].Status = doctorFail
		checks[0].Detail = "Aegis requires Linux"
	}

	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		_ = f.Close()
		checks = append(checks, doctorCheck{Bucket: "host", Label: "/dev/kvm access", Status: doctorPass, Detail: "current user can read and write /dev/kvm"})
	} else {
		checks = append(checks, doctorCheck{Bucket: "host", Label: "/dev/kvm access", Status: doctorFail, Detail: err.Error()})
	}

	if resolved, err := config.ResolveFirecrackerBinary(cfg.Runtime.FirecrackerBin); err == nil {
		checks = append(checks, doctorCheck{Bucket: "host", Label: "firecracker", Status: doctorPass, Detail: resolved})
	} else {
		checks = append(checks, doctorCheck{Bucket: "host", Label: "firecracker", Status: doctorFail, Detail: err.Error()})
	}

	checks = append(checks, doctorFileCheck("host", "kernel image", filepath.Join(cfg.Runtime.AssetsDir, "vmlinux")))
	checks = append(checks, doctorFileCheck("host", "rootfs", cfg.Runtime.RootfsPath))
	checks = append(checks, doctorRootfsSemanticCheck(cfg.Runtime.RootfsPath))
	checks = append(checks, doctorDatabaseCheck(cfg.Database.URL))
	checks = append(checks, doctorCgroupCheck(cfg.Runtime.CgroupParent))
	return checks
}

func doctorFileCheck(bucket string, label string, path string) doctorCheck {
	if strings.TrimSpace(path) == "" {
		return doctorCheck{Bucket: bucket, Label: label, Status: doctorFail, Detail: "path is empty"}
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return doctorCheck{Bucket: bucket, Label: label, Status: doctorPass, Detail: path}
	} else if err != nil {
		return doctorCheck{Bucket: bucket, Label: label, Status: doctorFail, Detail: err.Error()}
	}
	return doctorCheck{Bucket: bucket, Label: label, Status: doctorFail, Detail: path + " is a directory"}
}

func doctorRootfsSemanticCheck(rootfsPath string) doctorCheck {
	if strings.TrimSpace(rootfsPath) == "" {
		return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorSkip, Detail: "skipped because rootfs path is empty"}
	}
	if _, err := os.Stat(rootfsPath); err != nil {
		return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorSkip, Detail: "skipped because rootfs is missing"}
	}
	if _, err := exec.LookPath("debugfs"); err != nil {
		return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorWarn, Detail: "debugfs not found; semantic check skipped"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	flavorOut, err := doctorExecCommandContext(ctx, "debugfs", "-R", "cat /etc/aegis-rootfs-release", rootfsPath).CombinedOutput()
	if err != nil {
		return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorFail, Detail: strings.TrimSpace(string(flavorOut))}
	}
	if !strings.Contains(string(flavorOut), "rootfs_flavor=alpine") {
		return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorFail, Detail: "/etc/aegis-rootfs-release does not identify the Alpine rootfs"}
	}
	for _, path := range []string{"/sbin/init", "/usr/local/bin/guest-runner"} {
		out, err := doctorExecCommandContext(ctx, "debugfs", "-R", "stat "+path, rootfsPath).CombinedOutput()
		if err != nil {
			return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorFail, Detail: fmt.Sprintf("%s check failed: %s", path, strings.TrimSpace(string(out)))}
		}
	}
	return doctorCheck{Bucket: "host", Label: "rootfs semantic", Status: doctorPass, Detail: "verified via debugfs: /etc/aegis-rootfs-release, /sbin/init, /usr/local/bin/guest-runner"}
}

func doctorDatabaseCheck(dbURL string) doctorCheck {
	if strings.TrimSpace(dbURL) == "" {
		return doctorCheck{Bucket: "host", Label: "database", Status: doctorFail, Detail: "database.url is empty"}
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return doctorCheck{Bucket: "host", Label: "database", Status: doctorFail, Detail: err.Error()}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return doctorCheck{Bucket: "host", Label: "database", Status: doctorFail, Detail: err.Error()}
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'executions')`).Scan(&exists); err != nil {
		return doctorCheck{Bucket: "host", Label: "database", Status: doctorFail, Detail: err.Error()}
	}
	if !exists {
		return doctorCheck{Bucket: "host", Label: "database", Status: doctorFail, Detail: "executions table missing"}
	}
	return doctorCheck{Bucket: "host", Label: "database", Status: doctorPass, Detail: "connection ok, executions table present"}
}

func doctorCgroupCheck(parent string) doctorCheck {
	if err := executor.ValidateCgroupParent(parent); err == nil {
		return doctorCheck{Bucket: "host", Label: "cgroup parent", Status: doctorPass, Detail: parent}
	} else if doctorScopeReady() {
		return doctorCheck{Bucket: "host", Label: "cgroup parent", Status: doctorWarn, Detail: "direct write unavailable; serve can use delegated user scope"}
	} else {
		return doctorCheck{Bucket: "host", Label: "cgroup parent", Status: doctorFail, Detail: err.Error()}
	}
}

func doctorScopeReady() bool {
	_, runErr := exec.LookPath("systemd-run")
	_, ctlErr := exec.LookPath("systemctl")
	return runErr == nil && ctlErr == nil
}

func doctorRuntimeURL(cfg config.Config) string {
	if v := strings.TrimSpace(os.Getenv("AEGIS_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if strings.TrimSpace(cfg.API.URL) != "" {
		return strings.TrimRight(cfg.API.URL, "/")
	}
	return "http://localhost:8080"
}

func doctorDoJSON(req *http.Request, out any) error {
	resp, err := doctorHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		var apiErr apiErrorEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && strings.TrimSpace(apiErr.Error.Message) != "" {
			return errors.New(apiErr.Error.Message)
		}
		return fmt.Errorf("%s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func doctorExecuteSelfTest(runtimeURL string) (executeResponse, error) {
	payload, err := json.Marshal(executeRequest{Lang: "bash", Code: doctorSelfTestCode, TimeoutMs: 4000})
	if err != nil {
		return executeResponse{}, err
	}
	req, err := newRequest(http.MethodPost, strings.TrimRight(runtimeURL, "/")+"/v1/execute", bytes.NewReader(payload))
	if err != nil {
		return executeResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out executeResponse
	if err := doctorDoJSON(req, &out); err != nil {
		return executeResponse{}, err
	}
	return out, nil
}

func renderDoctorReport(stdout io.Writer, configPath string, runtimeURL string, checks []doctorCheck) int {
	fmt.Fprintln(stdout, "Doctor report:")
	fmt.Fprintf(stdout, "- config: %s\n", configPath)
	fmt.Fprintf(stdout, "- runtime: %s\n", runtimeURL)
	for _, bucket := range []string{"host", "runtime", "execution", "receipt"} {
		fmt.Fprintf(stdout, "%s:\n", doctorBucketTitle(bucket))
		for _, check := range checks {
			if check.Bucket != bucket {
				continue
			}
			fmt.Fprintf(stdout, "- [%s] %s: %s\n", check.Status, check.Label, check.Detail)
		}
	}
	hostStatus := doctorBucketStatus(checks, "host")
	runtimeStatus := doctorBucketStatus(checks, "runtime")
	executionStatus := doctorBucketStatus(checks, "execution")
	receiptStatus := doctorBucketStatus(checks, "receipt")
	fmt.Fprintln(stdout, "Overall:")
	fmt.Fprintf(stdout, "- host_ready=%s\n", hostStatus)
	fmt.Fprintf(stdout, "- runtime_ready=%s\n", runtimeStatus)
	fmt.Fprintf(stdout, "- execution_path_ready=%s\n", executionStatus)
	fmt.Fprintf(stdout, "- receipt_path_ready=%s\n", receiptStatus)
	if hostStatus == doctorFail || runtimeStatus == doctorFail || executionStatus == doctorFail || receiptStatus == doctorFail {
		return 1
	}
	return 0
}

func doctorBucketTitle(bucket string) string {
	if bucket == "" {
		return ""
	}
	return strings.ToUpper(bucket[:1]) + bucket[1:]
}

func doctorBucketStatus(checks []doctorCheck, bucket string) doctorStatus {
	status := doctorSkip
	for _, check := range checks {
		if check.Bucket != bucket {
			continue
		}
		switch check.Status {
		case doctorFail:
			return doctorFail
		case doctorWarn:
			if status != doctorPass {
				status = doctorWarn
			}
		case doctorPass:
			status = doctorPass
		case doctorSkip:
			if status == doctorSkip {
				status = doctorSkip
			}
		}
	}
	return status
}

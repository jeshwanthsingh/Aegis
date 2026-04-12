package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aegis/internal/api"
	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/observability"
	"aegis/internal/policy"
	warmpool "aegis/internal/pool"
	"aegis/internal/receipt"
	"aegis/internal/store"
	"aegis/internal/telemetry"
)

var (
	globScratchPathsFunc       = filepath.Glob
	readFileFunc               = os.ReadFile
	removePathFunc             = os.Remove
	findProcessFunc            = os.FindProcess
	markInFlightReconciledFunc = func(s *store.Store) error {
		if s == nil {
			return nil
		}
		return s.MarkInFlightReconciled()
	}
	markExecutionReconciledFunc = func(s *store.Store, executionID string) error {
		if s == nil {
			return nil
		}
		return s.MarkReconciled(executionID)
	}
	loadExecutionRecordFunc = func(s *store.Store, executionID string) (store.ExecutionRecord, error) {
		if s == nil {
			return store.ExecutionRecord{}, sql.ErrNoRows
		}
		return s.GetExecution(executionID)
	}
	emitReconciledReceiptFunc = emitReconciledReceipt
)

func main() {
	dbConn := flag.String("db", "postgres://localhost/aegis?sslmode=disable", "postgres connection string")
	policyPath := flag.String("policy", "configs/default-policy.yaml", "path to policy yaml")
	assetsDir := flag.String("assets-dir", "", "path to assets directory (vmlinux, rootfs images)")
	rootfsPath := flag.String("rootfs-path", os.Getenv("AEGIS_ROOTFS_PATH"), "optional rootfs image override for migration/rollback")
	flag.Parse()

	if err := os.MkdirAll("/tmp/aegis", 0o700); err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "create_tmp_dir", "error": err.Error()})
	}
	if err := os.Chmod("/tmp/aegis", 0o700); err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "chmod_tmp_dir", "error": err.Error()})
	}
	if err := executor.InitWorkspacesDir(); err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "init_workspaces_dir", "error": err.Error()})
	}

	s, err := store.Connect(*dbConn)
	if err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "connect_postgres", "error": err.Error()})
	}

	cgroupParent := executor.DefaultCgroupParent()
	if err := executor.ValidateCgroupParent(cgroupParent); err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "validate_cgroup_parent", "error": err.Error(), "cgroup_parent": cgroupParent})
	}
	observability.Info("cgroup_parent_ready", observability.Fields{"cgroup_parent": cgroupParent})

	reconcile(s)
	if err := executor.CleanupLeakedNetworks(); err != nil {
		observability.Warn("reconcile_leaked_networks_failed", observability.Fields{"error": err.Error()})
	}

	pol, err := policy.Load(*policyPath)
	if err != nil {
		observability.Fatal("startup_failed", observability.Fields{"step": "load_policy", "error": err.Error(), "policy_path": *policyPath})
	}
	observability.Info("policy_loaded", observability.Fields{"policy_path": *policyPath})

	apiKey := os.Getenv("AEGIS_API_KEY")
	if apiKey == "" {
		observability.Warn("auth_disabled", observability.Fields{"message": "AEGIS_API_KEY not set, running in unauthenticated dev mode"})
	}

	pool := executor.NewPool(5)
	observability.SetWorkerSlotsFunc(pool.Available)
	registry := api.NewBusRegistry()
	stats := api.NewStatsCounter()
	warmPool := warmpool.New(warmpool.Config{
		Size:   envInt("AEGIS_WARM_POOL_SIZE", 0),
		MaxAge: time.Duration(envInt("AEGIS_WARM_POOL_MAX_AGE", 300)) * time.Second,
		Shapes: warmpool.DefaultShapes(envInt("AEGIS_WARM_POOL_SIZE", 0), *assetsDir, *rootfsPath, pol),
	})
	warmPool.Start()
	defer warmPool.Close()
	uiDir := os.Getenv("AEGIS_UI_DIR")
	if uiDir == "" {
		uiDir = "ui"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", api.HandleHealth(pool, warmPool))
	mux.HandleFunc("GET /v1/health", api.HandleHealth(pool, warmPool))
	mux.HandleFunc("GET /ready", api.HandleReady(s, pool, warmPool))
	mux.HandleFunc("GET /metrics", observability.HandleMetrics())
	mux.HandleFunc("GET /v1/stats", api.NewStatsHandler(stats))
	mux.HandleFunc("GET /v1/events/{exec_id}", api.NewTelemetryHandler(registry))
	mux.HandleFunc("POST /v1/workspaces/{id}", api.WithAuth(apiKey, api.HandleCreateWorkspace()))
	mux.HandleFunc("DELETE /v1/workspaces/{id}", api.WithAuth(apiKey, api.HandleDeleteWorkspace()))
	mux.HandleFunc("/v1/execute", api.WithAuth(apiKey, api.NewHandler(s, pool, warmPool, pol, *assetsDir, *rootfsPath, registry, stats, filepath.Base(*policyPath))))
	mux.HandleFunc("/v1/execute/stream", api.WithAuth(apiKey, api.NewStreamHandler(s, pool, warmPool, pol, *assetsDir, *rootfsPath, registry, stats, filepath.Base(*policyPath))))
	if info, err := os.Stat(uiDir); err == nil && info.IsDir() {
		uiFS := http.FileServer(http.Dir(uiDir))
		mux.Handle("GET /ui/", http.StripPrefix("/ui/", uiFS))
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(uiDir, "index.html"))
		})
		observability.Info("ui_enabled", observability.Fields{"ui_dir": uiDir})
	} else if err != nil {
		observability.Warn("ui_disabled", observability.Fields{"ui_dir": uiDir, "error": err.Error()})
	} else {
		observability.Warn("ui_disabled", observability.Fields{"ui_dir": uiDir, "error": fmt.Sprintf("%s is not a directory", uiDir)})
	}

	observability.Info("server_listen", observability.Fields{"addr": ":8080"})
	if err := http.ListenAndServe(":8080", mux); err != nil {
		observability.Fatal("server_stopped", observability.Fields{"error": err.Error()})
	}
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

// reconcile cleans up orphaned scratch images and sockets from a previous crash.
func reconcile(s *store.Store) {
	cgroupParent := executor.DefaultCgroupParent()
	if err := markInFlightReconciledFunc(s); err != nil {
		observability.Warn("reconcile_mark_inflight_failed", observability.Fields{"error": err.Error()})
	}
	matches, err := globScratchPathsFunc("/tmp/aegis/scratch-*.ext4")
	if err != nil || len(matches) == 0 {
		return
	}
	observability.Info("reconcile_orphaned_scratch_found", observability.Fields{"count": len(matches)})

	for _, scratchPath := range matches {
		base := filepath.Base(scratchPath)
		uuid := strings.TrimSuffix(strings.TrimPrefix(base, "scratch-"), ".ext4")

		socketPath := "/tmp/aegis/fc-" + uuid + ".sock"
		vsockPath := "/tmp/aegis/vsock-" + uuid + ".sock"
		cgPath := executor.CgroupPath(cgroupParent, uuid)
		cleanup := telemetry.CleanupDoneData{}

		procsPath := cgPath + "/cgroup.procs"
		if data, err := readFileFunc(procsPath); err == nil {
			for _, pidStr := range strings.Fields(string(data)) {
				if pid, err := strconv.Atoi(pidStr); err == nil {
					if proc, err := findProcessFunc(pid); err == nil {
						_ = proc.Kill()
						observability.Warn("reconcile_orphaned_pid_killed", observability.Fields{"execution_id": uuid, "pid": pid})
					}
				}
			}
		}

		for _, f := range []string{scratchPath, socketPath, vsockPath} {
			if err := removePathFunc(f); err == nil {
				observability.Info("reconcile_orphaned_file_removed", observability.Fields{"execution_id": uuid, "file": filepath.Base(f)})
				switch f {
				case scratchPath:
					cleanup.ScratchRemoved = true
				case socketPath, vsockPath:
					cleanup.SocketRemoved = true
				}
			}
		}
		if err := removePathFunc(cgPath); err == nil {
			cleanup.CgroupRemoved = true
		}
		cleanup.AllClean = cleanup.ScratchRemoved && cleanup.SocketRemoved && cleanup.CgroupRemoved

		rec, err := loadExecutionRecordFunc(s, uuid)
		if err == sql.ErrNoRows {
			observability.Info("reconcile_untracked_warm_orphan_removed", observability.Fields{"execution_id": uuid})
			continue
		}
		if err != nil {
			observability.Warn("reconcile_load_execution_failed", observability.Fields{"execution_id": uuid, "error": err.Error()})
			continue
		}
		if err := markExecutionReconciledFunc(s, uuid); err != nil {
			observability.Warn("reconcile_mark_execution_failed", observability.Fields{"execution_id": uuid, "error": err.Error()})
			continue
		}
		if rec.Status != store.StatusReconciled {
			continue
		}
		if paths, err := emitReconciledReceiptFunc(rec, cleanup); err != nil {
			observability.Warn("reconcile_receipt_failed", observability.Fields{"execution_id": uuid, "error": err.Error()})
		} else {
			observability.Info("reconcile_receipt_written", observability.Fields{"execution_id": uuid, "proof_dir": paths.ProofDir})
		}
	}
}

func emitReconciledReceipt(rec store.ExecutionRecord, cleanup telemetry.CleanupDoneData) (receipt.BundlePaths, error) {
	finishedAt := time.Now().UTC()
	startedAt := rec.CreatedAt.UTC()
	if startedAt.IsZero() {
		startedAt = finishedAt
	}
	cleanupBytes, err := json.Marshal(cleanup)
	if err != nil {
		return receipt.BundlePaths{}, fmt.Errorf("marshal reconcile cleanup event: %w", err)
	}
	events := []telemetry.Event{{
		ExecID:    rec.ExecutionID,
		Timestamp: finishedAt.UnixNano(),
		Kind:      telemetry.KindCleanupDone,
		Data:      cleanupBytes,
	}}
	stderrData := "recovered_on_boot\n"
	signer, err := receipt.NewSignerFromEnv()
	if err != nil {
		return receipt.BundlePaths{}, err
	}
	signedReceipt, err := receipt.BuildSignedReceipt(receipt.Input{
		ExecutionID:     rec.ExecutionID,
		Backend:         models.BackendFirecracker,
		ExecutionStatus: store.StatusReconciled,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
		Outcome: receipt.Outcome{
			ExitCode:           -1,
			Reason:             "recovered_on_boot",
			ContainmentVerdict: "contained",
			OutputTruncated:    false,
		},
		TelemetryEvents: events,
		OutputArtifacts: receipt.ArtifactsFromBundleOutputs(rec.ExecutionID, "", stderrData, false),
		Attributes:      map[string]string{"reconciled": "true"},
	}, signer)
	if err != nil {
		return receipt.BundlePaths{}, err
	}
	return receipt.WriteProofBundle(receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT"))), rec.ExecutionID, signedReceipt, signer.PublicKey, "", stderrData, false)
}

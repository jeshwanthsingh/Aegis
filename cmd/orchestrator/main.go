package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"aegis/internal/api"
	"aegis/internal/executor"
	"aegis/internal/observability"
	"aegis/internal/policy"
	"aegis/internal/store"
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
	uiDir := os.Getenv("AEGIS_UI_DIR")
	if uiDir == "" {
		uiDir = "ui"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", api.HandleHealth(pool))
	mux.HandleFunc("GET /ready", api.HandleReady(s, pool))
	mux.HandleFunc("GET /metrics", observability.HandleMetrics())
	mux.HandleFunc("GET /v1/stats", api.NewStatsHandler(stats))
	mux.HandleFunc("GET /v1/events/{exec_id}", api.NewTelemetryHandler(registry))
	mux.HandleFunc("DELETE /v1/workspaces/{id}", api.WithAuth(apiKey, api.HandleDeleteWorkspace()))
	mux.HandleFunc("/v1/execute", api.WithAuth(apiKey, api.NewHandler(s, pool, pol, *assetsDir, *rootfsPath, registry, stats, filepath.Base(*policyPath))))
	mux.HandleFunc("/v1/execute/stream", api.WithAuth(apiKey, api.NewStreamHandler(s, pool, pol, *assetsDir, *rootfsPath, registry, stats, filepath.Base(*policyPath))))
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

// reconcile cleans up orphaned scratch images and sockets from a previous crash.
func reconcile(s *store.Store) {
	matches, err := filepath.Glob("/tmp/aegis/scratch-*.ext4")
	if err != nil || len(matches) == 0 {
		return
	}
	observability.Info("reconcile_orphaned_scratch_found", observability.Fields{"count": len(matches)})

	for _, scratchPath := range matches {
		base := filepath.Base(scratchPath)
		uuid := strings.TrimSuffix(strings.TrimPrefix(base, "scratch-"), ".ext4")

		socketPath := "/tmp/aegis/fc-" + uuid + ".sock"
		vsockPath := "/tmp/aegis/vsock-" + uuid + ".sock"
		cgPath := "/sys/fs/cgroup/aegis/" + uuid

		procsPath := cgPath + "/cgroup.procs"
		if data, err := os.ReadFile(procsPath); err == nil {
			for _, pidStr := range strings.Fields(string(data)) {
				if pid, err := strconv.Atoi(pidStr); err == nil {
					if proc, err := os.FindProcess(pid); err == nil {
						_ = proc.Kill()
						observability.Warn("reconcile_orphaned_pid_killed", observability.Fields{"execution_id": uuid, "pid": pid})
					}
				}
			}
		}

		for _, f := range []string{scratchPath, socketPath, vsockPath} {
			if err := os.Remove(f); err == nil {
				observability.Info("reconcile_orphaned_file_removed", observability.Fields{"execution_id": uuid, "file": filepath.Base(f)})
			}
		}
		_ = os.Remove(cgPath)

		if err := s.MarkSandboxError(uuid); err != nil {
			observability.Warn("reconcile_mark_sandbox_error_failed", observability.Fields{"execution_id": uuid, "error": err.Error()})
		}
	}
}

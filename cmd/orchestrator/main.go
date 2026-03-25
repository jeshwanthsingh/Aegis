package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"aegis/internal/api"
	"aegis/internal/executor"
	"aegis/internal/policy"
	"aegis/internal/store"
)

func main() {
	dbConn := flag.String("db", "postgres://localhost/aegis?sslmode=disable", "postgres connection string")
	policyPath := flag.String("policy", "configs/default-policy.yaml", "path to policy yaml")
	assetsDir := flag.String("assets-dir", "", "path to assets directory (vmlinux, alpine-base.ext4)")
	flag.Parse()

	if err := os.MkdirAll("/tmp/aegis", 0o755); err != nil {
		log.Fatalf("create /tmp/aegis: %v", err)
	}

	s, err := store.Connect(*dbConn)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}

	reconcile(s)
	if err := executor.CleanupLeakedNetworks(); err != nil {
		log.Printf("reconcile leaked networks: %v", err)
	}


	pol, err := policy.Load(*policyPath)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	log.Printf("policy loaded: %s", *policyPath)

	apiKey := os.Getenv("AEGIS_API_KEY")
	if apiKey == "" {
		log.Println("WARNING: AEGIS_API_KEY not set, running in unauthenticated dev mode")
	}

	pool := executor.NewPool(5)
	http.HandleFunc("GET /health", api.HandleHealth(pool))
	http.HandleFunc("/v1/execute", api.WithAuth(apiKey, api.NewHandler(s, pool, pol, *assetsDir)))
	http.HandleFunc("/v1/execute/stream", api.WithAuth(apiKey, api.NewStreamHandler(s, pool, pol, *assetsDir)))

	fmt.Println("Aegis orchestrator listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// reconcile cleans up orphaned scratch images and sockets from a previous crash.
func reconcile(s *store.Store) {
	matches, err := filepath.Glob("/tmp/aegis/scratch-*.ext4")
	if err != nil || len(matches) == 0 {
		return
	}
	log.Printf("reconcile: found %d orphaned scratch image(s)", len(matches))

	for _, scratchPath := range matches {
		base := filepath.Base(scratchPath)
		uuid := strings.TrimSuffix(strings.TrimPrefix(base, "scratch-"), ".ext4")

		socketPath := fmt.Sprintf("/tmp/aegis/fc-%s.sock", uuid)
		vsockPath := fmt.Sprintf("/tmp/aegis/vsock-%s.sock", uuid)
		cgPath := fmt.Sprintf("/sys/fs/cgroup/aegis/%s", uuid)

		procsPath := cgPath + "/cgroup.procs"
		if data, err := os.ReadFile(procsPath); err == nil {
			for _, pidStr := range strings.Fields(string(data)) {
				if pid, err := strconv.Atoi(pidStr); err == nil {
					if proc, err := os.FindProcess(pid); err == nil {
						proc.Kill()
						log.Printf("reconcile [%s]: killed orphaned pid %d", uuid, pid)
					}
				}
			}
		}

		for _, f := range []string{scratchPath, socketPath, vsockPath} {
			if err := os.Remove(f); err == nil {
				log.Printf("reconcile [%s]: removed %s", uuid, filepath.Base(f))
			}
		}
		os.Remove(cgPath)

		if err := s.MarkSandboxError(uuid); err != nil {
			log.Printf("reconcile [%s]: mark sandbox_error: %v", uuid, err)
		}
	}
}
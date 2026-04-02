package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/observability"
	"aegis/internal/policy"
	"aegis/internal/store"
	"aegis/internal/telemetry"

	"github.com/google/uuid"
)

type ExecuteRequest struct {
	ExecutionID string `json:"execution_id,omitempty"`
	Lang        string `json:"lang"`
	Code        string `json:"code"`
	TimeoutMs   int    `json:"timeout_ms"`
	Profile     string `json:"profile,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}

type ExecuteResponse struct {
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	ExitCode        int    `json:"exit_code,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	ExecutionID     string `json:"execution_id"`
	Error           string `json:"error,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}

const startupSlack = 15 * time.Second

// WithAuth wraps a handler with Bearer token authentication.
// If apiKey is empty the handler runs unauthenticated (dev mode).
func WithAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	if apiKey == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func HandleDeleteWorkspace() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := r.PathValue("id")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "workspace ID is required"})
			return
		}
		if err := executor.DeleteWorkspace(id); err != nil {
			status := http.StatusInternalServerError
			switch {
			case errors.Is(err, executor.ErrInvalidWorkspaceID):
				status = http.StatusBadRequest
			case errors.Is(err, os.ErrNotExist):
				status = http.StatusNotFound
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "workspace_id": id})
	}
}

func NewHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, policyVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
			resp.DurationMs = time.Since(start).Milliseconds()
			rec.DurationMs = resp.DurationMs
			if err := s.WriteExecution(rec); err != nil {
				observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": resp.ExecutionID, "error": err.Error()})
			}
			_ = json.NewEncoder(w).Encode(resp)
		}

		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many concurrent executions"}`))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			execID := uuid.New().String()
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				execStatus = "request_too_large"
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: "request_too_large"})
			} else {
				execStatus = "invalid_request"
				respond(ExecuteResponse{ExecutionID: execID, Error: "invalid request: " + err.Error()}, store.ExecutionRecord{ExecutionID: execID, Lang: "unknown", Outcome: "error", ErrorMsg: err.Error()})
			}
			return
		}

		execID, err := chooseExecutionID(req.ExecutionID)
		if err != nil {
			execStatus = "invalid_request"
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{Error: err.Error()})
			return
		}
		bus, execID, err := claimExecutionBus(registry, execID, req.ExecutionID != "")
		if err != nil {
			execStatus = "conflict"
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: err.Error()})
			return
		}
		defer func() {
			bus.Close()
			registry.Complete(execID)
		}()

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		if req.Profile == "" {
			req.Profile = pol.DefaultProfile
		}
		computeProfile, ok := pol.Profiles[req.Profile]
		if !ok {
			execStatus = "invalid_profile"
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: "invalid compute profile"})
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: err.Error()})
			return
		}

		var (
			vm              *executor.VMInstance
			exitCode        int
			exitReason      = "completed"
			outputTruncated bool
			recordStats     bool
			receiptPolicy   = buildReceiptPolicy(pol, policyVersion, req.Profile)
		)

		defer func() {
			cleanup := cleanupFromVM(vm)
			network := buildReceiptNetwork(pol, bus.Drain())
			receipt := models.ContainmentReceipt{
				ExecID:     execID,
				StartedAt:  start.Format(time.RFC3339Nano),
				EndedAt:    time.Now().Format(time.RFC3339Nano),
				DurationMs: time.Since(start).Milliseconds(),
				Language:   req.Lang,
				Policy:     receiptPolicy,
				Network:    network,
				Exit: models.ReceiptExit{
					Code:            exitCode,
					Reason:          exitReason,
					OutputTruncated: outputTruncated,
				},
				Cleanup: cleanup,
				Verdict: verdictFor(exitCode, exitReason),
			}
			bus.Emit(telemetry.KindReceipt, receipt)
			if recordStats && stats != nil {
				stats.RecordReceipt(receipt)
			}
		}()

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond+startupSlack)
		defer cancel()
		deadline, _ := ctx.Deadline()
		observability.Info("execution_start", observability.Fields{"execution_id": execID, "lang": req.Lang, "timeout_ms": timeoutMs, "deadline": deadline.Format(time.RFC3339Nano)})

		bootStart := time.Now()
		bootObserved := false
		recordBoot := func() {
			if bootObserved {
				return
			}
			bootObserved = true
			observability.ObserveBootDuration(time.Since(bootStart))
		}

		vm, err = executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
		if err != nil {
			recordBoot()
			if errors.Is(err, executor.ErrInvalidWorkspaceID) {
				execStatus = "validation_error"
				msg := err.Error()
				respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
				return
			}
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			respond(ExecuteResponse{ExecutionID: execID, Error: err.Error()}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()})
			return
		}
		defer func() {
			teardownStart := time.Now()
			if err := executor.Teardown(vm, bus); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources, bus); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			respond(ExecuteResponse{ExecutionID: execID, Error: err.Error()}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()})
			return
		}

		pollCtx, cancelPoller := context.WithCancel(ctx)
		defer cancelPoller()
		stopPoller := telemetry.StartCgroupPoller(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := executor.StartProxyHandler(proxyCtx, vm.GuestCID, execID); err != nil && proxyCtx.Err() == nil {
				observability.Warn("proxy_handler_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()

		conn, err := executor.DialWithRetry(vm.VsockPath, 1024, time.Until(deadline))
		if err != nil {
			recordBoot()
			outcome, status := "error", "sandbox_error"
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
				execStatus = "timeout"
				exitReason = "timeout"
			}
			recordStats = true
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			return
		}
		defer conn.Close()
		recordBoot()
		bus.Emit(telemetry.KindVMBootReady, map[string]interface{}{
			"elapsed_ms": time.Since(bootStart).Milliseconds(),
		})

		observability.Info("vsock_connected", observability.Fields{"execution_id": execID, "remaining_ms": time.Until(deadline).Milliseconds()})

		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, PidsLimit: pol.Resources.PidsMax, WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}

		result, err := executor.SendPayload(conn, payload, deadline, bus)
		if err != nil {
			outcome, status := "error", "sandbox_error"
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
				execStatus = "timeout"
				exitReason = "timeout"
			}
			recordStats = true
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			return
		}

		outcome := "success"
		execStatus = "success"
		if result.ExitCode != 0 {
			outcome = "completed_nonzero"
			execStatus = "completed_nonzero"
		}
		exitCode = result.ExitCode
		exitReason = result.ExitReason
		if exitReason == "" {
			exitReason = "completed"
		}
		outputTruncated = result.OutputTruncated
		recordStats = true
		respond(ExecuteResponse{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, ExecutionID: execID, OutputTruncated: result.OutputTruncated}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: "completed", StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes})
	}
}

func NewStreamHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, policyVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many concurrent executions"}`))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				execStatus = "request_too_large"
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: "request_too_large"})
			} else {
				execStatus = "invalid_request"
				_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: "invalid request: " + err.Error()})
			}
			return
		}

		execID, err := chooseExecutionID(req.ExecutionID)
		if err != nil {
			execStatus = "invalid_request"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{Error: err.Error()})
			return
		}
		bus, execID, err := claimExecutionBus(registry, execID, req.ExecutionID != "")
		if err != nil {
			execStatus = "conflict"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: err.Error()})
			return
		}
		defer func() {
			bus.Close()
			registry.Complete(execID)
		}()

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		if req.Profile == "" {
			req.Profile = pol.DefaultProfile
		}
		computeProfile, ok := pol.Profiles[req.Profile]
		if !ok {
			execStatus = "invalid_profile"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: "invalid compute profile"})
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: err.Error()})
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			execStatus = "streaming_unsupported"
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Execution-ID", execID)
		var (
			vm              *executor.VMInstance
			exitCode        int
			exitReason      = "completed"
			outputTruncated bool
			recordStats     bool
			receiptPolicy   = buildReceiptPolicy(pol, policyVersion, req.Profile)
		)

		defer func() {
			cleanup := cleanupFromVM(vm)
			network := buildReceiptNetwork(pol, bus.Drain())
			receipt := models.ContainmentReceipt{
				ExecID:     execID,
				StartedAt:  start.Format(time.RFC3339Nano),
				EndedAt:    time.Now().Format(time.RFC3339Nano),
				DurationMs: time.Since(start).Milliseconds(),
				Language:   req.Lang,
				Policy:     receiptPolicy,
				Network:    network,
				Exit: models.ReceiptExit{
					Code:            exitCode,
					Reason:          exitReason,
					OutputTruncated: outputTruncated,
				},
				Cleanup: cleanup,
				Verdict: verdictFor(exitCode, exitReason),
			}
			bus.Emit(telemetry.KindReceipt, receipt)
			if recordStats && stats != nil {
				stats.RecordReceipt(receipt)
			}
		}()

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond+startupSlack)
		defer cancel()
		deadline, _ := ctx.Deadline()
		observability.Info("stream_execution_start", observability.Fields{"execution_id": execID, "lang": req.Lang, "timeout_ms": timeoutMs, "deadline": deadline.Format(time.RFC3339Nano)})

		bootStart := time.Now()
		bootObserved := false
		recordBoot := func() {
			if bootObserved {
				return
			}
			bootObserved = true
			observability.ObserveBootDuration(time.Since(bootStart))
		}

		vm, err = executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
		if err != nil {
			recordBoot()
			if errors.Is(err, executor.ErrInvalidWorkspaceID) {
				execStatus = "validation_error"
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: err.Error()})
				return
			}
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		defer func() {
			teardownStart := time.Now()
			if err := executor.Teardown(vm, bus); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources, bus); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		pollCtx, cancelPoller := context.WithCancel(ctx)
		defer cancelPoller()
		stopPoller := telemetry.StartCgroupPoller(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := executor.StartProxyHandler(proxyCtx, vm.GuestCID, execID); err != nil && proxyCtx.Err() == nil {
				observability.Warn("proxy_handler_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()

		conn, err := executor.DialWithRetry(vm.VsockPath, 1024, time.Until(deadline))
		if err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			outcome := "error"
			exitCode = -1
			exitReason = "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				execStatus = "timeout"
				outcome = "timeout"
				exitReason = "timeout"
			}
			recordStats = true
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}
		defer conn.Close()
		recordBoot()
		bus.Emit(telemetry.KindVMBootReady, map[string]interface{}{
			"elapsed_ms": time.Since(bootStart).Milliseconds(),
		})

		if err := conn.SetDeadline(deadline); err != nil {
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, PidsLimit: pol.Resources.PidsMax, WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		result, err := executor.ReadChunks(conn, deadline, func(chunkType, chunk string) {
			writeSSE(w, flusher, models.GuestChunk{Type: chunkType, Chunk: chunk})
		}, bus)
		if err != nil {
			execStatus = "sandbox_error"
			outcome := err.Error()
			exitCode = -1
			exitReason = "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				execStatus = "timeout"
				outcome = "timeout"
				exitReason = "timeout"
			}
			recordStats = true
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}

		writeSSE(w, flusher, models.GuestChunk{Type: "done", ExitCode: result.ExitCode, DurationMs: result.DurationMs})
		outcome := "success"
		execStatus = "success"
		if result.ExitCode != 0 {
			outcome = "completed_nonzero"
			execStatus = "completed_nonzero"
		}
		exitCode = result.ExitCode
		exitReason = result.ExitReason
		if exitReason == "" {
			exitReason = "completed"
		}
		outputTruncated = result.OutputTruncated
		recordStats = true
		if err := s.WriteExecution(store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: "completed", DurationMs: time.Since(start).Milliseconds(), StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes}); err != nil {
			observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
		}
	}
}

func buildReceiptPolicy(pol *policy.Policy, version string, profile string) models.ReceiptPolicy {
	if pol == nil {
		return models.ReceiptPolicy{Version: version, Profile: profile}
	}
	return models.ReceiptPolicy{
		Version:        version,
		Profile:        profile,
		NetworkMode:    pol.Network.Mode,
		AllowedDomains: policyAllowedDomains(pol),
		CgroupLimits: models.ReceiptCgroupLimits{
			MemoryMax: strconv.Itoa(pol.Resources.MemoryMaxMB) + "M",
			PidsMax:   strconv.Itoa(pol.Resources.PidsMax),
			CpuQuota:  strconv.Itoa(pol.Resources.CPUPercent*1000) + " 100000",
			Swap:      "disabled",
		},
	}
}

func policyAllowedDomains(pol *policy.Policy) []string {
	if pol == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var domains []string
	for _, preset := range pol.Network.Presets {
		for _, host := range policy.NetworkPresets[preset] {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			domains = append(domains, host)
		}
	}
	slices.Sort(domains)
	return domains
}

func cleanupFromVM(vm *executor.VMInstance) models.ReceiptCleanup {
	if vm == nil {
		return models.ReceiptCleanup{}
	}
	return models.ReceiptCleanup{
		TapRemoved:     vm.Cleanup.TapRemoved,
		CgroupRemoved:  vm.Cleanup.CgroupRemoved,
		ScratchRemoved: vm.Cleanup.ScratchRemoved,
		SocketRemoved:  vm.Cleanup.SocketRemoved,
		AllClean:       vm.Cleanup.AllClean,
	}
}

func buildReceiptNetwork(pol *policy.Policy, events []telemetry.Event) models.ReceiptNetwork {
	summary := models.ReceiptNetwork{
		NetworkMode:    "",
		AllowedDomains: nil,
	}
	if pol != nil {
		summary.NetworkMode = pol.Network.Mode
		summary.AllowedDomains = policyAllowedDomains(pol)
	}
	for _, event := range events {
		switch event.Kind {
		case telemetry.KindDNSQuery:
			var data telemetry.DNSQueryData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				continue
			}
			summary.DNSQueriesTotal++
			switch data.Action {
			case "allow":
				summary.DNSQueriesAllowed++
			case "deny":
				summary.DNSQueriesDenied++
			}
		case telemetry.KindNetRuleAdd:
			summary.IptablesRulesAdded++
		}
	}
	return summary
}

func verdictFor(exitCode int, reason string) string {
	if exitCode == 0 && reason == "completed" {
		return "completed"
	}
	return "contained"
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, chunk models.GuestChunk) {
	b, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n\n"))
	flusher.Flush()
}

func chooseExecutionID(raw string) (string, error) {
	if raw == "" {
		return uuid.New().String(), nil
	}
	if strings.TrimSpace(raw) != raw {
		return "", errors.New("invalid execution_id")
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return "", errors.New("invalid execution_id")
	}
	return parsed.String(), nil
}

func claimExecutionBus(registry *BusRegistry, execID string, clientSupplied bool) (*telemetry.Bus, string, error) {
	for {
		bus := telemetry.NewBus(execID)
		if registry.TryRegister(execID, bus) {
			return bus, execID, nil
		}
		if clientSupplied {
			return nil, execID, errors.New("execution_id already in use")
		}
		execID = uuid.New().String()
	}
}

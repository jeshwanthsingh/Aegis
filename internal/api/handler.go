package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/observability"
	"aegis/internal/policy"
	"aegis/internal/store"

	"github.com/google/uuid"
)

type ExecuteRequest struct {
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
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "workspace_id": id})
	}
}

func NewHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string) http.HandlerFunc {
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
			execID := uuid.New().String()
			respond(ExecuteResponse{ExecutionID: execID, Error: "invalid compute profile"}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: "invalid compute profile"})
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			execID := uuid.New().String()
			msg := err.Error()
			respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
			return
		}

		execID := uuid.New().String()
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

		vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir)
		if err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			respond(ExecuteResponse{ExecutionID: execID, Error: err.Error()}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()})
			return
		}
		defer func() {
			teardownStart := time.Now()
			if err := executor.Teardown(vm); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			respond(ExecuteResponse{ExecutionID: execID, Error: err.Error()}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()})
			return
		}

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
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
				execStatus = "timeout"
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			return
		}
		defer conn.Close()
		recordBoot()

		observability.Info("vsock_connected", observability.Fields{"execution_id": execID, "remaining_ms": time.Until(deadline).Milliseconds()})

		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}

		result, err := executor.SendPayload(conn, payload, deadline)
		if err != nil {
			outcome, status := "error", "sandbox_error"
			execStatus = "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
				execStatus = "timeout"
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			return
		}

		outcome := "success"
		execStatus = "success"
		if result.ExitCode != 0 {
			outcome = "completed_nonzero"
			execStatus = "completed_nonzero"
		}
		respond(ExecuteResponse{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, ExecutionID: execID, OutputTruncated: result.OutputTruncated}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: "completed", StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes})
	}
}

func NewStreamHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string) http.HandlerFunc {
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
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: "invalid compute profile"})
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: err.Error()})
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

		execID := uuid.New().String()
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

		vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir)
		if err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		defer func() {
			teardownStart := time.Now()
			if err := executor.Teardown(vm); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

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
			if ctx.Err() == context.DeadlineExceeded {
				execStatus = "timeout"
				outcome = "timeout"
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}
		defer conn.Close()
		recordBoot()

		if err := conn.SetDeadline(deadline); err != nil {
			execStatus = "sandbox_error"
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			execStatus = "sandbox_error"
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		result, err := executor.ReadChunks(conn, deadline, func(chunkType, chunk string) { writeSSE(w, flusher, models.GuestChunk{Type: chunkType, Chunk: chunk}) })
		if err != nil {
			execStatus = "sandbox_error"
			outcome := err.Error()
			if ctx.Err() == context.DeadlineExceeded {
				execStatus = "timeout"
				outcome = "timeout"
			}
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
		if err := s.WriteExecution(store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: "completed", DurationMs: time.Since(start).Milliseconds(), StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes}); err != nil {
			observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
		}
	}
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

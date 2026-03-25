package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/policy"
	"aegis/internal/store"

	"github.com/google/uuid"
)

type ExecuteRequest struct {
	Lang      string `json:"lang"`
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
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
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

// HandleHealth returns server liveness and worker pool capacity.
// No auth required - safe to call from load balancers and monitoring.
func HandleHealth(pool *executor.Pool) http.HandlerFunc {
	type healthResponse struct {
		Status               string `json:"status"`
		WorkerSlotsAvailable int    `json:"worker_slots_available"`
		WorkerSlotsTotal     int    `json:"worker_slots_total"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(healthResponse{
			Status:               "ok",
			WorkerSlotsAvailable: pool.Available(),
			WorkerSlotsTotal:     5,
		})
	}
}

func NewHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
			resp.DurationMs = time.Since(start).Milliseconds()
			rec.DurationMs = resp.DurationMs
			if err := s.WriteExecution(rec); err != nil {
				log.Printf("audit log [%s]: %v", resp.ExecutionID, err)
			}
			json.NewEncoder(w).Encode(resp)
		}

		if err := pool.Acquire(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many concurrent executions"}`))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			execID := uuid.New().String()
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: execID, Error: "request_too_large"})
			} else {
				respond(
					ExecuteResponse{ExecutionID: execID, Error: "invalid request: " + err.Error()},
					store.ExecutionRecord{ExecutionID: execID, Lang: "unknown", Outcome: "error", ErrorMsg: err.Error()},
				)
			}
			return
		}

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execID := uuid.New().String()
			msg := err.Error()
			respond(
				ExecuteResponse{ExecutionID: execID, Error: msg},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg},
			)
			return
		}

		execID := uuid.New().String()
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		log.Printf("[%s] lang=%s timeout_ms=%d deadline=%s", execID, req.Lang, timeoutMs, deadline.Format("15:04:05.000"))

		vm, err := executor.NewVM(execID, pol, assetsDir)
		if err != nil {
			respond(
				ExecuteResponse{ExecutionID: execID, Error: err.Error()},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()},
			)
			return
		}
		defer executor.Teardown(vm)

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources); err != nil {
			respond(
				ExecuteResponse{ExecutionID: execID, Error: err.Error()},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()},
			)
			return
		}

		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := executor.StartProxyHandler(proxyCtx, vm.GuestCID, execID); err != nil && proxyCtx.Err() == nil {
				log.Printf("[%s] proxy handler: %v", execID, err)
			}
		}()

		conn, err := executor.DialWithRetry(vm.VsockPath, 1024, time.Until(deadline))
		if err != nil {
			outcome, status := "error", "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
			}
			respond(
				ExecuteResponse{ExecutionID: execID, Error: outcome},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()},
			)
			return
		}
		defer conn.Close()

		log.Printf("[%s] vsock connected, %.0fms remaining", execID, float64(time.Until(deadline).Milliseconds()))

		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs}

		result, err := executor.SendPayload(conn, payload, deadline)
		if err != nil {
			outcome, status := "error", "sandbox_error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome, status = "timeout", "timed_out"
			}
			respond(
				ExecuteResponse{ExecutionID: execID, Error: outcome},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()},
			)
			return
		}

		outcome := "success"
		if result.ExitCode != 0 {
			outcome = "completed_nonzero"
		}
		respond(
			ExecuteResponse{
				Stdout:          result.Stdout,
				Stderr:          result.Stderr,
				ExitCode:        result.ExitCode,
				ExecutionID:     execID,
				OutputTruncated: result.OutputTruncated,
			},
			store.ExecutionRecord{
				ExecutionID: execID,
				Lang:        req.Lang,
				ExitCode:    result.ExitCode,
				Outcome:     outcome,
				Status:      "completed",
				StdoutBytes: result.StdoutBytes,
				StderrBytes: result.StderrBytes,
			},
		)
	}
}

func NewStreamHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy, assetsDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		if err := pool.Acquire(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many concurrent executions"}`))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: "request_too_large"})
			} else {
				json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: "invalid request: " + err.Error()})
			}
			return
		}

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ExecuteResponse{ExecutionID: uuid.New().String(), Error: err.Error()})
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		execID := uuid.New().String()
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		log.Printf("[%s] stream lang=%s timeout_ms=%d deadline=%s", execID, req.Lang, timeoutMs, deadline.Format("15:04:05.000"))

		vm, err := executor.NewVM(execID, pol, assetsDir)
		if err != nil {
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		defer executor.Teardown(vm)

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID, pol.Resources); err != nil {
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := executor.StartProxyHandler(proxyCtx, vm.GuestCID, execID); err != nil && proxyCtx.Err() == nil {
				log.Printf("[%s] proxy handler: %v", execID, err)
			}
		}()

		conn, err := executor.DialWithRetry(vm.VsockPath, 1024, time.Until(deadline))
		if err != nil {
			outcome := "error"
			if ctx.Err() == context.DeadlineExceeded {
				outcome = "timeout"
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}
		defer conn.Close()

		if err := conn.SetDeadline(deadline); err != nil {
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs}
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		result, err := executor.ReadChunks(conn, deadline, func(chunkType, chunk string) {
			writeSSE(w, flusher, models.GuestChunk{Type: chunkType, Chunk: chunk})
		})
		if err != nil {
			outcome := err.Error()
			if ctx.Err() == context.DeadlineExceeded {
				outcome = "timeout"
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}

		writeSSE(w, flusher, models.GuestChunk{Type: "done", ExitCode: result.ExitCode, DurationMs: result.DurationMs})
		outcome := "success"
		if result.ExitCode != 0 {
			outcome = "completed_nonzero"
		}
		if err := s.WriteExecution(store.ExecutionRecord{
			ExecutionID: execID,
			Lang:        req.Lang,
			ExitCode:    result.ExitCode,
			Outcome:     outcome,
			Status:      "completed",
			DurationMs:  time.Since(start).Milliseconds(),
			StdoutBytes: result.StdoutBytes,
			StderrBytes: result.StderrBytes,
		}); err != nil {
			log.Printf("audit log [%s]: %v", execID, err)
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
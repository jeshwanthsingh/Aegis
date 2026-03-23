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
// No auth required — safe to call from load balancers and monitoring.
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

func NewHandler(s *store.Store, pool *executor.Pool, pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "application/json")

		// Enforce 128KB request body limit before any reading.
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
			resp.DurationMs = time.Since(start).Milliseconds()
			rec.DurationMs = resp.DurationMs
			if err := s.WriteExecution(rec); err != nil {
				log.Printf("audit log [%s]: %v", resp.ExecutionID, err)
			}
			json.NewEncoder(w).Encode(resp)
		}

		// Capacity check — reject before doing any work
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
		// Context is created AFTER acquiring the pool slot so the timeout clock
		// does not tick while waiting for capacity.
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()

		deadline, _ := ctx.Deadline()
		log.Printf("[%s] lang=%s timeout_ms=%d deadline=%s",
			execID, req.Lang, timeoutMs, deadline.Format("15:04:05.000"))

		vm, err := executor.NewVM(execID)
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

		log.Printf("[%s] vsock connected, %.0fms remaining",
			execID, float64(time.Until(deadline).Milliseconds()))

		result, err := executor.SendPayload(conn, models.Payload{Lang: req.Lang, Code: req.Code}, deadline)
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
				Outcome:     "success",
				Status:      "completed",
				StdoutBytes: result.StdoutBytes,
				StderrBytes: result.StderrBytes,
			},
		)
	}
}


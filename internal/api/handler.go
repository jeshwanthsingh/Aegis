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

func NewHandler(s *store.Store, pool *executor.Pool) http.HandlerFunc {
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
			execID := uuid.New().String()
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(ExecuteResponse{
				ExecutionID: execID,
				Error:       "worker pool at capacity, try again later",
			})
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

		if req.Lang != "python" && req.Lang != "bash" && req.Lang != "node" {
			execID := uuid.New().String()
			msg := "unsupported lang: must be python or bash"
			respond(
				ExecuteResponse{ExecutionID: execID, Error: msg},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg},
			)
			return
		}
		if len(req.Code) > 64*1024 {
			execID := uuid.New().String()
			msg := "code exceeds 64KB limit"
			respond(
				ExecuteResponse{ExecutionID: execID, Error: msg},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg},
			)
			return
		}
		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = 500
		}
		if timeoutMs > 10000 {
			execID := uuid.New().String()
			msg := "timeout_ms exceeds maximum of 10000"
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

		if err := executor.SetupCgroup(execID, vm.FirecrackerPID); err != nil {
			respond(
				ExecuteResponse{ExecutionID: execID, Error: err.Error()},
				store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: "sandbox_error", ErrorMsg: err.Error()},
			)
			return
		}

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

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

	"aegis/internal/broker"
	"aegis/internal/executor"
	"aegis/internal/models"
	"aegis/internal/observability"
	"aegis/internal/policy"
	policycontract "aegis/internal/policy/contract"
	policydivergence "aegis/internal/policy/divergence"
	policyevaluator "aegis/internal/policy/evaluator"
	warmpool "aegis/internal/pool"
	"aegis/internal/receipt"
	"aegis/internal/store"
	"aegis/internal/telemetry"

	"github.com/google/uuid"
)

type ExecuteRequest struct {
	ExecutionID string          `json:"execution_id,omitempty"`
	Lang        string          `json:"lang"`
	Code        string          `json:"code"`
	TimeoutMs   int             `json:"timeout_ms"`
	Profile     string          `json:"profile,omitempty"`
	WorkspaceID string          `json:"workspace_id,omitempty"`
	Intent      json.RawMessage `json:"intent,omitempty"`
}

type ExecuteResponse struct {
	Stdout               string `json:"stdout,omitempty"`
	Stderr               string `json:"stderr,omitempty"`
	ExitCode             int    `json:"exit_code,omitempty"`
	ExitReason           string `json:"exit_reason,omitempty"`
	DurationMs           int64  `json:"duration_ms"`
	ExecutionID          string `json:"execution_id"`
	Error                string `json:"error,omitempty"`
	OutputTruncated      bool   `json:"output_truncated,omitempty"`
	ProofDir             string `json:"proof_dir,omitempty"`
	ReceiptPath          string `json:"receipt_path,omitempty"`
	ReceiptPublicKeyPath string `json:"receipt_public_key_path,omitempty"`
	ReceiptSummaryPath   string `json:"receipt_summary_path,omitempty"`
}

const startupSlack = 15 * time.Second

var (
	acquireExecutionVMFunc  = acquireExecutionVM
	setupCgroupFunc         = executor.SetupCgroup
	teardownVMFunc          = executor.Teardown
	startBrokerListenerFunc = executor.StartBrokerListener
	dialWithRetryFunc       = executor.DialWithRetry
	sendPayloadFunc         = executor.SendPayload
	readChunksFunc          = executor.ReadChunks
	startCgroupPollerFunc   = telemetry.StartCgroupPoller
	emitSignedReceiptFunc   = emitSignedReceipt
)

func buildPointEvaluator(req ExecuteRequest) (*policyevaluator.Evaluator, *policycontract.IntentContract, error) {
	if len(req.Intent) == 0 {
		return nil, nil, nil
	}
	intent, err := policycontract.LoadIntentContractJSON(req.Intent)
	if err != nil {
		return nil, nil, err
	}
	if req.ExecutionID != "" && req.ExecutionID != intent.ExecutionID {
		return nil, nil, errors.New("intent.execution_id must match execution_id")
	}
	if req.Lang != "" && req.Lang != intent.Language {
		return nil, nil, errors.New("intent.language must match lang")
	}
	eval := policyevaluator.New(intent)
	return eval, &intent, nil
}

func guestPidsLimit(lang string, intent *policycontract.IntentContract, defaultLimit int) int {
	if defaultLimit <= 0 {
		return 0
	}
	if intent == nil || intent.ProcessScope.AllowShell {
		return defaultLimit
	}
	switch strings.TrimSpace(lang) {
	case "python", "node":
		return 0
	default:
		return defaultLimit
	}
}
func requestedExecutionID(req ExecuteRequest, intent *policycontract.IntentContract) string {
	if req.ExecutionID != "" {
		return req.ExecutionID
	}
	if intent != nil {
		return intent.ExecutionID
	}
	return ""
}

func warmEligible(req ExecuteRequest, warm *warmpool.Manager, pol *policy.Policy) bool {
	if warm == nil || !warm.Enabled() || pol == nil {
		return false
	}
	if req.WorkspaceID != "" {
		return false
	}
	return req.Profile == pol.DefaultProfile
}

func acquireExecutionVM(ctx context.Context, warm *warmpool.Manager, execID string, req ExecuteRequest, pol *policy.Policy, computeProfile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*executor.VMInstance, string, error) {
	if warmEligible(req, warm, pol) {
		vm, ok, err := warm.Claim(ctx)
		if ok && err == nil {
			vm.CgroupID = execID
			return vm, "warm", nil
		}
		if err != nil {
			observability.Warn("warm_pool_claim_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
		}
	} else if warm != nil && warm.Enabled() {
		warm.RecordColdFallback()
	}
	vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
	if vm != nil {
		vm.CgroupID = execID
	}
	return vm, "cold", err
}

// WithAuth wraps a handler with Bearer token authentication.
// If apiKey is empty the handler runs unauthenticated (dev mode).
func WithAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	if apiKey == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if authorization == "" {
			writeAPIError(w, http.StatusUnauthorized, "auth_required", "Authorization header missing", errorDetails("header", "Authorization"))
			return
		}
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authorization, bearerPrefix) {
			writeAPIError(w, http.StatusUnauthorized, "auth_invalid", "Authorization header must use Bearer token", errorDetails("header", "Authorization"))
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authorization, bearerPrefix))
		if token == "" || token != apiKey {
			writeAPIError(w, http.StatusUnauthorized, "auth_invalid", "Authorization token invalid", nil)
			return
		}
		next(w, r)
	}
}

func HandleDeleteWorkspace() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_request", "workspace ID is required", errorDetails("path_param", "id"))
			return
		}
		if err := executor.DeleteWorkspace(id); err != nil {
			switch {
			case errors.Is(err, executor.ErrInvalidWorkspaceID):
				writeAPIError(w, http.StatusBadRequest, "invalid_workspace_id", err.Error(), errorDetails("workspace_id", id))
			case errors.Is(err, os.ErrNotExist):
				writeAPIError(w, http.StatusNotFound, "workspace_not_found", err.Error(), errorDetails("workspace_id", id))
			default:
				writeAPIError(w, http.StatusInternalServerError, "workspace_delete_failed", err.Error(), errorDetails("workspace_id", id))
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "workspace_id": id})
	}
}

func NewHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, policyVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		proofRoot := receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT")))
		proofPaths := receipt.BundlePaths{}
		respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
			resp.DurationMs = time.Since(start).Milliseconds()
			resp = withReceiptProof(resp, proofPaths)
			rec.DurationMs = resp.DurationMs
			if err := writeExecutionRecord(s, rec); err != nil {
				observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": resp.ExecutionID, "error": err.Error()})
			}
			writeJSON(w, http.StatusOK, resp)
		}

		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent executions", errorDetails("retry_after_seconds", 5))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := decodeJSONBody(r.Body, &req); err != nil {
			execStatus = "invalid_request"
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				execStatus = "request_too_large"
				writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 128 KiB limit", errorDetails("max_bytes", maxBytesErr.Limit))
			} else {
				writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid request body", errorDetails("cause", err.Error()))
			}
			return
		}

		pointEvaluator, intent, err := buildPointEvaluator(req)
		if err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
			return
		}
		var divergenceEvaluator *policydivergence.Evaluator
		if intent != nil {
			divergenceEvaluator = policydivergence.New(*intent)
		}

		execID, err := chooseExecutionID(requestedExecutionID(req, intent))
		if err != nil {
			execStatus = "invalid_request"
			writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error(), errorDetails("field", "execution_id"))
			return
		}
		bus, execID, err := claimExecutionBus(registry, execID, requestedExecutionID(req, intent) != "")
		if err != nil {
			execStatus = "conflict"
			writeAPIError(w, http.StatusConflict, "execution_conflict", err.Error(), errorDetails("execution_id", execID))
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
			writeAPIError(w, http.StatusBadRequest, "invalid_profile", "invalid compute profile", errorDetails("profile", req.Profile))
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
			return
		}

		var (
			vm              *executor.VMInstance
			exitCode        int
			exitReason      = "completed"
			outputTruncated bool
			stdoutData      string
			stderrData      string
			recordStats     bool
			receiptPolicy   = buildReceiptPolicy(pol, policyVersion, req.Profile)
		)

		receiptEmitted := false

		defer func() {
			if receiptEmitted {
				return
			}
			finishedAt := time.Now()
			containmentReceipt, _, _ := emitSignedReceiptFunc(execID, start, finishedAt, req, intent, vm, pol, receiptPolicy, exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus)
			if recordStats && stats != nil {
				stats.RecordReceipt(containmentReceipt)
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

		var vmPath string
		claimStart := time.Now()
		vm, vmPath, err = acquireExecutionVMFunc(ctx, warm, execID, req, pol, computeProfile, assetsDir, rootfsPath, bus)
		claimElapsed := time.Since(claimStart)
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
		observability.Info("vm_acquired", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": claimElapsed.Milliseconds()})
		defer func() {
			teardownStart := time.Now()
			if err := teardownVMFunc(vm, bus); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()
		vm.CgroupID = execID

		if err := setupCgroupFunc(execID, vm.FirecrackerPID, pol.Resources, bus); err != nil {
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
		stopPoller := startCgroupPollerFunc(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		var brokerInst *broker.Broker
		if intent != nil && len(intent.BrokerScope.AllowedDomains) > 0 {
			brokerInst = broker.New(intent.BrokerScope, execID, bus)
		}
		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := startBrokerListenerFunc(proxyCtx, vm.VsockPath, brokerInst, divergenceEvaluator); err != nil && proxyCtx.Err() == nil {
				observability.Warn("broker_listener_error", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()

		conn, err := dialWithRetryFunc(vm.VsockPath, executor.GuestExecPort, time.Until(deadline))
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
		observability.ObserveVMReadyDuration(vmPath, time.Since(bootStart))
		observability.RecordExecutionPath(vmPath)
		bus.Emit(telemetry.KindVMBootReady, map[string]interface{}{
			"elapsed_ms": time.Since(bootStart).Milliseconds(),
			"path":       vmPath,
		})

		observability.Info("vsock_connected", observability.Fields{"execution_id": execID, "remaining_ms": time.Until(deadline).Milliseconds()})

		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, PidsLimit: guestPidsLimit(req.Lang, intent, pol.Resources.PidsMax), WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}
		observability.Info("payload_dispatch_start", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": time.Since(start).Milliseconds()})

		result, err := sendPayloadFunc(conn, payload, deadline, bus, pointEvaluator, divergenceEvaluator, enforcementCallback(execID, vm, bus))
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

		exitCode = result.ExitCode
		exitReason = result.ExitReason
		if exitReason == "" {
			exitReason = "completed"
		}
		outcome, status, metricStatus := classifyExecutionResult(exitCode, exitReason)
		execStatus = metricStatus
		outputTruncated = result.OutputTruncated
		stdoutData = result.Stdout
		stderrData = result.Stderr
		recordStats = true
		finishedAt := time.Now()
		containmentReceipt, actualProofPaths, receiptErr := emitSignedReceiptFunc(execID, start, finishedAt, req, intent, vm, pol, receiptPolicy, exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus)
		if receiptErr != nil {
			execStatus = "receipt_error"
			recordStats = true
			rec := store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: "receipt_error", StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes, ErrorMsg: receiptErr.Error(), DurationMs: time.Since(start).Milliseconds()}
			if err := writeExecutionRecord(s, rec); err != nil {
				observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
			writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
			return
		}
		proofPaths = actualProofPaths
		receiptEmitted = true
		if stats != nil {
			stats.RecordReceipt(containmentReceipt)
		}
		respond(ExecuteResponse{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, ExitReason: exitReason, ExecutionID: execID, OutputTruncated: result.OutputTruncated}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: status, StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes})
	}
}

func NewStreamHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, policyVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent executions", errorDetails("retry_after_seconds", 5))
			return
		}
		defer pool.Release()

		var req ExecuteRequest
		if err := decodeJSONBody(r.Body, &req); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				execStatus = "request_too_large"
				writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 128 KiB limit", errorDetails("max_bytes", maxBytesErr.Limit))
			} else {
				execStatus = "invalid_request"
				writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid request body", errorDetails("cause", err.Error()))
			}
			return
		}

		pointEvaluator, intent, err := buildPointEvaluator(req)
		if err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
			return
		}
		var divergenceEvaluator *policydivergence.Evaluator
		if intent != nil {
			divergenceEvaluator = policydivergence.New(*intent)
		}

		execID, err := chooseExecutionID(requestedExecutionID(req, intent))
		if err != nil {
			execStatus = "invalid_request"
			writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error(), errorDetails("field", "execution_id"))
			return
		}
		bus, execID, err := claimExecutionBus(registry, execID, requestedExecutionID(req, intent) != "")
		if err != nil {
			execStatus = "conflict"
			writeAPIError(w, http.StatusConflict, "execution_conflict", err.Error(), errorDetails("execution_id", execID))
			return
		}
		defer func() {
			bus.Close()
			registry.Complete(execID)
		}()

		proofRoot := receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT")))

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
			writeAPIError(w, http.StatusBadRequest, "invalid_profile", "invalid compute profile", errorDetails("profile", req.Profile))
			return
		}
		if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			execStatus = "streaming_unsupported"
			writeAPIError(w, http.StatusInternalServerError, "streaming_unsupported", "streaming unsupported", nil)
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
			stdoutData      string
			stderrData      string
			recordStats     bool
			receiptPolicy   = buildReceiptPolicy(pol, policyVersion, req.Profile)
		)

		receiptEmitted := false

		defer func() {
			if receiptEmitted {
				return
			}
			finishedAt := time.Now()
			containmentReceipt, _, _ := emitSignedReceiptFunc(execID, start, finishedAt, req, intent, vm, pol, receiptPolicy, exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus)
			if recordStats && stats != nil {
				stats.RecordReceipt(containmentReceipt)
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

		var vmPath string
		claimStart := time.Now()
		vm, vmPath, err = acquireExecutionVMFunc(ctx, warm, execID, req, pol, computeProfile, assetsDir, rootfsPath, bus)
		claimElapsed := time.Since(claimStart)
		if err != nil {
			recordBoot()
			if errors.Is(err, executor.ErrInvalidWorkspaceID) {
				execStatus = "validation_error"
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
				return
			}
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		observability.Info("vm_acquired", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": claimElapsed.Milliseconds()})
		defer func() {
			teardownStart := time.Now()
			if err := teardownVMFunc(vm, bus); err != nil {
				observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
			} else {
				observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
			}
			observability.ObserveTeardownDuration(time.Since(teardownStart))
		}()
		vm.CgroupID = execID

		if err := setupCgroupFunc(execID, vm.FirecrackerPID, pol.Resources, bus); err != nil {
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
		stopPoller := startCgroupPollerFunc(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		var brokerInst *broker.Broker
		if intent != nil && len(intent.BrokerScope.AllowedDomains) > 0 {
			brokerInst = broker.New(intent.BrokerScope, execID, bus)
		}
		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := startBrokerListenerFunc(proxyCtx, vm.VsockPath, brokerInst, divergenceEvaluator); err != nil && proxyCtx.Err() == nil {
				observability.Warn("broker_listener_error", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()

		conn, err := dialWithRetryFunc(vm.VsockPath, executor.GuestExecPort, time.Until(deadline))
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
		observability.ObserveVMReadyDuration(vmPath, time.Since(bootStart))
		observability.RecordExecutionPath(vmPath)
		bus.Emit(telemetry.KindVMBootReady, map[string]interface{}{
			"elapsed_ms": time.Since(bootStart).Milliseconds(),
			"path":       vmPath,
		})

		if err := conn.SetDeadline(deadline); err != nil {
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		payload := models.Payload{Lang: req.Lang, Code: req.Code, TimeoutMs: timeoutMs, PidsLimit: guestPidsLimit(req.Lang, intent, pol.Resources.PidsMax), WorkspaceRequested: req.WorkspaceID != ""}
		if vm.Network != nil {
			payload.NetworkRequested = true
			payload.GuestIP = vm.Network.GuestIP
			payload.GatewayIP = vm.Network.GatewayIP
			payload.DNSServer = vm.Network.GatewayIP
		}
		observability.Info("payload_dispatch_start", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": time.Since(start).Milliseconds()})
		if err := json.NewEncoder(conn).Encode(payload); err != nil {
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		result, err := readChunksFunc(conn, deadline, func(chunkType, chunk string) {
			writeSSE(w, flusher, models.GuestChunk{Type: chunkType, Chunk: chunk})
		}, bus, pointEvaluator, divergenceEvaluator, enforcementCallback(execID, vm, bus))
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

		exitCode = result.ExitCode
		exitReason = result.ExitReason
		if exitReason == "" {
			exitReason = "completed"
		}
		outcome, status, metricStatus := classifyExecutionResult(exitCode, exitReason)
		execStatus = metricStatus
		outputTruncated = result.OutputTruncated
		stdoutData = result.Stdout
		stderrData = result.Stderr
		recordStats = true
		finishedAt := time.Now()
		containmentReceipt, proofPaths, receiptErr := emitSignedReceiptFunc(execID, start, finishedAt, req, intent, vm, pol, receiptPolicy, exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus)
		if receiptErr != nil {
			execStatus = "receipt_error"
			recordStats = true
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
			return
		}
		receiptEmitted = true
		if stats != nil {
			stats.RecordReceipt(containmentReceipt)
		}
		if proofPaths.ReceiptPath != "" {
			writeSSE(w, flusher, proofChunk(execID, proofPaths))
		}
		writeSSE(w, flusher, models.GuestChunk{Type: "done", ExitCode: result.ExitCode, Reason: exitReason, DurationMs: result.DurationMs})
		if err := writeExecutionRecord(s, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: status, DurationMs: time.Since(start).Milliseconds(), StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes}); err != nil {
			observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "error": err.Error()})
		}
	}
}

func withReceiptProof(resp ExecuteResponse, proofPaths receipt.BundlePaths) ExecuteResponse {
	if proofPaths.ReceiptPath == "" {
		return resp
	}
	resp.ProofDir = proofPaths.ProofDir
	resp.ReceiptPath = proofPaths.ReceiptPath
	resp.ReceiptPublicKeyPath = proofPaths.PublicKeyPath
	resp.ReceiptSummaryPath = proofPaths.SummaryPath
	return resp
}

func proofChunk(execID string, proofPaths receipt.BundlePaths) models.GuestChunk {
	return models.GuestChunk{
		Type:                 "proof",
		ExecutionID:          execID,
		ProofDir:             proofPaths.ProofDir,
		ReceiptPath:          proofPaths.ReceiptPath,
		ReceiptPublicKeyPath: proofPaths.PublicKeyPath,
		ReceiptSummaryPath:   proofPaths.SummaryPath,
		ArtifactCount:        proofPaths.ArtifactCount,
		DivergenceVerdict:    proofPaths.DivergenceVerdict,
	}
}

func emitSignedReceipt(execID string, startedAt time.Time, finishedAt time.Time, req ExecuteRequest, intent *policycontract.IntentContract, vm *executor.VMInstance, pol *policy.Policy, receiptPolicy models.ReceiptPolicy, exitCode int, exitReason string, outputTruncated bool, stdoutData string, stderrData string, proofRoot string, bus *telemetry.Bus) (models.ContainmentReceipt, receipt.BundlePaths, error) {
	events := bus.Drain()
	cleanup := cleanupFromVM(vm)
	network := buildReceiptNetwork(pol, events)
	containmentReceipt := models.ContainmentReceipt{
		ExecID:     execID,
		StartedAt:  startedAt.Format(time.RFC3339Nano),
		EndedAt:    finishedAt.Format(time.RFC3339Nano),
		DurationMs: finishedAt.Sub(startedAt).Milliseconds(),
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
	signer, signerErr := receipt.NewSignerFromEnv()
	if signerErr != nil {
		observability.Error("receipt_signer_init_failed", observability.Fields{"execution_id": execID, "error": signerErr.Error()})
		return containmentReceipt, receipt.BundlePaths{}, signerErr
	}
	artifacts := receipt.ArtifactsFromBundleOutputs(execID, stdoutData, stderrData, outputTruncated)
	signedReceipt, buildErr := receipt.BuildSignedReceipt(receipt.Input{
		ExecutionID:     execID,
		WorkflowID:      workflowID(intent),
		Backend:         models.BackendFirecracker,
		TaskClass:       taskClass(intent),
		DeclaredPurpose: declaredPurpose(intent),
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
		IntentRaw:       cloneRawJSON(req.Intent),
		Outcome: receipt.Outcome{
			ExitCode:           exitCode,
			Reason:             exitReason,
			ContainmentVerdict: containmentReceipt.Verdict,
			OutputTruncated:    outputTruncated,
		},
		TelemetryEvents: events,
		OutputArtifacts: artifacts,
		Attributes:      receiptAttributes(intent),
	}, signer)
	if buildErr != nil {
		observability.Error("receipt_build_failed", observability.Fields{"execution_id": execID, "error": buildErr.Error()})
		return containmentReceipt, receipt.BundlePaths{}, buildErr
	}
	bus.Emit(telemetry.KindReceipt, signedReceipt)
	observability.Info("receipt_built", observability.Fields{"execution_id": execID, "artifact_count": len(signedReceipt.Statement.Subject), "divergence_verdict": signedReceipt.Statement.Predicate.Divergence.Verdict})
	observability.Info("receipt_signed", observability.Fields{"execution_id": execID, "signer_key_id": signedReceipt.Statement.Predicate.SignerKeyID})
	paths, writeErr := receipt.WriteProofBundle(proofRoot, execID, signedReceipt, signer.PublicKey, stdoutData, stderrData, outputTruncated)
	if writeErr != nil {
		observability.Error("receipt_bundle_write_failed", observability.Fields{"execution_id": execID, "error": writeErr.Error()})
		return containmentReceipt, receipt.BundlePaths{}, writeErr
	}
	observability.Info("receipt_bundle_written", observability.Fields{"execution_id": execID, "proof_dir": paths.ProofDir, "artifact_count": paths.ArtifactCount, "divergence_verdict": paths.DivergenceVerdict})
	return containmentReceipt, paths, nil
}

func workflowID(intent *policycontract.IntentContract) string {
	if intent == nil {
		return ""
	}
	return intent.WorkflowID
}

func taskClass(intent *policycontract.IntentContract) string {
	if intent == nil {
		return ""
	}
	return intent.TaskClass
}

func declaredPurpose(intent *policycontract.IntentContract) string {
	if intent == nil {
		return ""
	}
	return intent.DeclaredPurpose
}

func receiptAttributes(intent *policycontract.IntentContract) map[string]string {
	if intent == nil || len(intent.Attributes) == 0 {
		return map[string]string{}
	}
	attrs := make(map[string]string, len(intent.Attributes))
	for key, value := range intent.Attributes {
		attrs[key] = value
	}
	return attrs
}

func cloneRawJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return copied
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

func classifyExecutionResult(exitCode int, exitReason string) (string, string, string) {
	if exitReason == "divergence_terminated" {
		return "contained", "terminated_on_divergence", "contained"
	}
	if strings.HasPrefix(exitReason, "security_denied") {
		return "contained", "security_denied", "contained"
	}
	if exitCode != 0 {
		return "completed_nonzero", "completed", "completed_nonzero"
	}
	return "success", "completed", "success"
}

func enforcementCallback(execID string, vm *executor.VMInstance, bus *telemetry.Bus) func(models.PolicyDivergenceResult) error {
	if vm == nil {
		return nil
	}
	return func(result models.PolicyDivergenceResult) error {
		observability.Warn("policy_enforcement_kill_vm", observability.Fields{
			"execution_id": execID,
			"seq":          result.LastSeq,
			"verdict":      result.CurrentVerdict,
			"vm_pid":       vm.FirecrackerPID,
		})
		return vm.Kill()
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, chunk models.GuestChunk) {
	b, err := json.Marshal(chunk)
	if err != nil {
		observability.Warn("sse_encode_failed", observability.Fields{"type": chunk.Type, "error": err.Error()})
		return
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		observability.Warn("sse_write_failed", observability.Fields{"type": chunk.Type, "error": err.Error()})
		return
	}
	if _, err := w.Write(b); err != nil {
		observability.Warn("sse_write_failed", observability.Fields{"type": chunk.Type, "error": err.Error()})
		return
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		observability.Warn("sse_write_failed", observability.Fields{"type": chunk.Type, "error": err.Error()})
		return
	}
	flusher.Flush()
}

func writeExecutionRecord(s *store.Store, rec store.ExecutionRecord) error {
	if s == nil {
		return nil
	}
	return s.WriteExecution(rec)
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

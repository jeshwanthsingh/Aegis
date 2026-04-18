package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegis/internal/broker"
	"aegis/internal/capabilities"
	"aegis/internal/executor"
	"aegis/internal/governance"
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
	ExecutionID  string                `json:"execution_id,omitempty"`
	Lang         string                `json:"lang"`
	Code         string                `json:"code"`
	TimeoutMs    int                   `json:"timeout_ms"`
	Profile      string                `json:"profile,omitempty"`
	WorkspaceID  string                `json:"workspace_id,omitempty"`
	Intent       json.RawMessage       `json:"intent,omitempty"`
	Capabilities *capabilities.Request `json:"capabilities,omitempty"`
}

type ExecuteResponse struct {
	Stdout               string `json:"stdout,omitempty"`
	Stderr               string `json:"stderr,omitempty"`
	ExitCode             int    `json:"exit_code,omitempty"`
	ExitReason           string `json:"exit_reason,omitempty"`
	DurationMs           int64  `json:"duration_ms"`
	ExecutionID          string `json:"execution_id"`
	DispatchPath         string `json:"dispatch_path,omitempty"`
	ColdFallbackReason   string `json:"cold_fallback_reason,omitempty"`
	Error                string `json:"error,omitempty"`
	OutputTruncated      bool   `json:"output_truncated,omitempty"`
	ProofDir             string `json:"proof_dir,omitempty"`
	ReceiptPath          string `json:"receipt_path,omitempty"`
	ReceiptPublicKeyPath string `json:"receipt_public_key_path,omitempty"`
	ReceiptSummaryPath   string `json:"receipt_summary_path,omitempty"`
}

const startupSlack = 15 * time.Second
const serialLogTailBytes = 8192
const vmmOverheadMB = 128
const rawInterpreterPidsLimit = 8

var (
	acquireExecutionVMFunc   = acquireExecutionVM
	setupCgroupFunc          = executor.SetupCgroup
	teardownVMFunc           = executor.Teardown
	startBrokerListenerFunc  = executor.StartBrokerListener
	dialWithRetryFunc        = executor.DialWithRetry
	waitForGuestReadyFunc    = executor.WaitForGuestReady
	sendPayloadFunc          = executor.SendPayload
	readChunksFunc           = executor.ReadChunks
	startCgroupPollerFunc    = telemetry.StartCgroupPoller
	emitSignedReceiptFunc    = emitSignedReceipt
	writeExecutionRecordFunc = writeExecutionRecord
)

func buildPointEvaluator(req *ExecuteRequest, defaultTimeoutMs int) (*policyevaluator.Evaluator, *policycontract.IntentContract, error) {
	if req == nil {
		return nil, nil, nil
	}
	if len(req.Intent) > 0 && req.Capabilities != nil && !req.Capabilities.IsZero() {
		return nil, nil, &capabilities.InvalidRequestError{Message: "intent and capabilities cannot both be provided"}
	}
	if len(req.Intent) == 0 {
		if req.Capabilities == nil || req.Capabilities.IsZero() {
			return nil, nil, nil
		}
		executionID, err := chooseExecutionID(req.ExecutionID)
		if err != nil {
			return nil, nil, err
		}
		timeoutSec := float64(defaultTimeoutMs) / 1000
		if req.TimeoutMs > 0 {
			timeoutSec = float64(req.TimeoutMs) / 1000
		}
		compiled, err := capabilities.Compile(executionID, req.Lang, timeoutSec, *req.Capabilities)
		if err != nil {
			return nil, nil, err
		}
		req.ExecutionID = executionID
		req.Intent = compiled.Raw
		eval := policyevaluator.New(compiled.Intent)
		return eval, &compiled.Intent, nil
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
	if intent == nil {
		switch strings.TrimSpace(lang) {
		case "python", "node":
			if defaultLimit > rawInterpreterPidsLimit {
				return rawInterpreterPidsLimit
			}
		}
		return defaultLimit
	}
	switch strings.TrimSpace(lang) {
	case "python", "node":
		if intent.ProcessScope.AllowShell {
			return defaultLimit
		}
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

func warmShapeDecision(req ExecuteRequest, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string) (string, string) {
	if warm == nil || !warm.Enabled() || pol == nil {
		return "", warmpool.FallbackPoolDisabled
	}
	if req.WorkspaceID != "" {
		return "", warmpool.FallbackWorkspace
	}
	if !warmpool.SupportedWarmProfile(req.Profile) {
		return "", warmpool.FallbackProfile
	}
	shapeKey := warmpool.ShapeKey(req.Profile, assetsDir, rootfsPath, pol)
	if !warm.SupportsShape(shapeKey) {
		return "", warmpool.FallbackShapeMissing
	}
	return shapeKey, ""
}

func resolveRequestedProfile(req ExecuteRequest, pol *policy.Policy) string {
	if strings.TrimSpace(req.Profile) != "" {
		return req.Profile
	}
	if pol == nil {
		return ""
	}
	lang := strings.TrimSpace(req.Lang)
	switch lang {
	case "bash":
		if _, ok := pol.Profiles["nano"]; ok {
			return "nano"
		}
	case "python", "node", "":
		if _, ok := pol.Profiles["standard"]; ok {
			return "standard"
		}
	default:
		if _, ok := pol.Profiles["standard"]; ok {
			return "standard"
		}
	}
	return pol.DefaultProfile
}

func resourcesForProfile(base policy.ResourcePolicy, profile policy.ComputeProfile) policy.ResourcePolicy {
	resolved := base
	if profile.MemoryMB > 0 {
		resolved.MemoryMaxMB = profile.MemoryMB + vmmOverheadMB
	}
	return resolved
}

func runtimeEnvelopeForExecution(req ExecuteRequest, vm *executor.VMInstance, cgroup *executor.EffectiveCgroupLimits, brokerEnabled bool) *receipt.RuntimeEnvelope {
	if vm == nil {
		return nil
	}
	runtime := &receipt.RuntimeEnvelope{
		Profile:   strings.TrimSpace(req.Profile),
		VCPUCount: vm.VCPUCount,
		MemoryMB:  vm.MemoryMB,
		Network: &receipt.RuntimeNetworkEnvelope{
			Enabled: false,
			Mode:    "none",
		},
		Broker: &receipt.RuntimeBrokerEnvelope{
			Enabled: brokerEnabled,
		},
	}
	if vm.Network != nil {
		presets := append([]string(nil), vm.Network.Presets...)
		sort.Strings(presets)
		mode := strings.TrimSpace(vm.Network.Mode)
		if mode == "" {
			mode = "none"
		}
		runtime.Network = &receipt.RuntimeNetworkEnvelope{
			Enabled: true,
			Mode:    mode,
			Presets: presets,
		}
	}
	if cgroup != nil {
		runtime.Cgroup = &receipt.RuntimeCgroupEnvelope{
			MemoryMaxMB:  cgroup.MemoryMaxMB,
			MemoryHighMB: cgroup.MemoryHighMB,
			PidsMax:      cgroup.PidsMax,
			CPUMax:       cgroup.CPUMax,
			SwapMax:      cgroup.SwapMax,
		}
	}
	runtime.AppliedOverrides = mergeRuntimeOverrides(vm.AppliedOverrides, cgroupOverrideNames(cgroup))
	if len(runtime.AppliedOverrides) == 0 {
		runtime.AppliedOverrides = nil
	}
	return runtime
}

func policyEvidenceForExecution(req ExecuteRequest, pol *policy.Policy, timeoutMs int) (*receipt.PolicyEnvelope, error) {
	if pol == nil {
		return nil, nil
	}
	policyEvidence := &receipt.PolicyEnvelope{
		Baseline: receipt.BaselinePolicy{
			Language:      strings.TrimSpace(req.Lang),
			CodeSizeBytes: len(req.Code),
			MaxCodeBytes:  pol.MaxCodeBytes,
			TimeoutMs:     timeoutMs,
			MaxTimeoutMs:  pol.MaxTimeoutMs,
			Profile:       strings.TrimSpace(req.Profile),
		},
	}
	mode := strings.TrimSpace(pol.Network.Mode)
	if mode == "" {
		mode = "none"
	}
	presets := append([]string(nil), pol.Network.Presets...)
	sort.Strings(presets)
	policyEvidence.Baseline.Network = &receipt.BaselineNetworkPolicy{
		Mode:    mode,
		Presets: presets,
	}
	if len(req.Intent) == 0 {
		return policyEvidence, nil
	}
	intent, err := policycontract.LoadIntentContractJSON(req.Intent)
	if err != nil {
		return nil, err
	}
	source := receipt.PolicyIntentSourceContract
	if req.Capabilities != nil && !req.Capabilities.IsZero() {
		source = receipt.PolicyIntentSourceCompiledCapabilities
	}
	policyEvidence.Intent = &receipt.IntentPolicyDigest{
		Digest: governance.DigestIntent(intent),
		Source: source,
	}
	return policyEvidence, nil
}

func mergeRuntimeOverrides(groups ...[]string) []string {
	seen := map[string]struct{}{}
	var merged []string
	for _, group := range groups {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			merged = append(merged, value)
		}
	}
	sort.Strings(merged)
	return merged
}

func cgroupOverrideNames(cgroup *executor.EffectiveCgroupLimits) []string {
	if cgroup == nil {
		return nil
	}
	return append([]string(nil), cgroup.AppliedOverrides...)
}

func readSerialLogTail(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(raw) > serialLogTailBytes {
		raw = raw[len(raw)-serialLogTailBytes:]
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return ""
	}
	return text
}

func readCgroupMemoryDetail(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return ""
	}
	return text
}

func readCgroupMemoryDetails(vm *executor.VMInstance) string {
	if vm == nil {
		return ""
	}
	cgroupID := strings.TrimSpace(vm.CgroupID)
	if cgroupID == "" {
		cgroupID = vm.UUID
	}
	cgPath := executor.CgroupPath(executor.DefaultCgroupParent(), cgroupID)
	var lines []string
	if events := readCgroupMemoryDetail(filepath.Join(cgPath, "memory.events")); events != "" {
		lines = append(lines, "memory.events:\n"+events)
	}
	if current := readCgroupMemoryDetail(filepath.Join(cgPath, "memory.current")); current != "" {
		lines = append(lines, "memory.current: "+current)
	}
	if max := readCgroupMemoryDetail(filepath.Join(cgPath, "memory.max")); max != "" {
		lines = append(lines, "memory.max: "+max)
	}
	if peak := readCgroupMemoryDetail(filepath.Join(cgPath, "memory.peak")); peak != "" {
		lines = append(lines, "memory.peak: "+peak)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func enrichSandboxFailure(err error, vm *executor.VMInstance) (string, string) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	if vm == nil {
		return errMsg, ""
	}
	serialTail := readSerialLogTail(vm.SerialLogPath)
	if serialTail == "" {
		if cgroupDetail := readCgroupMemoryDetails(vm); cgroupDetail != "" {
			stderrDetail := "host cgroup memory:\n" + cgroupDetail
			if errMsg == "" {
				return stderrDetail, stderrDetail
			}
			return errMsg + "\n" + stderrDetail, stderrDetail
		}
		return errMsg, ""
	}
	parts := []string{"firecracker serial tail (" + filepath.Base(vm.SerialLogPath) + "):\n" + serialTail}
	if cgroupDetail := readCgroupMemoryDetails(vm); cgroupDetail != "" {
		parts = append(parts, "host cgroup memory:\n"+cgroupDetail)
	}
	stderrDetail := strings.Join(parts, "\n")
	if errMsg == "" {
		return stderrDetail, stderrDetail
	}
	return errMsg + "\n" + stderrDetail, stderrDetail
}

func acquireExecutionVM(ctx context.Context, warm *warmpool.Manager, execID string, req ExecuteRequest, pol *policy.Policy, computeProfile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*executor.VMInstance, string, string, error) {
	shapeKey, fallbackReason := warmShapeDecision(req, warm, pol, assetsDir, rootfsPath)
	if shapeKey != "" {
		vm, ok, claimReason, err := warm.ClaimFor(ctx, shapeKey)
		if ok && err == nil {
			if err := vm.ClaimExecutionIdentity(execID); err != nil {
				observability.Warn("warm_pool_claim_identity_rebind_failed", observability.Fields{"execution_id": execID, "asset_id": vm.AssetID, "error": err.Error()})
				if teardownErr := teardownVMFunc(vm, bus); teardownErr != nil {
					observability.Warn("warm_pool_claim_rebind_teardown_failed", observability.Fields{"execution_id": execID, "asset_id": vm.AssetID, "error": teardownErr.Error()})
				}
				fallbackReason = warmpool.FallbackClaimError
				if warm != nil {
					warm.RecordColdFallbackReason(fallbackReason)
				}
			} else {
				return vm, "warm", "", nil
			}
		}
		if err != nil {
			fallbackReason = claimReason
			observability.Warn("warm_pool_claim_failed", observability.Fields{"execution_id": execID, "error": err.Error(), "fallback_reason": fallbackReason})
		} else if !ok {
			fallbackReason = claimReason
		}
	} else if warm != nil {
		warm.RecordColdFallbackReason(fallbackReason)
	}
	vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
	if vm != nil {
		if claimErr := vm.ClaimExecutionIdentity(execID); claimErr != nil {
			return nil, "cold", fallbackReason, claimErr
		}
	}
	return vm, "cold", fallbackReason, err
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

func HandleCreateWorkspace() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_request", "workspace ID is required", errorDetails("path_param", "id"))
			return
		}
		if _, err := executor.CreateWorkspace(id, executor.DefaultWorkspaceSizeMB); err != nil {
			switch {
			case errors.Is(err, executor.ErrInvalidWorkspaceID):
				writeAPIError(w, http.StatusBadRequest, "invalid_workspace_id", err.Error(), errorDetails("workspace_id", id))
			case errors.Is(err, executor.ErrWorkspaceExists):
				writeAPIError(w, http.StatusConflict, "workspace_exists", err.Error(), errorDetails("workspace_id", id))
			default:
				writeAPIError(w, http.StatusInternalServerError, "workspace_create_failed", err.Error(), errorDetails("workspace_id", id))
			}
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "workspace_id": id})
	}
}

func NewHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
	workspaceRegistry := resolveWorkspaceRegistry(workspaceRegistries)
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

		proofRoot := receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT")))
		proofPaths := receipt.BundlePaths{}
		var (
			vmPath             string
			coldFallbackReason string
		)
		respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
			resp.DurationMs = time.Since(start).Milliseconds()
			resp.DispatchPath = vmPath
			if vmPath == "cold" && coldFallbackReason != "" {
				resp.ColdFallbackReason = coldFallbackReason
			}
			resp = withReceiptProof(resp, proofPaths)
			writeJSON(w, http.StatusOK, resp)
		}

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

		pointEvaluator, intent, err := buildPointEvaluator(&req, pol.DefaultTimeoutMs)
		if err != nil {
			execStatus = "validation_error"
			errorCode := "invalid_intent_contract"
			var invalidReq *capabilities.InvalidRequestError
			if errors.As(err, &invalidReq) {
				errorCode = "invalid_request"
			}
			writeAPIError(w, http.StatusBadRequest, errorCode, err.Error(), nil)
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
		if req.WorkspaceID != "" {
			if err := executor.ValidateWorkspaceID(req.WorkspaceID); err != nil {
				execStatus = "validation_error"
				writeAPIError(w, http.StatusBadRequest, "invalid_workspace_id", err.Error(), errorDetails("workspace_id", req.WorkspaceID))
				return
			}
			if !workspaceRegistry.TryClaim(req.WorkspaceID, execID) {
				execStatus = "workspace_busy"
				writeAPIError(w, http.StatusConflict, "workspace_busy", "workspace already has an active execution", errorDetails("workspace_id", req.WorkspaceID))
				return
			}
			defer workspaceRegistry.Release(req.WorkspaceID, execID)
		}
		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent executions", errorDetails("retry_after_seconds", 5))
			return
		}
		defer pool.Release()
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
		recordLifecycleStatus(s, execID, req.Lang, store.StatusRequested, "")

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		req.TimeoutMs = timeoutMs
		req.Profile = resolveRequestedProfile(req, pol)
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
		policyEvidence, err := policyEvidenceForExecution(req, pol, timeoutMs)
		if err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
			return
		}

		var (
			vm              *executor.VMInstance
			effectiveCgroup *executor.EffectiveCgroupLimits
			exitCode        int
			exitReason      = "completed"
			outputTruncated bool
			stdoutData      string
			stderrData      string
			brokerEnabled   bool
		)
		currentRuntimeEnvelope := func() *receipt.RuntimeEnvelope {
			return runtimeEnvelopeForExecution(req, vm, effectiveCgroup, brokerEnabled)
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond+startupSlack)
		defer cancel()
		deadline, _ := ctx.Deadline()
		observability.Info("execution_start", observability.Fields{"execution_id": execID, "lang": req.Lang, "timeout_ms": timeoutMs, "deadline": deadline.Format(time.RFC3339Nano)})
		recordLifecycleStatus(s, execID, req.Lang, store.StatusBooting, "")

		bootStart := time.Now()
		bootObserved := false
		recordBoot := func() {
			if bootObserved {
				return
			}
			bootObserved = true
			observability.ObserveBootDuration(time.Since(bootStart))
		}

		claimStart := time.Now()
		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, pol, computeProfile, assetsDir, rootfsPath, bus)
		claimElapsed := time.Since(claimStart)
		if err != nil {
			recordBoot()
			if errors.Is(err, executor.ErrInvalidWorkspaceID) {
				execStatus = "validation_error"
				msg := err.Error()
				_ = writeExecutionRecordFunc(s, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: msg})
				respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
				return
			}
			if req.WorkspaceID != "" && errors.Is(err, os.ErrNotExist) {
				execStatus = "validation_error"
				msg := "workspace_not_found: " + req.WorkspaceID
				_ = writeExecutionRecordFunc(s, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: msg})
				respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
				return
			}
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			status := store.StatusSandboxError
			outcome := "error"
			if timedOut(ctx, deadline, err) {
				execStatus = "timeout"
				exitReason = "timeout"
				status = store.StatusTimedOut
				outcome = "timeout"
			}
			_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			proofPaths = actualProofPaths
			if receiptErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
				return
			}
			clientError := err.Error()
			if status == store.StatusTimedOut {
				clientError = "timeout"
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: clientError}, rec)
			return
		}
		observability.Info("vm_acquired", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": claimElapsed.Milliseconds(), "cold_fallback_reason": coldFallbackReason})
		vm.CgroupID = execID

		resolvedResources := resourcesForProfile(pol.Resources, computeProfile)
		resolvedCgroup := executor.ResolveCgroupLimits(resolvedResources)
		if err := setupCgroupFunc(execID, vm.FirecrackerPID, resolvedResources, bus); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			errMsg, stderrDetail := enrichSandboxFailure(err, vm)
			stderrData = stderrDetail
			_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: errMsg})
			proofPaths = actualProofPaths
			if receiptErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
				return
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: errMsg, Stderr: stderrDetail}, rec)
			return
		}
		effectiveCgroup = &resolvedCgroup

		pollCtx, cancelPoller := context.WithCancel(ctx)
		defer cancelPoller()
		stopPoller := startCgroupPollerFunc(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		var brokerInst *broker.Broker
		if intent != nil && len(intent.BrokerScope.AllowedDomains) > 0 {
			brokerInst = broker.New(intent.BrokerScope, execID, bus)
			brokerEnabled = true
		}
		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := startBrokerListenerFunc(proxyCtx, vm.VsockPath, brokerInst, divergenceEvaluator); err != nil && proxyCtx.Err() == nil {
				observability.Warn("broker_listener_error", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()
		if err := waitForGuestReadyFunc(vm.VsockPath, time.Until(deadline)); err != nil {
			recordBoot()
			exitCode = -1
			exitReason = "sandbox_error"
			outcome := "error"
			status := store.StatusSandboxError
			errMsg, stderrDetail := enrichSandboxFailure(err, vm)
			stderrData = stderrDetail
			if timedOut(ctx, deadline, err) {
				execStatus = "timeout"
				exitReason = "timeout"
				outcome = "timeout"
				status = store.StatusTimedOut
			} else {
				execStatus = "sandbox_error"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: errMsg})
			proofPaths = actualProofPaths
			if receiptErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
				return
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome, Stderr: stderrDetail}, rec)
			return
		}
		recordLifecycleStatus(s, execID, req.Lang, store.StatusGuestReady, "")

		conn, err := dialWithRetryFunc(vm.VsockPath, executor.GuestExecPort, time.Until(deadline))
		if err != nil {
			recordBoot()
			outcome, status := "error", store.StatusSandboxError
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			errMsg, stderrDetail := enrichSandboxFailure(err, vm)
			stderrData = stderrDetail
			if timedOut(ctx, deadline, err) {
				outcome, status = "timeout", store.StatusTimedOut
				execStatus = "timeout"
				exitReason = "timeout"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: errMsg})
			proofPaths = actualProofPaths
			if receiptErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
				return
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome, Stderr: stderrDetail}, rec)
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
		recordLifecycleStatus(s, execID, req.Lang, store.StatusRunning, "")

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
			outcome, status := "error", store.StatusSandboxError
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			errMsg, stderrDetail := enrichSandboxFailure(err, vm)
			stderrData = stderrDetail
			if timedOut(ctx, deadline, err) {
				outcome, status = "timeout", store.StatusTimedOut
				execStatus = "timeout"
				exitReason = "timeout"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: errMsg})
			proofPaths = actualProofPaths
			if receiptErr != nil {
				writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
				return
			}
			respond(ExecuteResponse{ExecutionID: execID, Error: outcome, Stderr: stderrDetail}, rec)
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
		_, actualProofPaths, rec, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: status, StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes})
		if receiptErr != nil {
			execStatus = "sandbox_error"
			writeAPIError(w, http.StatusInternalServerError, "receipt_signing_failed", "receipt signing failed", errorDetails("execution_id", execID, "cause", receiptErr.Error()))
			return
		}
		proofPaths = actualProofPaths
		respond(ExecuteResponse{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, ExitReason: exitReason, ExecutionID: execID, OutputTruncated: result.OutputTruncated}, rec)
	}
}

func NewStreamHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
	workspaceRegistry := resolveWorkspaceRegistry(workspaceRegistries)
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		execStatus := "error"
		defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()

		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)

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

		pointEvaluator, intent, err := buildPointEvaluator(&req, pol.DefaultTimeoutMs)
		if err != nil {
			execStatus = "validation_error"
			errorCode := "invalid_intent_contract"
			var invalidReq *capabilities.InvalidRequestError
			if errors.As(err, &invalidReq) {
				errorCode = "invalid_request"
			}
			writeAPIError(w, http.StatusBadRequest, errorCode, err.Error(), nil)
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
		if req.WorkspaceID != "" {
			if err := executor.ValidateWorkspaceID(req.WorkspaceID); err != nil {
				execStatus = "validation_error"
				writeAPIError(w, http.StatusBadRequest, "invalid_workspace_id", err.Error(), errorDetails("workspace_id", req.WorkspaceID))
				return
			}
			if !workspaceRegistry.TryClaim(req.WorkspaceID, execID) {
				execStatus = "workspace_busy"
				writeAPIError(w, http.StatusConflict, "workspace_busy", "workspace already has an active execution", errorDetails("workspace_id", req.WorkspaceID))
				return
			}
			defer workspaceRegistry.Release(req.WorkspaceID, execID)
		}
		if err := pool.Acquire(); err != nil {
			execStatus = "too_many_requests"
			w.Header().Set("Retry-After", "5")
			writeAPIError(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent executions", errorDetails("retry_after_seconds", 5))
			return
		}
		defer pool.Release()
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
		recordLifecycleStatus(s, execID, req.Lang, store.StatusRequested, "")

		proofRoot := receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT")))

		timeoutMs := req.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = pol.DefaultTimeoutMs
		}
		req.TimeoutMs = timeoutMs
		req.Profile = resolveRequestedProfile(req, pol)
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
		policyEvidence, err := policyEvidenceForExecution(req, pol, timeoutMs)
		if err != nil {
			execStatus = "validation_error"
			writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
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
			vm                 *executor.VMInstance
			vmPath             string
			effectiveCgroup    *executor.EffectiveCgroupLimits
			exitCode           int
			exitReason         = "completed"
			coldFallbackReason string
			outputTruncated    bool
			stdoutData         string
			stderrData         string
			brokerEnabled      bool
		)
		currentRuntimeEnvelope := func() *receipt.RuntimeEnvelope {
			return runtimeEnvelopeForExecution(req, vm, effectiveCgroup, brokerEnabled)
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond+startupSlack)
		defer cancel()
		deadline, _ := ctx.Deadline()
		observability.Info("stream_execution_start", observability.Fields{"execution_id": execID, "lang": req.Lang, "timeout_ms": timeoutMs, "deadline": deadline.Format(time.RFC3339Nano)})
		recordLifecycleStatus(s, execID, req.Lang, store.StatusBooting, "")

		bootStart := time.Now()
		bootObserved := false
		recordBoot := func() {
			if bootObserved {
				return
			}
			bootObserved = true
			observability.ObserveBootDuration(time.Since(bootStart))
		}

		claimStart := time.Now()
		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, pol, computeProfile, assetsDir, rootfsPath, bus)
		claimElapsed := time.Since(claimStart)
		if err != nil {
			recordBoot()
			if errors.Is(err, executor.ErrInvalidWorkspaceID) {
				execStatus = "validation_error"
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
				return
			}
			if req.WorkspaceID != "" && errors.Is(err, os.ErrNotExist) {
				execStatus = "validation_error"
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "workspace_not_found: " + req.WorkspaceID})
				return
			}
			exitCode = -1
			exitReason = "sandbox_error"
			outcome := "error"
			status := store.StatusSandboxError
			execStatus = "sandbox_error"
			if timedOut(ctx, deadline, err) {
				outcome = "timeout"
				status = store.StatusTimedOut
				exitReason = "timeout"
				execStatus = "timeout"
			}
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
			clientError := err.Error()
			if status == store.StatusTimedOut {
				clientError = "timeout"
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: clientError})
			return
		}
		observability.Info("vm_acquired", observability.Fields{"execution_id": execID, "path": vmPath, "elapsed_ms": claimElapsed.Milliseconds(), "cold_fallback_reason": coldFallbackReason})
		vm.CgroupID = execID

		resolvedResources := resourcesForProfile(pol.Resources, computeProfile)
		resolvedCgroup := executor.ResolveCgroupLimits(resolvedResources)
		if err := setupCgroupFunc(execID, vm.FirecrackerPID, resolvedResources, bus); err != nil {
			recordBoot()
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}
		effectiveCgroup = &resolvedCgroup

		pollCtx, cancelPoller := context.WithCancel(ctx)
		defer cancelPoller()
		stopPoller := startCgroupPollerFunc(pollCtx, bus, execID, 100*time.Millisecond)
		defer stopPoller()

		var brokerInst *broker.Broker
		if intent != nil && len(intent.BrokerScope.AllowedDomains) > 0 {
			brokerInst = broker.New(intent.BrokerScope, execID, bus)
			brokerEnabled = true
		}
		proxyCtx, proxyCancel := context.WithCancel(ctx)
		defer proxyCancel()
		go func() {
			if err := startBrokerListenerFunc(proxyCtx, vm.VsockPath, brokerInst, divergenceEvaluator); err != nil && proxyCtx.Err() == nil {
				observability.Warn("broker_listener_error", observability.Fields{"execution_id": execID, "error": err.Error()})
			}
		}()
		if err := waitForGuestReadyFunc(vm.VsockPath, time.Until(deadline)); err != nil {
			recordBoot()
			exitCode = -1
			exitReason = "sandbox_error"
			outcome := "error"
			status := store.StatusSandboxError
			execStatus = "sandbox_error"
			if timedOut(ctx, deadline, err) {
				outcome = "timeout"
				status = store.StatusTimedOut
				exitReason = "timeout"
				execStatus = "timeout"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: outcome})
			return
		}
		recordLifecycleStatus(s, execID, req.Lang, store.StatusGuestReady, "")

		conn, err := dialWithRetryFunc(vm.VsockPath, executor.GuestExecPort, time.Until(deadline))
		if err != nil {
			recordBoot()
			outcome := "error"
			status := store.StatusSandboxError
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			if timedOut(ctx, deadline, err) {
				execStatus = "timeout"
				outcome = "timeout"
				status = store.StatusTimedOut
				exitReason = "timeout"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
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
		recordLifecycleStatus(s, execID, req.Lang, store.StatusRunning, "")

		if err := conn.SetDeadline(deadline); err != nil {
			execStatus = "sandbox_error"
			exitCode = -1
			exitReason = "sandbox_error"
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
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
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: err.Error()})
			return
		}

		result, err := readChunksFunc(conn, deadline, func(chunkType, chunk string) {
			writeSSE(w, flusher, models.GuestChunk{Type: chunkType, Chunk: chunk})
		}, bus, pointEvaluator, divergenceEvaluator, enforcementCallback(execID, vm, bus))
		if err != nil {
			execStatus = "sandbox_error"
			outcome := err.Error()
			status := store.StatusSandboxError
			exitCode = -1
			exitReason = "sandbox_error"
			if timedOut(ctx, deadline, err) {
				execStatus = "timeout"
				outcome = "timeout"
				status = store.StatusTimedOut
				exitReason = "timeout"
			}
			bus.Emit(telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: exitCode, Reason: exitReason})
			_, _, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: outcome, Status: status, ErrorMsg: err.Error()})
			if receiptErr != nil {
				writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
				return
			}
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
		_, proofPaths, _, receiptErr := finalizeExecution(s, stats, execID, start, req, intent, policyEvidence, vm, currentRuntimeEnvelope(), exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, ExitCode: result.ExitCode, Outcome: outcome, Status: status, DurationMs: time.Since(start).Milliseconds(), StdoutBytes: result.StdoutBytes, StderrBytes: result.StderrBytes})
		if receiptErr != nil {
			execStatus = "sandbox_error"
			writeSSE(w, flusher, models.GuestChunk{Type: "error", Error: "receipt signing failed: " + receiptErr.Error()})
			return
		}
		if proofPaths.ReceiptPath != "" {
			writeSSE(w, flusher, proofChunk(execID, proofPaths))
		}
		writeSSE(w, flusher, models.GuestChunk{Type: "done", ExitCode: result.ExitCode, Reason: exitReason, DurationMs: result.DurationMs})
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

func emitSignedReceipt(execID string, startedAt time.Time, finishedAt time.Time, req ExecuteRequest, intent *policycontract.IntentContract, policyEvidence *receipt.PolicyEnvelope, vm *executor.VMInstance, runtime *receipt.RuntimeEnvelope, executionStatus string, exitCode int, exitReason string, outputTruncated bool, stdoutData string, stderrData string, proofRoot string, bus *telemetry.Bus) (receipt.SignedReceipt, receipt.BundlePaths, error) {
	events := bus.Drain()
	signer, signerErr := receipt.NewSignerFromEnv()
	if signerErr != nil {
		observability.Error("receipt_signer_init_failed", observability.Fields{"execution_id": execID, "error": signerErr.Error()})
		return receipt.SignedReceipt{}, receipt.BundlePaths{}, signerErr
	}
	artifacts := receipt.ArtifactsFromBundleOutputs(execID, stdoutData, stderrData, outputTruncated)
	signedReceipt, buildErr := receipt.BuildSignedReceipt(receipt.Input{
		ExecutionID:     execID,
		WorkflowID:      workflowID(intent),
		Backend:         models.BackendFirecracker,
		TaskClass:       taskClass(intent),
		DeclaredPurpose: declaredPurpose(intent),
		WorkspaceID:     req.WorkspaceID,
		ExecutionStatus: executionStatus,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
		IntentRaw:       cloneRawJSON(req.Intent),
		Policy:          policyEvidence,
		Outcome: receipt.Outcome{
			ExitCode:           exitCode,
			Reason:             exitReason,
			ContainmentVerdict: containmentVerdictForOutcome(exitCode, exitReason),
			OutputTruncated:    outputTruncated,
		},
		Runtime:         runtime,
		TelemetryEvents: events,
		OutputArtifacts: artifacts,
		Attributes:      receiptAttributes(req, intent),
	}, signer)
	if buildErr != nil {
		observability.Error("receipt_build_failed", observability.Fields{"execution_id": execID, "error": buildErr.Error()})
		return receipt.SignedReceipt{}, receipt.BundlePaths{}, buildErr
	}
	bus.Emit(telemetry.KindReceipt, signedReceipt)
	observability.Info("receipt_built", observability.Fields{"execution_id": execID, "artifact_count": len(signedReceipt.Statement.Subject), "divergence_verdict": signedReceipt.Statement.Predicate.Divergence.Verdict})
	observability.Info("receipt_signed", observability.Fields{"execution_id": execID, "signer_key_id": signedReceipt.Statement.Predicate.SignerKeyID})
	paths, writeErr := receipt.WriteProofBundle(proofRoot, execID, signedReceipt, signer.PublicKey, stdoutData, stderrData, outputTruncated)
	if writeErr != nil {
		observability.Error("receipt_bundle_write_failed", observability.Fields{"execution_id": execID, "error": writeErr.Error()})
		return receipt.SignedReceipt{}, receipt.BundlePaths{}, writeErr
	}
	observability.Info("receipt_bundle_written", observability.Fields{"execution_id": execID, "proof_dir": paths.ProofDir, "artifact_count": paths.ArtifactCount, "divergence_verdict": paths.DivergenceVerdict})
	return signedReceipt, paths, nil
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

func receiptAttributes(req ExecuteRequest, intent *policycontract.IntentContract) map[string]string {
	size := 0
	if intent != nil {
		size = len(intent.Attributes)
	}
	if req.WorkspaceID != "" {
		size++
	}
	if size == 0 {
		return map[string]string{}
	}
	attrs := make(map[string]string, size)
	if intent != nil {
		for key, value := range intent.Attributes {
			attrs[key] = value
		}
	}
	if req.WorkspaceID != "" {
		attrs["workspace_id"] = req.WorkspaceID
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

func containmentVerdictForOutcome(exitCode int, reason string) string {
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

func recordLifecycleStatus(s *store.Store, execID string, lang string, status string, errorMsg string) {
	if err := writeExecutionRecordFunc(s, store.ExecutionRecord{
		ExecutionID: execID,
		Lang:        lang,
		Outcome:     "pending",
		Status:      status,
		ErrorMsg:    errorMsg,
	}); err != nil {
		observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "status": status, "error": err.Error()})
	}
}

func timedOut(ctx context.Context, deadline time.Time, err error) bool {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		type timeout interface{ Timeout() bool }
		if te, ok := err.(timeout); ok && te.Timeout() {
			return true
		}
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func finalizeExecution(s *store.Store, stats *StatsCounter, execID string, start time.Time, req ExecuteRequest, intent *policycontract.IntentContract, policyEvidence *receipt.PolicyEnvelope, vm *executor.VMInstance, runtime *receipt.RuntimeEnvelope, exitCode int, exitReason string, outputTruncated bool, stdoutData string, stderrData string, proofRoot string, bus *telemetry.Bus, rec store.ExecutionRecord) (receipt.SignedReceipt, receipt.BundlePaths, store.ExecutionRecord, error) {
	if vm != nil {
		recordLifecycleStatus(s, execID, req.Lang, store.StatusFinalizing, "")
	}

	if rec.Status == "" {
		rec.Status = store.StatusCompleted
	}
	rec.ExecutionID = execID
	rec.Lang = req.Lang
	rec.DurationMs = time.Since(start).Milliseconds()

	var teardownErr error
	if vm != nil {
		teardownStart := time.Now()
		teardownErr = teardownVMFunc(vm, bus)
		if teardownErr != nil {
			observability.Error("teardown_failed", observability.Fields{"execution_id": execID, "error": teardownErr.Error()})
		} else {
			observability.Info("teardown_completed", observability.Fields{"execution_id": execID})
		}
		observability.ObserveTeardownDuration(time.Since(teardownStart))
	}

	if teardownErr != nil {
		rec.Status = store.StatusTeardownFailed
		if rec.ErrorMsg == "" {
			rec.ErrorMsg = teardownErr.Error()
		} else {
			rec.ErrorMsg += "; teardown: " + teardownErr.Error()
		}
	}

	finishedAt := time.Now()
	signedReceipt, proofPaths, receiptErr := emitSignedReceiptFunc(execID, start, finishedAt, req, intent, policyEvidence, vm, runtime, rec.Status, exitCode, exitReason, outputTruncated, stdoutData, stderrData, proofRoot, bus)
	if receiptErr != nil {
		if rec.ErrorMsg == "" {
			rec.ErrorMsg = "receipt signing failed: " + receiptErr.Error()
		} else {
			rec.ErrorMsg += "; receipt: " + receiptErr.Error()
		}
	}

	if err := writeExecutionRecordFunc(s, rec); err != nil {
		observability.Warn("audit_log_write_failed", observability.Fields{"execution_id": execID, "status": rec.Status, "error": err.Error()})
	}

	if receiptErr == nil && stats != nil {
		stats.RecordReceipt(signedReceipt.Statement)
	}
	return signedReceipt, proofPaths, rec, receiptErr
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

func resolveWorkspaceRegistry(registries []*WorkspaceRegistry) *WorkspaceRegistry {
	if len(registries) > 0 && registries[0] != nil {
		return registries[0]
	}
	return NewWorkspaceRegistry()
}

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"aegis/internal/api"
	policycontract "aegis/internal/policy/contract"
	"aegis/internal/receipt"

	"github.com/google/uuid"
)

const (
	defaultTimeoutSec  = 10
	defaultMemoryMB    = 128
	defaultCPUQuota    = 100
	defaultStdoutBytes = 4096
	defaultWorkflowID  = "mcp_local"
	defaultWorkspace   = "/workspace"
)

type ToolHandler struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	version    string
}

type ExecuteArgs struct {
	Code                string             `json:"code"`
	Language            string             `json:"language"`
	TimeoutSec          *float64           `json:"timeout_sec,omitempty"`
	AllowNetworkDomains []string           `json:"allow_network_domains,omitempty"`
	AllowWritePaths     []string           `json:"allow_write_paths,omitempty"`
	BrokerDelegations   []BrokerDelegation `json:"broker_delegations,omitempty"`
}

type BrokerDelegation struct {
	Name     string `json:"name"`
	Resource string `json:"resource,omitempty"`
	Method   string `json:"method,omitempty"`
}

type ExecuteToolResult struct {
	ExecutionID     string         `json:"execution_id"`
	OK              bool           `json:"ok"`
	Stdout          string         `json:"stdout"`
	Stderr          string         `json:"stderr"`
	ExitCode        int            `json:"exit_code"`
	ExitReason      string         `json:"exit_reason,omitempty"`
	DurationMs      int64          `json:"duration_ms,omitempty"`
	ProofDir        string         `json:"proof_dir,omitempty"`
	ReceiptPath     string         `json:"receipt_path,omitempty"`
	Receipt         map[string]any `json:"receipt,omitempty"`
	Divergence      map[string]any `json:"divergence,omitempty"`
	Broker          map[string]any `json:"broker,omitempty"`
	Error           string         `json:"error,omitempty"`
	VerificationErr string         `json:"verification_error,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
}

type VerifyArgs struct {
	ExecutionID string `json:"execution_id,omitempty"`
	ProofDir    string `json:"proof_dir,omitempty"`
}

type VerifyToolResult struct {
	OK              bool           `json:"ok"`
	ExecutionID     string         `json:"execution_id,omitempty"`
	ProofDir        string         `json:"proof_dir,omitempty"`
	Verified        bool           `json:"verified"`
	Verdict         string         `json:"verdict,omitempty"`
	SigningMode     string         `json:"signing_mode,omitempty"`
	KeySource       string         `json:"key_source,omitempty"`
	Summary         string         `json:"summary,omitempty"`
	VerificationErr string         `json:"verification_error,omitempty"`
	Diagnostics     map[string]any `json:"diagnostics,omitempty"`
}

type InvalidParamsError struct {
	Message string
	Details map[string]any
}

func (e *InvalidParamsError) Error() string {
	return e.Message
}

func NewToolHandler(version string) *ToolHandler {
	baseURL := strings.TrimRight(strings.TrimSpace(firstNonEmpty(os.Getenv("AEGIS_BASE_URL"), os.Getenv("AEGIS_URL"))), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &ToolHandler{
		baseURL:    baseURL,
		apiKey:     strings.TrimSpace(os.Getenv("AEGIS_API_KEY")),
		httpClient: &http.Client{},
		version:    version,
	}
}

func (h *ToolHandler) Initialize(_ context.Context, params InitializeParams) (InitializeResult, error) {
	protocol := latestProtocol
	switch params.ProtocolVersion {
	case "", "2025-03-26", latestProtocol:
		if params.ProtocolVersion != "" {
			protocol = params.ProtocolVersion
		}
	}
	return InitializeResult{
		ProtocolVersion: protocol,
		Capabilities:    map[string]any{"tools": map[string]any{}},
		ServerInfo:      ServerInfo{Name: serverName, Version: h.version},
		Instructions:    "Aegis is the hands layer: use aegis_execute for isolated code execution and aegis_verify for proof validation.",
	}, nil
}

func (h *ToolHandler) ListTools(_ context.Context) (ToolsListResult, error) {
	return ToolsListResult{Tools: []Tool{
		{
			Name:        "aegis_execute",
			Title:       "Aegis Execute",
			Description: "Execute code in a hardware-isolated Aegis microVM with policy enforcement, divergence detection, and cryptographic execution proof.",
			InputSchema: executeInputSchema(),
		},
		{
			Name:        "aegis_verify",
			Title:       "Aegis Verify",
			Description: "Verify a signed execution receipt from a previous Aegis run by proof directory or execution ID.",
			InputSchema: verifyInputSchema(),
		},
	}}, nil
}

func (h *ToolHandler) CallTool(ctx context.Context, params CallToolParams) (CallToolResult, error) {
	switch params.Name {
	case "aegis_execute":
		args, err := decodeToolArgs[ExecuteArgs](params.Arguments)
		if err != nil {
			return CallToolResult{}, err
		}
		payload, err := h.Execute(ctx, args)
		if err != nil {
			return CallToolResult{}, err
		}
		return toolResultFromStructured(payload, payload.OK), nil
	case "aegis_verify":
		args, err := decodeToolArgs[VerifyArgs](params.Arguments)
		if err != nil {
			return CallToolResult{}, err
		}
		payload, err := h.Verify(args)
		if err != nil {
			return CallToolResult{}, err
		}
		return toolResultFromStructured(payload, payload.OK), nil
	default:
		return CallToolResult{}, &InvalidParamsError{Message: fmt.Sprintf("unknown tool %q", params.Name)}
	}
}

func (h *ToolHandler) Execute(ctx context.Context, args ExecuteArgs) (ExecuteToolResult, error) {
	if strings.TrimSpace(args.Code) == "" {
		return ExecuteToolResult{}, &InvalidParamsError{Message: "code is required"}
	}
	language := normalizeLanguage(args.Language)
	if language == "" {
		return ExecuteToolResult{}, &InvalidParamsError{Message: "language must be one of python, bash, node"}
	}
	timeoutSec, err := validateTimeout(args.TimeoutSec)
	if err != nil {
		return ExecuteToolResult{}, err
	}
	executionID := uuid.NewString()
	intent, err := BuildDefaultIntent(executionID, language, timeoutSec, args.AllowNetworkDomains, args.AllowWritePaths, args.BrokerDelegations)
	if err != nil {
		return ExecuteToolResult{}, err
	}
	intentJSON, err := json.Marshal(intentWire(intent))
	if err != nil {
		return ExecuteToolResult{}, fmt.Errorf("marshal intent: %w", err)
	}
	reqBody := api.ExecuteRequest{
		ExecutionID: executionID,
		Lang:        language,
		Code:        args.Code,
		TimeoutMs:   int(math.Ceil(timeoutSec * 1000)),
		Intent:      intentJSON,
	}
	resp, raw, err := h.executeHTTP(ctx, reqBody)
	if err != nil {
		return ExecuteToolResult{}, err
	}
	result := ExecuteToolResult{
		ExecutionID: resp.ExecutionID,
		OK:          resp.Error == "" && resp.ExitCode == 0 && (resp.ExitReason == "" || resp.ExitReason == "completed"),
		Stdout:      resp.Stdout,
		Stderr:      resp.Stderr,
		ExitCode:    resp.ExitCode,
		ExitReason:  resp.ExitReason,
		DurationMs:  resp.DurationMs,
		ProofDir:    resp.ProofDir,
		ReceiptPath: resp.ReceiptPath,
		Error:       resp.Error,
		Raw:         raw,
	}
	verifyResult, verifyErr := h.Verify(VerifyArgs{ExecutionID: resp.ExecutionID, ProofDir: resp.ProofDir})
	if verifyErr == nil {
		result.Receipt = map[string]any{
			"verified":     verifyResult.Verified,
			"verdict":      verifyResult.Verdict,
			"signing_mode": verifyResult.SigningMode,
			"key_source":   verifyResult.KeySource,
			"summary":      verifyResult.Summary,
		}
		if verifyResult.Diagnostics != nil {
			if divergence, ok := verifyResult.Diagnostics["divergence"].(map[string]any); ok {
				result.Divergence = divergence
			}
			if broker, ok := verifyResult.Diagnostics["broker"].(map[string]any); ok {
				result.Broker = broker
			}
		}
	} else {
		result.VerificationErr = verifyErr.Error()
	}
	return result, nil
}

func (h *ToolHandler) Verify(args VerifyArgs) (VerifyToolResult, error) {
	executionID := strings.TrimSpace(args.ExecutionID)
	proofDir := strings.TrimSpace(args.ProofDir)
	if executionID == "" && proofDir == "" {
		return VerifyToolResult{}, &InvalidParamsError{Message: "execution_id or proof_dir is required"}
	}
	paths, err := receipt.ResolveBundlePaths("", executionID, proofDir)
	if err != nil {
		return VerifyToolResult{}, fmt.Errorf("resolve proof bundle: %w", err)
	}
	loaded, loadErr := receipt.LoadSignedReceiptFile(paths.ReceiptPath)
	result := VerifyToolResult{
		OK:          false,
		ExecutionID: executionID,
		ProofDir:    paths.ProofDir,
	}
	if loadErr == nil {
		result.ExecutionID = loaded.Statement.Predicate.ExecutionID
	}
	if executionID != "" && loadErr == nil && loaded.Statement.Predicate.ExecutionID != executionID {
		return VerifyToolResult{}, &InvalidParamsError{
			Message: "proof_dir execution_id does not match the supplied execution_id",
			Details: map[string]any{"execution_id": executionID, "resolved_execution_id": loaded.Statement.Predicate.ExecutionID},
		}
	}
	statement, verifyErr := receipt.VerifyBundlePaths(paths)
	if verifyErr != nil {
		result.VerificationErr = verifyErr.Error()
		if loadErr == nil {
			enrichVerifyResult(&result, loaded.Statement)
		}
		return result, nil
	}
	result.OK = true
	result.Verified = true
	enrichVerifyResult(&result, statement)
	result.Summary = summaryText(paths.SummaryPath, statement)
	return result, nil
}

func enrichVerifyResult(result *VerifyToolResult, statement receipt.Statement) {
	result.ExecutionID = statement.Predicate.ExecutionID
	result.Verdict = string(statement.Predicate.Divergence.Verdict)
	result.SigningMode = string(statement.Predicate.Trust.SigningMode)
	result.KeySource = string(statement.Predicate.Trust.KeySource)
	result.Diagnostics = map[string]any{
		"backend": statement.Predicate.Backend,
		"outcome": map[string]any{
			"reason":    statement.Predicate.Outcome.Reason,
			"exit_code": statement.Predicate.Outcome.ExitCode,
		},
		"divergence": map[string]any{
			"verdict":            statement.Predicate.Divergence.Verdict,
			"triggered_rule_ids": append([]string(nil), statement.Predicate.Divergence.TriggeredRuleIDs...),
			"rule_hit_count":     statement.Predicate.Divergence.RuleHitCount,
		},
	}
	if statement.Predicate.BrokerSummary != nil {
		result.Diagnostics["broker"] = map[string]any{
			"request_count":   statement.Predicate.BrokerSummary.RequestCount,
			"allowed_count":   statement.Predicate.BrokerSummary.AllowedCount,
			"denied_count":    statement.Predicate.BrokerSummary.DeniedCount,
			"domains_allowed": append([]string(nil), statement.Predicate.BrokerSummary.DomainsAllowed...),
			"domains_denied":  append([]string(nil), statement.Predicate.BrokerSummary.DomainsDenied...),
			"bindings_used":   append([]string(nil), statement.Predicate.BrokerSummary.BindingsUsed...),
		}
	}
}

func (h *ToolHandler) executeHTTP(ctx context.Context, payload api.ExecuteRequest) (api.ExecuteResponse, map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return api.ExecuteResponse{}, nil, fmt.Errorf("marshal execute request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/v1/execute", bytes.NewReader(body))
	if err != nil {
		return api.ExecuteResponse{}, nil, fmt.Errorf("build execute request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.apiKey)
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return api.ExecuteResponse{}, nil, fmt.Errorf("call Aegis orchestrator: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return api.ExecuteResponse{}, nil, fmt.Errorf("read execute response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var envelope api.ErrorEnvelope
		if json.Unmarshal(respBytes, &envelope) == nil && envelope.Error.Code != "" {
			return api.ExecuteResponse{}, nil, fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return api.ExecuteResponse{}, nil, fmt.Errorf("aegis execute returned HTTP %d", resp.StatusCode)
	}
	var decoded api.ExecuteResponse
	if err := json.Unmarshal(respBytes, &decoded); err != nil {
		return api.ExecuteResponse{}, nil, fmt.Errorf("decode execute response: %w", err)
	}
	raw := map[string]any{}
	_ = json.Unmarshal(respBytes, &raw)
	return decoded, raw, nil
}

func BuildDefaultIntent(executionID string, language string, timeoutSec float64, networkDomains []string, writePaths []string, delegations []BrokerDelegation) (policycontract.IntentContract, error) {
	if executionID == "" {
		return policycontract.IntentContract{}, &InvalidParamsError{Message: "execution_id is required"}
	}
	language = normalizeLanguage(language)
	if language == "" {
		return policycontract.IntentContract{}, &InvalidParamsError{Message: "language must be one of python, bash, node"}
	}
	allowedDomains, err := cleanStringList(networkDomains, false)
	if err != nil {
		return policycontract.IntentContract{}, err
	}
	writeList, err := cleanStringList(writePaths, true)
	if err != nil {
		return policycontract.IntentContract{}, err
	}
	for _, runtimePath := range runtimeWritePaths(language) {
		if !slices.Contains(writeList, runtimePath) {
			writeList = append(writeList, runtimePath)
		}
	}
	allowedDelegations := make([]string, 0, len(delegations))
	for _, delegation := range delegations {
		name := strings.TrimSpace(delegation.Name)
		if name == "" {
			return policycontract.IntentContract{}, &InvalidParamsError{Message: "broker_delegations entries require name"}
		}
		if !slices.Contains(allowedDelegations, name) {
			allowedDelegations = append(allowedDelegations, name)
		}
	}
	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     executionID,
		WorkflowID:      defaultWorkflowID,
		TaskClass:       "mcp_execute",
		DeclaredPurpose: fmt.Sprintf("Execute %s code via the Aegis MCP server", language),
		Language:        language,
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    defaultWorkspace,
			ReadPaths:        []string{defaultWorkspace},
			WritePaths:       writeList,
			DenyPaths:        []string{},
			MaxDistinctFiles: maxDistinctFiles(language, writeList),
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     len(allowedDomains) > 0,
			AllowedDomains:   allowedDomains,
			AllowedIPs:       []string{},
			MaxDNSQueries:    len(allowedDomains),
			MaxOutboundConns: len(allowedDomains),
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:     []string{defaultBinaryFor(language)},
			AllowShell:          language == "bash",
			AllowPackageInstall: false,
			MaxChildProcesses:   defaultChildProcesses(language),
		},
		BrokerScope: policycontract.BrokerScope{
			AllowedDelegations: allowedDelegations,
			RequireHostConsent: false,
		},
		Budgets: policycontract.BudgetLimits{
			TimeoutSec:  int(math.Ceil(timeoutSec)),
			MemoryMB:    defaultMemoryMB,
			CPUQuota:    defaultCPUQuota,
			StdoutBytes: defaultStdoutBytes,
		},
		Attributes: map[string]string{"surface": "mcp"},
	}
	if err := intent.Validate(); err != nil {
		return policycontract.IntentContract{}, &InvalidParamsError{Message: err.Error()}
	}
	return intent, nil
}

func executeInputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"code": map[string]any{"type": "string", "description": "Code to execute."},
			"language": map[string]any{
				"type":        "string",
				"enum":        []string{"python", "bash", "node"},
				"description": "Execution language.",
			},
			"timeout_sec": map[string]any{
				"type":        "number",
				"default":     defaultTimeoutSec,
				"description": "Execution timeout in seconds.",
			},
			"allow_network_domains": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional domain allowlist for outbound network access.",
			},
			"allow_write_paths": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Optional writable guest paths. Absolute guest paths only.",
			},
			"broker_delegations": map[string]any{
				"type":        "array",
				"description": "Optional broker delegations to request.",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":     map[string]any{"type": "string"},
						"resource": map[string]any{"type": "string"},
						"method":   map[string]any{"type": "string"},
					},
					"required": []string{"name"},
				},
			},
		},
		"required": []string{"code", "language"},
	}
}

func verifyInputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"execution_id": map[string]any{"type": "string", "description": "Execution ID to resolve under the local Aegis proof root."},
			"proof_dir":    map[string]any{"type": "string", "description": "Explicit proof bundle directory."},
		},
	}
}

func toolResultFromStructured(payload any, ok bool) CallToolResult {
	encoded, _ := json.MarshalIndent(payload, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(encoded),
		}},
		StructuredContent: mustStructuredContent(payload),
		IsError:           !ok,
	}
}

func mustStructuredContent(payload any) map[string]any {
	encoded, _ := json.Marshal(payload)
	decoded := map[string]any{}
	_ = json.Unmarshal(encoded, &decoded)
	return decoded
}

func decodeToolArgs[T any](args map[string]any) (T, error) {
	var decoded T
	raw, err := json.Marshal(args)
	if err != nil {
		return decoded, &InvalidParamsError{Message: "encode tool arguments", Details: map[string]any{"cause": err.Error()}}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return decoded, &InvalidParamsError{Message: "invalid tool arguments", Details: map[string]any{"cause": err.Error()}}
	}
	return decoded, nil
}

func validateTimeout(timeout *float64) (float64, error) {
	if timeout == nil {
		return defaultTimeoutSec, nil
	}
	if *timeout <= 0 {
		return 0, &InvalidParamsError{Message: "timeout_sec must be greater than zero"}
	}
	return *timeout, nil
}

func cleanStringList(values []string, requireAbs bool) ([]string, error) {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if requireAbs && !filepath.IsAbs(trimmed) {
			return nil, &InvalidParamsError{Message: "allow_write_paths entries must be absolute guest paths", Details: map[string]any{"path": trimmed}}
		}
		if !slices.Contains(cleaned, trimmed) {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned, nil
}

func summaryText(path string, statement receipt.Statement) string {
	if path != "" {
		if bytes, err := os.ReadFile(path); err == nil {
			return string(bytes)
		}
	}
	return receipt.FormatSummary(statement, true)
}

func normalizeLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "python", "python3":
		return "python"
	case "bash", "sh":
		return "bash"
	case "node", "javascript", "js":
		return "node"
	default:
		return ""
	}
}

func defaultBinaryFor(language string) string {
	switch language {
	case "python":
		return "python3"
	case "node":
		return "node"
	default:
		return "bash"
	}
}

func defaultChildProcesses(language string) int {
	if language == "bash" {
		return 2
	}
	return 1
}

func maxDistinctFiles(language string, writePaths []string) int {
	base := 64
	if len(writePaths)+base > base {
		return len(writePaths) + base
	}
	return base
}

func runtimeWritePaths(language string) []string {
	if language == "bash" {
		return []string{"/dev/tty"}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func intentWire(intent policycontract.IntentContract) map[string]any {
	return map[string]any{
		"version":          intent.Version,
		"execution_id":     intent.ExecutionID,
		"workflow_id":      intent.WorkflowID,
		"task_class":       intent.TaskClass,
		"declared_purpose": intent.DeclaredPurpose,
		"language":         intent.Language,
		"resource_scope": map[string]any{
			"workspace_root":     intent.ResourceScope.WorkspaceRoot,
			"read_paths":         intent.ResourceScope.ReadPaths,
			"write_paths":        intent.ResourceScope.WritePaths,
			"deny_paths":         intent.ResourceScope.DenyPaths,
			"max_distinct_files": intent.ResourceScope.MaxDistinctFiles,
		},
		"network_scope": map[string]any{
			"allow_network":      intent.NetworkScope.AllowNetwork,
			"allowed_domains":    intent.NetworkScope.AllowedDomains,
			"allowed_ips":        intent.NetworkScope.AllowedIPs,
			"max_dns_queries":    intent.NetworkScope.MaxDNSQueries,
			"max_outbound_conns": intent.NetworkScope.MaxOutboundConns,
		},
		"process_scope": map[string]any{
			"allowed_binaries":      intent.ProcessScope.AllowedBinaries,
			"allow_shell":           intent.ProcessScope.AllowShell,
			"allow_package_install": intent.ProcessScope.AllowPackageInstall,
			"max_child_processes":   intent.ProcessScope.MaxChildProcesses,
		},
		"broker_scope": map[string]any{
			"allowed_delegations":  intent.BrokerScope.AllowedDelegations,
			"require_host_consent": intent.BrokerScope.RequireHostConsent,
		},
		"budgets": map[string]any{
			"timeout_sec":  intent.Budgets.TimeoutSec,
			"memory_mb":    intent.Budgets.MemoryMB,
			"cpu_quota":    intent.Budgets.CPUQuota,
			"stdout_bytes": intent.Budgets.StdoutBytes,
		},
		"attributes": intent.Attributes,
	}
}

package capabilities

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"aegis/internal/governance"
	policycontract "aegis/internal/policy/contract"
)

const (
	defaultTimeoutSec  = 10
	defaultMemoryMB    = 128
	defaultCPUQuota    = 100
	defaultStdoutBytes = 4096
	defaultWorkflowID  = "mcp_local"
	defaultWorkspace   = "/workspace"
)

type Request struct {
	NetworkDomains []string       `json:"network_domains,omitempty"`
	WritePaths     []string       `json:"write_paths,omitempty"`
	Broker         *BrokerRequest `json:"broker,omitempty"`
}

type BrokerRequest struct {
	Delegations     []Delegation `json:"delegations,omitempty"`
	HTTPRequests    bool         `json:"http_requests,omitempty"`
	DependencyFetch bool         `json:"dependency_fetch,omitempty"`
}

type Delegation struct {
	Name     string `json:"name"`
	Resource string `json:"resource,omitempty"`
	Method   string `json:"method,omitempty"`
}

type InvalidRequestError struct {
	Message string
}

func (e *InvalidRequestError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type CompiledIntent struct {
	Intent policycontract.IntentContract
	Raw    json.RawMessage
}

func (r *Request) IsZero() bool {
	if r == nil {
		return true
	}
	if len(r.NetworkDomains) > 0 || len(r.WritePaths) > 0 {
		return false
	}
	if r.Broker == nil {
		return true
	}
	return len(r.Broker.Delegations) == 0 && !r.Broker.HTTPRequests && !r.Broker.DependencyFetch
}

func NormalizeLanguage(language string) string {
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

func WorkspaceRequired(writePaths []string) bool {
	for _, path := range writePaths {
		clean := filepath.Clean(strings.TrimSpace(path))
		if clean == defaultWorkspace || strings.HasPrefix(clean, defaultWorkspace+"/") {
			return true
		}
	}
	return false
}

func Compile(executionID string, language string, timeoutSec float64, req Request) (CompiledIntent, error) {
	if strings.TrimSpace(executionID) == "" {
		return CompiledIntent{}, &InvalidRequestError{Message: "execution_id is required"}
	}
	language = NormalizeLanguage(language)
	if language == "" {
		return CompiledIntent{}, &InvalidRequestError{Message: "language must be one of python, bash, node"}
	}
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	allowedDomains, err := cleanStringList(req.NetworkDomains, false, "network_domains")
	if err != nil {
		return CompiledIntent{}, err
	}
	writeList, err := cleanStringList(req.WritePaths, true, "write_paths")
	if err != nil {
		return CompiledIntent{}, err
	}
	for _, runtimePath := range runtimeWritePaths(language) {
		if !slices.Contains(writeList, runtimePath) {
			writeList = append(writeList, runtimePath)
		}
	}

	broker := req.Broker
	if broker == nil {
		broker = &BrokerRequest{}
	}
	allowedDelegations := make([]string, 0, len(broker.Delegations))
	brokerDomains := make([]string, 0, len(broker.Delegations))
	for _, delegation := range broker.Delegations {
		name := strings.TrimSpace(delegation.Name)
		if name == "" {
			return CompiledIntent{}, &InvalidRequestError{Message: "capabilities.broker.delegations entries require name"}
		}
		resource := strings.TrimSpace(delegation.Resource)
		if resource == "" {
			return CompiledIntent{}, &InvalidRequestError{Message: "capabilities.broker.delegations entries require resource"}
		}
		domain, err := delegationDomain(resource)
		if err != nil {
			return CompiledIntent{}, &InvalidRequestError{Message: fmt.Sprintf("capabilities.broker.delegations resource must be a hostname or URL: %v", err)}
		}
		if !slices.Contains(allowedDelegations, name) {
			allowedDelegations = append(allowedDelegations, name)
		}
		if !slices.Contains(brokerDomains, domain) {
			brokerDomains = append(brokerDomains, domain)
		}
	}

	brokerActionTypes := make([]string, 0, 2)
	if broker.HTTPRequests {
		brokerActionTypes = append(brokerActionTypes, governance.ActionHTTPRequest)
	}
	if broker.DependencyFetch {
		brokerActionTypes = append(brokerActionTypes, governance.ActionDependencyFetch)
	}
	brokerActionTypes = governance.EffectiveBrokerActionTypes(policycontract.BrokerScope{
		AllowedDomains:     brokerDomains,
		AllowedActionTypes: brokerActionTypes,
	})

	allowNetwork := len(allowedDomains) > 0 || len(brokerDomains) > 0
	allowedIPs := []string{}
	maxOutboundConns := len(allowedDomains)
	if len(brokerDomains) > 0 {
		if maxOutboundConns < 1 {
			maxOutboundConns = 1
		}
	}

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     executionID,
		WorkflowID:      defaultWorkflowID,
		TaskClass:       "capability_execute",
		DeclaredPurpose: fmt.Sprintf("Execute %s code via the Aegis capability request surface", language),
		Language:        language,
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    defaultWorkspace,
			ReadPaths:        runtimeReadPaths(language),
			WritePaths:       writeList,
			DenyPaths:        []string{},
			MaxDistinctFiles: maxDistinctFiles(language, writeList),
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     allowNetwork,
			AllowedDomains:   allowedDomains,
			AllowedIPs:       allowedIPs,
			MaxDNSQueries:    len(allowedDomains),
			MaxOutboundConns: maxOutboundConns,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:     []string{defaultBinaryFor(language)},
			AllowShell:          language == "bash",
			AllowPackageInstall: false,
			MaxChildProcesses:   defaultChildProcesses(language),
		},
		BrokerScope: policycontract.BrokerScope{
			AllowedDelegations: allowedDelegations,
			AllowedDomains:     brokerDomains,
			AllowedActionTypes: brokerActionTypes,
			RequireHostConsent: false,
		},
		Budgets: policycontract.BudgetLimits{
			TimeoutSec:  int(math.Ceil(timeoutSec)),
			MemoryMB:    defaultMemoryMB,
			CPUQuota:    defaultCPUQuota,
			StdoutBytes: defaultStdoutBytes,
		},
		Attributes: map[string]string{"surface": "capability_request"},
	}
	if err := intent.Validate(); err != nil {
		return CompiledIntent{}, &InvalidRequestError{Message: err.Error()}
	}
	raw, err := MarshalIntentJSON(intent)
	if err != nil {
		return CompiledIntent{}, err
	}
	return CompiledIntent{Intent: intent, Raw: raw}, nil
}

func MarshalIntentJSON(intent policycontract.IntentContract) (json.RawMessage, error) {
	wire := map[string]any{
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
			"allowed_domains":      intent.BrokerScope.AllowedDomains,
			"allowed_action_types": intent.BrokerScope.AllowedActionTypes,
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
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal intent: %w", err)
	}
	return json.RawMessage(encoded), nil
}

func cleanStringList(values []string, requireAbs bool, field string) ([]string, error) {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if requireAbs && !filepath.IsAbs(trimmed) {
			return nil, &InvalidRequestError{Message: fmt.Sprintf("%s entries must be absolute guest paths", field)}
		}
		if !slices.Contains(cleaned, trimmed) {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned, nil
}

func delegationDomain(resource string) (string, error) {
	trimmed := strings.TrimSpace(resource)
	if trimmed == "" {
		return "", fmt.Errorf("empty resource")
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname()), nil
	}
	if !strings.Contains(trimmed, "://") {
		parsed, err := url.Parse("https://" + trimmed)
		if err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname()), nil
		}
	}
	return "", fmt.Errorf("resource %q has no hostname", trimmed)
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

func runtimeReadPaths(language string) []string {
	readPaths := []string{defaultWorkspace}
	switch language {
	case "python", "node":
		readPaths = append(readPaths, "/tmp")
	}
	return readPaths
}

func DecodeJSON[T any](raw []byte) (T, error) {
	var decoded T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return decoded, err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return decoded, fmt.Errorf("trailing content")
		}
		return decoded, err
	}
	return decoded, nil
}

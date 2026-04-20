package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/models"
	policycfg "aegis/internal/policy"
)

type IntentContract struct {
	Version         string
	ExecutionID     string
	WorkflowID      string
	TaskClass       string
	DeclaredPurpose string
	Language        string
	BackendHint     models.RuntimeBackend
	ResourceScope   ResourceScope
	NetworkScope    NetworkScope
	ProcessScope    ProcessScope
	BrokerScope     BrokerScope
	Budgets         BudgetLimits
	Attributes      map[string]string
}

type ResourceScope struct {
	WorkspaceRoot    string
	ReadPaths        []string
	WritePaths       []string
	DenyPaths        []string
	MaxDistinctFiles int
}

type NetworkScope struct {
	AllowNetwork            bool
	AllowedDomains          []string
	AllowedIPs              []string
	AllowedDomainsSpecified bool `json:"-"`
	AllowedIPsSpecified     bool `json:"-"`
	MaxDNSQueries           int
	MaxOutboundConns        int
}

type ProcessScope struct {
	AllowedBinaries     []string
	AllowShell          bool
	AllowPackageInstall bool
	MaxChildProcesses   int
}

type BrokerScope struct {
	AllowedDelegations []string
	AllowedDomains     []string
	AllowedActionTypes []string
	RequireHostConsent bool
}

type BudgetLimits struct {
	TimeoutSec  int
	MemoryMB    int
	CPUQuota    int
	StdoutBytes int
}

type intentContractJSON struct {
	Version         string                `json:"version"`
	ExecutionID     string                `json:"execution_id"`
	WorkflowID      string                `json:"workflow_id"`
	TaskClass       string                `json:"task_class"`
	DeclaredPurpose string                `json:"declared_purpose"`
	Language        string                `json:"language"`
	BackendHint     models.RuntimeBackend `json:"backend_hint,omitempty"`
	ResourceScope   resourceScopeJSON     `json:"resource_scope"`
	NetworkScope    networkScopeJSON      `json:"network_scope"`
	ProcessScope    processScopeJSON      `json:"process_scope"`
	BrokerScope     brokerScopeJSON       `json:"broker_scope"`
	Budgets         budgetsJSON           `json:"budgets"`
	Attributes      map[string]string     `json:"attributes,omitempty"`
}

type resourceScopeJSON struct {
	WorkspaceRoot    string   `json:"workspace_root"`
	ReadPaths        []string `json:"read_paths"`
	WritePaths       []string `json:"write_paths"`
	DenyPaths        []string `json:"deny_paths"`
	MaxDistinctFiles int      `json:"max_distinct_files"`
}

type networkScopeJSON struct {
	AllowNetwork     bool      `json:"allow_network"`
	AllowedDomains   *[]string `json:"allowed_domains,omitempty"`
	AllowedIPs       *[]string `json:"allowed_ips,omitempty"`
	MaxDNSQueries    int       `json:"max_dns_queries"`
	MaxOutboundConns int       `json:"max_outbound_conns"`
}

type processScopeJSON struct {
	AllowedBinaries     []string `json:"allowed_binaries"`
	AllowShell          bool     `json:"allow_shell"`
	AllowPackageInstall bool     `json:"allow_package_install"`
	MaxChildProcesses   int      `json:"max_child_processes"`
}

type brokerScopeJSON struct {
	AllowedDelegations []string `json:"allowed_delegations"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	AllowedActionTypes []string `json:"allowed_action_types,omitempty"`
	RequireHostConsent bool     `json:"require_host_consent"`
}

type budgetsJSON struct {
	TimeoutSec  int `json:"timeout_sec"`
	MemoryMB    int `json:"memory_mb"`
	CPUQuota    int `json:"cpu_quota"`
	StdoutBytes int `json:"stdout_bytes"`
}

func LoadIntentContractJSON(raw []byte) (IntentContract, error) {
	var payload intentContractJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return IntentContract{}, fmt.Errorf("decode intent contract: %w", err)
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return IntentContract{}, fmt.Errorf("decode intent contract: trailing content")
		}
		return IntentContract{}, fmt.Errorf("decode intent contract: trailing content: %w", err)
	}

	intent := IntentContract{
		Version:         payload.Version,
		ExecutionID:     strings.TrimSpace(payload.ExecutionID),
		WorkflowID:      strings.TrimSpace(payload.WorkflowID),
		TaskClass:       strings.TrimSpace(payload.TaskClass),
		DeclaredPurpose: strings.TrimSpace(payload.DeclaredPurpose),
		Language:        strings.TrimSpace(payload.Language),
		BackendHint:     payload.BackendHint,
		ResourceScope: ResourceScope{
			WorkspaceRoot:    cleanAbsPath(payload.ResourceScope.WorkspaceRoot),
			ReadPaths:        cleanAbsPaths(payload.ResourceScope.ReadPaths),
			WritePaths:       cleanAbsPaths(payload.ResourceScope.WritePaths),
			DenyPaths:        cleanAbsPaths(payload.ResourceScope.DenyPaths),
			MaxDistinctFiles: payload.ResourceScope.MaxDistinctFiles,
		},
		NetworkScope: NetworkScope{
			AllowNetwork:            payload.NetworkScope.AllowNetwork,
			AllowedDomains:          cleanStringPointer(payload.NetworkScope.AllowedDomains),
			AllowedIPs:              cleanStringPointer(payload.NetworkScope.AllowedIPs),
			AllowedDomainsSpecified: payload.NetworkScope.AllowedDomains != nil,
			AllowedIPsSpecified:     payload.NetworkScope.AllowedIPs != nil,
			MaxDNSQueries:           payload.NetworkScope.MaxDNSQueries,
			MaxOutboundConns:        payload.NetworkScope.MaxOutboundConns,
		},
		ProcessScope: ProcessScope{
			AllowedBinaries:     cleanStrings(payload.ProcessScope.AllowedBinaries),
			AllowShell:          payload.ProcessScope.AllowShell,
			AllowPackageInstall: payload.ProcessScope.AllowPackageInstall,
			MaxChildProcesses:   payload.ProcessScope.MaxChildProcesses,
		},
		BrokerScope: BrokerScope{
			AllowedDelegations: cleanStrings(payload.BrokerScope.AllowedDelegations),
			AllowedDomains:     cleanStrings(payload.BrokerScope.AllowedDomains),
			AllowedActionTypes: cleanStrings(payload.BrokerScope.AllowedActionTypes),
			RequireHostConsent: payload.BrokerScope.RequireHostConsent,
		},
		Budgets: BudgetLimits{
			TimeoutSec:  payload.Budgets.TimeoutSec,
			MemoryMB:    payload.Budgets.MemoryMB,
			CPUQuota:    payload.Budgets.CPUQuota,
			StdoutBytes: payload.Budgets.StdoutBytes,
		},
		Attributes: cloneStringMap(payload.Attributes),
	}
	if err := intent.Validate(); err != nil {
		return IntentContract{}, err
	}
	return intent, nil
}

func (c IntentContract) Validate() error {
	if c.Version != "v1" {
		return fmt.Errorf("intent contract version must be v1")
	}
	if c.ExecutionID == "" {
		return fmt.Errorf("execution_id is required")
	}
	if c.WorkflowID == "" {
		return fmt.Errorf("workflow_id is required")
	}
	if c.TaskClass == "" {
		return fmt.Errorf("task_class is required")
	}
	if c.DeclaredPurpose == "" {
		return fmt.Errorf("declared_purpose is required")
	}
	if c.Language == "" {
		return fmt.Errorf("language is required")
	}
	switch c.BackendHint {
	case "", models.BackendFirecracker, models.BackendGVisor:
	default:
		return fmt.Errorf("backend_hint is invalid: %s", c.BackendHint)
	}
	if err := validateResourceScope(c.ResourceScope); err != nil {
		return err
	}
	if err := validateNetworkScope(c.NetworkScope); err != nil {
		return err
	}
	if err := validateProcessScope(c.ProcessScope); err != nil {
		return err
	}
	if err := validateBrokerScope(c.BrokerScope); err != nil {
		return err
	}
	if err := validateBudgets(c.Budgets); err != nil {
		return err
	}
	return nil
}

func validateResourceScope(scope ResourceScope) error {
	if scope.WorkspaceRoot == "" {
		return fmt.Errorf("resource_scope.workspace_root is required")
	}
	if !isAbs(scope.WorkspaceRoot) {
		return fmt.Errorf("resource_scope.workspace_root must be absolute")
	}
	if scope.MaxDistinctFiles < 1 {
		return fmt.Errorf("resource_scope.max_distinct_files must be greater than 0")
	}
	for _, list := range [][]string{scope.ReadPaths, scope.WritePaths, scope.DenyPaths} {
		for _, path := range list {
			if !isAbs(path) {
				return fmt.Errorf("resource_scope paths must be absolute")
			}
		}
	}
	return nil
}

func validateNetworkScope(scope NetworkScope) error {
	if scope.MaxDNSQueries < 0 {
		return fmt.Errorf("network_scope.max_dns_queries must be non-negative")
	}
	if scope.MaxOutboundConns < 0 {
		return fmt.Errorf("network_scope.max_outbound_conns must be non-negative")
	}
	for _, domain := range scope.AllowedDomains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "*") {
			return fmt.Errorf("network_scope.allowed_domains does not support wildcards: %q", domain)
		}
		if strings.Contains(normalized, "://") || strings.Contains(normalized, "/") {
			return fmt.Errorf("network_scope.allowed_domains must contain bare hostnames: %q", domain)
		}
	}
	for _, addr := range scope.AllowedIPs {
		if _, err := normalizeRequestedNetwork(addr); err != nil {
			return fmt.Errorf("network_scope.allowed_ips contains invalid IP/CIDR %q", addr)
		}
	}
	return nil
}

func ResolveEffectiveAllowlist(scope NetworkScope, baseline policycfg.NetworkAllowlist) (policycfg.NetworkAllowlist, error) {
	baselineFQDNs := normalizeDomains(baseline.FQDNs)
	baselineCIDRs, err := normalizeBaselineCIDRs(baseline.CIDRs)
	if err != nil {
		return policycfg.NetworkAllowlist{}, err
	}
	if !scope.AllowedDomainsSpecified && !scope.AllowedIPsSpecified {
		return policycfg.NetworkAllowlist{
			FQDNs: baselineFQDNs,
			CIDRs: baselineCIDRs,
		}, nil
	}

	requestedFQDNs := []string{}
	if scope.AllowedDomainsSpecified {
		requestedFQDNs = normalizeDomains(scope.AllowedDomains)
		for _, domain := range requestedFQDNs {
			if !containsStringFold(baselineFQDNs, domain) {
				return policycfg.NetworkAllowlist{}, fmt.Errorf("network_scope.allowed_domains entry %q is not present in baseline network.allowlist.fqdns", domain)
			}
		}
	}

	requestedCIDRs := []string{}
	if scope.AllowedIPsSpecified {
		requestedCIDRs, err = normalizeRequestedCIDRs(scope.AllowedIPs)
		if err != nil {
			return policycfg.NetworkAllowlist{}, err
		}
		for _, requested := range requestedCIDRs {
			ok, err := cidrContainedInAny(requested, baselineCIDRs)
			if err != nil {
				return policycfg.NetworkAllowlist{}, err
			}
			if !ok {
				return policycfg.NetworkAllowlist{}, fmt.Errorf("network_scope.allowed_ips entry %q is not contained within baseline network.allowlist.cidrs", requested)
			}
		}
	}

	return policycfg.NetworkAllowlist{
		FQDNs: requestedFQDNs,
		CIDRs: requestedCIDRs,
	}, nil
}

func validateProcessScope(scope ProcessScope) error {
	if scope.MaxChildProcesses < 0 {
		return fmt.Errorf("process_scope.max_child_processes must be non-negative")
	}
	return nil
}

func validateBrokerScope(scope BrokerScope) error {
	for _, delegation := range scope.AllowedDelegations {
		if delegation == "" {
			return fmt.Errorf("broker_scope.allowed_delegations must not contain empty values")
		}
	}
	for _, actionType := range scope.AllowedActionTypes {
		switch strings.ToLower(strings.TrimSpace(actionType)) {
		case "http_request", "dependency_fetch":
		default:
			return fmt.Errorf("broker_scope.allowed_action_types contains invalid value %q", actionType)
		}
	}
	return nil
}

func validateBudgets(b BudgetLimits) error {
	if b.TimeoutSec < 1 {
		return fmt.Errorf("budgets.timeout_sec must be greater than 0")
	}
	if b.MemoryMB < 1 {
		return fmt.Errorf("budgets.memory_mb must be greater than 0")
	}
	if b.CPUQuota < 1 {
		return fmt.Errorf("budgets.cpu_quota must be greater than 0")
	}
	if b.StdoutBytes < 1 {
		return fmt.Errorf("budgets.stdout_bytes must be greater than 0")
	}
	return nil
}

func cleanAbsPaths(paths []string) []string {
	if len(paths) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		cleaned := cleanAbsPath(path)
		if cleaned == "" {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result
}

func cleanAbsPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	return filepath.Clean(trimmed)
}

func cleanStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func cleanStringPointer(values *[]string) []string {
	if values == nil {
		return []string{}
	}
	return cleanStrings(*values)
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func isAbs(path string) bool {
	return strings.HasPrefix(path, "/")
}

func normalizeDomains(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		value = strings.TrimSuffix(value, ".")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeBaselineCIDRs(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		prefix, err := normalizeRequestedNetwork(raw)
		if err != nil {
			return nil, fmt.Errorf("baseline network.allowlist.cidrs contains invalid CIDR %q", raw)
		}
		if !strings.Contains(strings.TrimSpace(raw), "/") {
			return nil, fmt.Errorf("baseline network.allowlist.cidrs must use CIDR notation: %q", raw)
		}
		canonical := prefix.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeRequestedCIDRs(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		prefix, err := normalizeRequestedNetwork(raw)
		if err != nil {
			return nil, fmt.Errorf("network_scope.allowed_ips contains invalid IP/CIDR %q", raw)
		}
		if prefix.Addr().IsLoopback() {
			continue
		}
		canonical := prefix.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeRequestedNetwork(raw string) (netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("empty network value")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("only IPv4 CIDRs are supported")
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("only IPv4 addresses are supported")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func cidrContainedInAny(requested string, baseline []string) (bool, error) {
	reqPrefix, err := netip.ParsePrefix(requested)
	if err != nil {
		return false, err
	}
	reqRange, err := prefixRange(reqPrefix)
	if err != nil {
		return false, err
	}
	for _, raw := range baseline {
		basePrefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return false, err
		}
		baseRange, err := prefixRange(basePrefix)
		if err != nil {
			return false, err
		}
		if compareAddr(reqRange.first, baseRange.first) >= 0 && compareAddr(reqRange.last, baseRange.last) <= 0 {
			return true, nil
		}
	}
	return false, nil
}

type cidrAddrRange struct {
	first netip.Addr
	last  netip.Addr
}

func prefixRange(prefix netip.Prefix) (cidrAddrRange, error) {
	start := prefix.Masked().Addr()
	if !start.Is4() {
		return cidrAddrRange{}, fmt.Errorf("only IPv4 prefixes are supported")
	}
	maskSize := prefix.Bits()
	hostBits := 32 - maskSize
	startBytes := start.As4()
	startInt := uint32(startBytes[0])<<24 | uint32(startBytes[1])<<16 | uint32(startBytes[2])<<8 | uint32(startBytes[3])
	endInt := startInt | ((1 << hostBits) - 1)
	return cidrAddrRange{
		first: start,
		last: netip.AddrFrom4([4]byte{
			byte(endInt >> 24),
			byte(endInt >> 16),
			byte(endInt >> 8),
			byte(endInt),
		}),
	}, nil
}

func compareAddr(a, b netip.Addr) int {
	a4 := a.As4()
	b4 := b.As4()
	for i := range a4 {
		switch {
		case a4[i] < b4[i]:
			return -1
		case a4[i] > b4[i]:
			return 1
		}
	}
	return 0
}

func containsStringFold(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

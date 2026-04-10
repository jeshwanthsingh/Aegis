package evaluator

import (
	"path/filepath"
	"strings"

	"aegis/internal/models"
	"aegis/internal/policy/cedar"
	"aegis/internal/policy/contract"
)

type Evaluator struct {
	intent   contract.IntentContract
	compiled cedar.CompiledContract
}

func New(intent contract.IntentContract) *Evaluator {
	return &Evaluator{
		intent:   intent,
		compiled: cedar.Compile(intent),
	}
}

func (e *Evaluator) Evaluate(event models.RuntimeEvent) models.PolicyPointDecision {
	action, ok := mapEventAction(event)
	if !ok {
		return models.PolicyPointDecision{
			ExecutionID: event.ExecutionID,
			EventSeq:    event.Seq,
			EventType:   event.Type,
			Decision:    models.DecisionNotApplicable,
			Reason:      "event type not mapped to point decision",
			Metadata:    map[string]string{},
		}
	}

	result := models.PolicyPointDecision{
		ExecutionID: event.ExecutionID,
		EventSeq:    event.Seq,
		EventType:   event.Type,
		CedarAction: action,
		Decision:    models.DecisionAllow,
		Reason:      "allowed by intent contract",
		Metadata: map[string]string{
			"task_class": e.compiled.Context.TaskClass,
		},
	}

	switch action {
	case models.ActionExec:
		return e.evaluateExec(event, result)
	case models.ActionRead:
		return e.evaluateFileAccess(event, result, false)
	case models.ActionWrite:
		return e.evaluateFileAccess(event, result, true)
	case models.ActionConnect:
		return e.evaluateConnect(event, result)
	default:
		result.Decision = models.DecisionNotApplicable
		result.Reason = "action not implemented for point decision"
		return result
	}
}

func mapEventAction(event models.RuntimeEvent) (models.CedarAction, bool) {
	switch event.Type {
	case models.EventProcessExec:
		return models.ActionExec, true
	case models.EventFileOpen:
		if models.FileOpenHasWriteIntent(event.Flags) {
			return models.ActionWrite, true
		}
		return models.ActionRead, true
	case models.EventNetConnect:
		return models.ActionConnect, true
	default:
		return "", false
	}
}

func (e *Evaluator) evaluateExec(event models.RuntimeEvent, result models.PolicyPointDecision) models.PolicyPointDecision {
	binaryPath := strings.TrimSpace(event.Exe)
	if binaryPath == "" {
		binaryPath = strings.TrimSpace(event.Comm)
	}
	base := filepath.Base(binaryPath)
	result.Metadata["binary"] = base

	if isShellBinary(base) && !e.compiled.Context.AllowShell {
		result.Decision = models.DecisionDeny
		result.Reason = "shell execution is not allowed"
		return result
	}
	if isPackageInstaller(base) && !e.compiled.Context.AllowPackageInstall {
		result.Decision = models.DecisionDeny
		result.Reason = "package installation tooling is not allowed"
		return result
	}
	if len(e.compiled.Principal.AllowedBinaries) == 0 {
		result.Decision = models.DecisionDeny
		result.Reason = "no binaries are allowlisted"
		return result
	}
	if !containsBinary(e.compiled.Principal.AllowedBinaries, base, binaryPath) {
		result.Decision = models.DecisionDeny
		result.Reason = "binary is outside allowed_binaries"
		return result
	}
	return result
}

func (e *Evaluator) evaluateFileAccess(event models.RuntimeEvent, result models.PolicyPointDecision, writeIntent bool) models.PolicyPointDecision {
	path := cleanPath(event.Path)
	result.Metadata["path"] = path
	result.Metadata["mode"] = models.FileOpenAccessMode(event.Flags)

	if writeIntent {
		result.Metadata["flags"] = models.FileOpenFlagSummary(event.Flags)
		result.Metadata["limitation"] = "file.open reflects write-intent from open flags, not a proven completed write"
		if models.FileOpenHasDestructiveFlags(event.Flags) {
			result.Metadata["destructive_flags"] = "true"
		}
	} else {
		result.Metadata["limitation"] = "file.open read decisions reflect open intent only, not completed reads"
	}

	if path == "" {
		result.Decision = models.DecisionDeny
		result.Reason = "file path is missing"
		return result
	}
	if !writeIntent {
		if baseline, ok := runtimeBaselineRead(path); ok {
			result.Metadata["baseline"] = baseline
			result.Reason = "allowed by runtime baseline"
			return result
		}
	}
	if pathMatchesAny(path, e.compiled.Principal.DenyPaths) {
		result.Decision = models.DecisionDeny
		result.Reason = "path matches deny_paths"
		return result
	}
	if writeIntent {
		if pathMatchesAny(path, e.compiled.Principal.WritePaths) {
			return result
		}
		result.Decision = models.DecisionDeny
		result.Reason = "path is outside write_paths"
		return result
	}
	if pathMatchesAny(path, e.compiled.Principal.ReadPaths) {
		return result
	}
	result.Decision = models.DecisionDeny
	result.Reason = "path is outside read_paths"
	return result
}

func (e *Evaluator) evaluateConnect(event models.RuntimeEvent, result models.PolicyPointDecision) models.PolicyPointDecision {
	result.Metadata["dst_ip"] = strings.TrimSpace(event.DstIP)
	if event.Domain != "" {
		result.Metadata["domain"] = strings.TrimSpace(event.Domain)
	}

	if !e.compiled.Context.AllowNetwork {
		result.Decision = models.DecisionDeny
		result.Reason = "network access is disabled by intent contract"
		return result
	}

	hasDomainRules := len(e.compiled.Principal.AllowedDomains) > 0
	hasIPRules := len(e.compiled.Principal.AllowedIPs) > 0
	if !hasDomainRules && !hasIPRules {
		return result
	}
	if event.Domain != "" && containsString(e.compiled.Principal.AllowedDomains, event.Domain) {
		return result
	}
	if event.DstIP != "" && containsString(e.compiled.Principal.AllowedIPs, event.DstIP) {
		return result
	}
	result.Decision = models.DecisionDeny
	result.Reason = "destination is outside network allowlists"
	return result
}

func containsBinary(allowed []string, base string, full string) bool {
	for _, candidate := range allowed {
		if candidate == base || candidate == full || filepath.Base(candidate) == base {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pathMatchesAny(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		prefix = cleanPath(prefix)
		if prefix == "" {
			continue
		}
		if path == prefix {
			return true
		}
		if strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func cleanPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}

func runtimeBaselineRead(path string) (string, bool) {
	exact := map[string]string{
		"/etc/ld.so.cache":   "runtime_loader",
		"/etc/localtime":     "runtime_loader",
		"/etc/host.conf":     "runtime_network",
		"/etc/hosts":         "runtime_network",
		"/etc/nsswitch.conf": "runtime_network",
		"/etc/resolv.conf":   "runtime_network",
	}
	if baseline, ok := exact[path]; ok {
		return baseline, true
	}
	prefixes := map[string]string{
		"/lib/":           "runtime_loader",
		"/usr/lib/":       "runtime_loader",
		"/usr/local/lib/": "runtime_loader",
		"/tmp/launcher-":  "runtime_launcher",
	}
	for prefix, baseline := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return baseline, true
		}
	}
	return "", false
}

func isShellBinary(name string) bool {
	switch name {
	case "sh", "ash", "bash", "dash", "zsh", "ksh", "fish":
		return true
	default:
		return false
	}
}

func isPackageInstaller(name string) bool {
	switch name {
	case "pip", "pip3", "npm", "pnpm", "yarn", "apk", "apt", "apt-get", "dnf", "yum", "gem", "cargo", "brew":
		return true
	default:
		return false
	}
}

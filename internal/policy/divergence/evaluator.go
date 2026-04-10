package divergence

import (
	"fmt"
	"strconv"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

const (
	repeatedShellExecWarnThreshold  = 3
	repeatedDeniedConnectThreshold  = 2
	repeatedDeniedFileOpenThreshold = 3
	workspaceScanFloor              = 4
	execBudgetSlack                 = 2
)

type Evaluator struct {
	intent contract.IntentContract
	state  *State
}

type ObserveOutcome struct {
	Result         models.PolicyDivergenceResult
	NewRuleHits    []models.DivergenceRuleHit
	VerdictChanged bool
}

func New(intent contract.IntentContract) *Evaluator {
	return &Evaluator{
		intent: intent,
		state:  newState(intent),
	}
}

func (e *Evaluator) Observe(event models.RuntimeEvent, decision *models.PolicyPointDecision) ObserveOutcome {
	previous := e.state.Verdict
	e.state.applyEvent(e.intent, event, decision)
	hits := e.evaluateRules(event, decision)
	newHits := make([]models.DivergenceRuleHit, 0, len(hits))
	for _, hit := range hits {
		if e.state.addRuleHit(hit) {
			newHits = append(newHits, hit)
		}
	}
	result := e.state.result(e.intent)
	return ObserveOutcome{
		Result:         result,
		NewRuleHits:    newHits,
		VerdictChanged: previous != result.CurrentVerdict,
	}
}

func (e *Evaluator) evaluateRules(event models.RuntimeEvent, decision *models.PolicyPointDecision) []models.DivergenceRuleHit {
	var hits []models.DivergenceRuleHit
	if hit, ok := e.ruleShellDisallowed(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleRepeatedShellExec(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleShellSpawnDenied(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.rulePackageInstallDisallowed(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleChildLimitExceeded(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleExecBudgetExceeded(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleDistinctFileLimitExceeded(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleRepeatedDeniedFileOpen(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleWriteOutsideScope(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleWriteDenied(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleDestructiveWriteIntent(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleWorkspaceScanBeforeTarget(event); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleNetworkDisabledConnect(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleRepeatedDeniedConnect(event, decision); ok {
		hits = append(hits, hit)
	}
	if hit, ok := e.ruleConnectFanoutExceeded(event); ok {
		hits = append(hits, hit)
	}
	return hits
}

func (e *Evaluator) ruleShellDisallowed(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventProcessExec || e.intent.ProcessScope.AllowShell {
		return models.DivergenceRuleHit{}, false
	}
	binary := eventBinary(event)
	if !isShellBinary(binary) {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("process.shell_disallowed", "process", models.DivergenceSeverityKillCandidate, fmt.Sprintf("shell binary %s executed while allow_shell=false", binary), event.Seq, map[string]string{"binary": binary, "point_decision": pointDecisionValue(decision)}), true
}

func (e *Evaluator) ruleRepeatedShellExec(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventProcessExec {
		return models.DivergenceRuleHit{}, false
	}
	if e.state.Process.ShellExecCount <= repeatedShellExecWarnThreshold {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("process.shell_fanout", "process", models.DivergenceSeverityWarn, fmt.Sprintf("shell_exec_count=%d exceeded threshold=%d", e.state.Process.ShellExecCount, repeatedShellExecWarnThreshold), event.Seq, map[string]string{"shell_exec_count": strconv.Itoa(e.state.Process.ShellExecCount), "threshold": strconv.Itoa(repeatedShellExecWarnThreshold)}), true
}

func (e *Evaluator) ruleShellSpawnDenied(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventProcessExec || decision == nil || decision.Decision != models.DecisionDeny {
		return models.DivergenceRuleHit{}, false
	}
	parentBinary, ok := e.state.Process.BinaryByPID[event.PPID]
	if !ok || !isShellBinary(parentBinary) {
		return models.DivergenceRuleHit{}, false
	}
	binary := eventBinary(event)
	return ruleHit("process.shell_spawn_denied", "process", models.DivergenceSeverityKillCandidate, fmt.Sprintf("shell parent %s spawned denied binary %s", parentBinary, binary), event.Seq, map[string]string{"parent_binary": parentBinary, "binary": binary}), true
}

func (e *Evaluator) rulePackageInstallDisallowed(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventProcessExec || e.intent.ProcessScope.AllowPackageInstall {
		return models.DivergenceRuleHit{}, false
	}
	binary := eventBinary(event)
	if !isPackageInstaller(binary) {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("process.package_install_disallowed", "process", models.DivergenceSeverityKillCandidate, fmt.Sprintf("package installer %s executed while allow_package_install=false", binary), event.Seq, map[string]string{"binary": binary}), true
}

func (e *Evaluator) ruleChildLimitExceeded(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if e.intent.ProcessScope.MaxChildProcesses <= 0 {
		return models.DivergenceRuleHit{}, false
	}
	if len(e.state.Process.ChildPIDs) <= e.intent.ProcessScope.MaxChildProcesses {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("process.child_limit_exceeded", "process", models.DivergenceSeverityKillCandidate, fmt.Sprintf("child_process_count=%d exceeded max_child_processes=%d", len(e.state.Process.ChildPIDs), e.intent.ProcessScope.MaxChildProcesses), event.Seq, map[string]string{"child_process_count": strconv.Itoa(len(e.state.Process.ChildPIDs)), "max_child_processes": strconv.Itoa(e.intent.ProcessScope.MaxChildProcesses)}), true
}

func (e *Evaluator) ruleExecBudgetExceeded(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventProcessExec {
		return models.DivergenceRuleHit{}, false
	}
	budget := execBudget(e.intent)
	if e.state.Process.ExecCount <= budget {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("process.exec_budget_exceeded", "process", models.DivergenceSeverityWarn, fmt.Sprintf("exec_count=%d exceeded exec_budget=%d", e.state.Process.ExecCount, budget), event.Seq, map[string]string{"exec_count": strconv.Itoa(e.state.Process.ExecCount), "exec_budget": strconv.Itoa(budget)}), true
}

func (e *Evaluator) ruleDistinctFileLimitExceeded(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen {
		return models.DivergenceRuleHit{}, false
	}
	if len(e.state.File.DistinctPaths) <= e.intent.ResourceScope.MaxDistinctFiles {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("file.distinct_limit_exceeded", "filesystem", models.DivergenceSeverityKillCandidate, fmt.Sprintf("distinct_paths=%d exceeded max_distinct_files=%d under file-open intent semantics", len(e.state.File.DistinctPaths), e.intent.ResourceScope.MaxDistinctFiles), event.Seq, map[string]string{"distinct_paths": strconv.Itoa(len(e.state.File.DistinctPaths)), "max_distinct_files": strconv.Itoa(e.intent.ResourceScope.MaxDistinctFiles), "mode": models.FileOpenAccessMode(event.Flags)}), true
}

func (e *Evaluator) ruleRepeatedDeniedFileOpen(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen || decision == nil || decision.Decision != models.DecisionDeny || decision.CedarAction != models.ActionRead {
		return models.DivergenceRuleHit{}, false
	}
	deniedCount := deniedFileCount(e.state.File.DeniedPaths)
	if deniedCount < repeatedDeniedFileOpenThreshold {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("file.denied_repeated", "filesystem", models.DivergenceSeverityWarn, fmt.Sprintf("denied_file_open_count=%d reached probing threshold=%d under read-only file semantics", deniedCount, repeatedDeniedFileOpenThreshold), event.Seq, map[string]string{"denied_file_open_count": strconv.Itoa(deniedCount), "threshold": strconv.Itoa(repeatedDeniedFileOpenThreshold), "mode": "read-only"}), true
}

func (e *Evaluator) ruleWriteOutsideScope(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen || decision == nil || decision.CedarAction != models.ActionWrite || decision.Decision != models.DecisionDeny || decision.Reason != "path is outside write_paths" {
		return models.DivergenceRuleHit{}, false
	}
	path := cleanPath(event.Path)
	flags := models.FileOpenFlagSummary(event.Flags)
	return ruleHit("file.write_outside_scope", "filesystem", models.DivergenceSeverityKillCandidate, fmt.Sprintf("write-intent open path=%s is outside write_paths flags=%s", path, flags), event.Seq, map[string]string{"path": path, "flags": flags}), true
}

func (e *Evaluator) ruleWriteDenied(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen || decision == nil || decision.CedarAction != models.ActionWrite || decision.Decision != models.DecisionDeny || decision.Reason == "path is outside write_paths" {
		return models.DivergenceRuleHit{}, false
	}
	path := cleanPath(event.Path)
	flags := models.FileOpenFlagSummary(event.Flags)
	return ruleHit("file.write_denied", "filesystem", models.DivergenceSeverityKillCandidate, fmt.Sprintf("write-intent open path=%s denied: %s flags=%s", path, decision.Reason, flags), event.Seq, map[string]string{"path": path, "reason": decision.Reason, "flags": flags}), true
}

func (e *Evaluator) ruleDestructiveWriteIntent(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen || decision == nil || decision.CedarAction != models.ActionWrite || decision.Decision != models.DecisionDeny || !models.FileOpenHasDestructiveFlags(event.Flags) {
		return models.DivergenceRuleHit{}, false
	}
	path := cleanPath(event.Path)
	flags := models.FileOpenFlagSummary(event.Flags)
	return ruleHit("file.destructive_open_flags", "filesystem", models.DivergenceSeverityKillCandidate, fmt.Sprintf("write-intent open path=%s carried destructive flags=%s", path, flags), event.Seq, map[string]string{"path": path, "flags": flags}), true
}

func (e *Evaluator) ruleWorkspaceScanBeforeTarget(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventFileOpen || e.state.File.DeclaredTargetTouched || models.FileOpenHasWriteIntent(event.Flags) {
		return models.DivergenceRuleHit{}, false
	}
	threshold := workspaceScanFloor
	if e.intent.ResourceScope.MaxDistinctFiles < threshold {
		threshold = e.intent.ResourceScope.MaxDistinctFiles
	}
	if threshold < 2 {
		threshold = 2
	}
	if len(e.state.File.WorkspaceDistinctPaths) < threshold {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("file.workspace_scan_before_target", "filesystem", models.DivergenceSeverityWarn, fmt.Sprintf("workspace_distinct_paths=%d reached scan threshold=%d before declared target touch under read-oriented file semantics", len(e.state.File.WorkspaceDistinctPaths), threshold), event.Seq, map[string]string{"workspace_distinct_paths": strconv.Itoa(len(e.state.File.WorkspaceDistinctPaths)), "threshold": strconv.Itoa(threshold), "mode": "read-only"}), true
}

func (e *Evaluator) ruleNetworkDisabledConnect(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventNetConnect || e.intent.NetworkScope.AllowNetwork {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("network.connect_disabled", "network", models.DivergenceSeverityKillCandidate, fmt.Sprintf("connect destination=%s attempted while allow_network=false", connectDestination(event)), event.Seq, map[string]string{"destination": connectDestination(event), "point_decision": pointDecisionValue(decision)}), true
}

func (e *Evaluator) ruleRepeatedDeniedConnect(event models.RuntimeEvent, decision *models.PolicyPointDecision) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventNetConnect || decision == nil || decision.Decision != models.DecisionDeny {
		return models.DivergenceRuleHit{}, false
	}
	if e.state.Network.DeniedConnectCount < repeatedDeniedConnectThreshold {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("network.denied_repeated", "network", models.DivergenceSeverityKillCandidate, fmt.Sprintf("denied_connect_count=%d reached probing threshold=%d", e.state.Network.DeniedConnectCount, repeatedDeniedConnectThreshold), event.Seq, map[string]string{"denied_connect_count": strconv.Itoa(e.state.Network.DeniedConnectCount), "threshold": strconv.Itoa(repeatedDeniedConnectThreshold)}), true
}

func (e *Evaluator) ruleConnectFanoutExceeded(event models.RuntimeEvent) (models.DivergenceRuleHit, bool) {
	if event.Type != models.EventNetConnect {
		return models.DivergenceRuleHit{}, false
	}
	budget := e.intent.NetworkScope.MaxOutboundConns
	if budget < 0 {
		budget = 0
	}
	if len(e.state.Network.DistinctDestinations) <= budget {
		return models.DivergenceRuleHit{}, false
	}
	return ruleHit("network.connect_fanout_exceeded", "network", models.DivergenceSeverityKillCandidate, fmt.Sprintf("distinct_destinations=%d exceeded max_outbound_conns=%d", len(e.state.Network.DistinctDestinations), budget), event.Seq, map[string]string{"distinct_destinations": strconv.Itoa(len(e.state.Network.DistinctDestinations)), "max_outbound_conns": strconv.Itoa(budget)}), true
}

func execBudget(intent contract.IntentContract) int {
	budget := len(intent.ProcessScope.AllowedBinaries) + intent.ProcessScope.MaxChildProcesses + execBudgetSlack
	if budget < 4 {
		return 4
	}
	return budget
}

func ruleHit(ruleID string, category string, severity models.DivergenceSeverity, message string, seq uint64, metadata map[string]string) models.DivergenceRuleHit {
	return models.DivergenceRuleHit{
		RuleID:   ruleID,
		Category: category,
		Severity: severity,
		Message:  message,
		EventSeq: seq,
		Metadata: metadata,
	}
}

func pointDecisionValue(decision *models.PolicyPointDecision) string {
	if decision == nil {
		return string(models.DecisionNotApplicable)
	}
	return string(decision.Decision)
}

// ObserveBrokerDenial records a broker credential denial and evaluates divergence rules.
// This is called from the broker listener when a request is denied by policy.
func (e *Evaluator) ObserveBrokerDenial(domain, bindingOrReason, ruleID string) ObserveOutcome {
	previous := e.state.Verdict
	e.state.Broker.RequestCount++
	e.state.Broker.DeniedCount++
	if domain != "" {
		e.state.Broker.DeniedDomains[domain]++
	}
	if bindingOrReason != "" {
		e.state.Broker.DeniedBindings[bindingOrReason]++
	}

	var hits []models.DivergenceRuleHit
	if hit, ok := e.ruleBrokerDenied(domain, ruleID); ok {
		if e.state.addRuleHit(hit) {
			hits = append(hits, hit)
		}
	}
	result := e.state.result(e.intent)
	return ObserveOutcome{
		Result:         result,
		NewRuleHits:    hits,
		VerdictChanged: previous != result.CurrentVerdict,
	}
}

func (e *Evaluator) ruleBrokerDenied(domain, ruleID string) (models.DivergenceRuleHit, bool) {
	if e.state.Broker.DeniedCount < 1 {
		return models.DivergenceRuleHit{}, false
	}
	severity := models.DivergenceSeverityWarn
	msg := fmt.Sprintf("broker_denied: %d denied broker request(s); first denied domain=%q rule=%q",
		e.state.Broker.DeniedCount, domain, ruleID)
	return ruleHit("broker.request_denied", "broker", severity, msg, 0, map[string]string{
		"denied_count": strconv.Itoa(e.state.Broker.DeniedCount),
		"domain":       domain,
		"rule_id":      ruleID,
	}), true
}

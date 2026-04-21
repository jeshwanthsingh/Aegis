package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"aegis/internal/approval"
	"aegis/internal/escalation"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/models"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

const (
	ActionHTTPRequest     = "http_request"
	ActionDependencyFetch = "dependency_fetch"
	ActionNetworkConnect  = "network_connect"
	ActionHostRepoApply   = "host_repo_apply_patch"
)

type CapabilityPath string

const (
	CapabilityPathBroker       CapabilityPath = "broker"
	CapabilityPathDirectEgress CapabilityPath = "direct_egress"
)

type Request struct {
	ExecutionID string            `json:"execution_id"`
	ActionType  string            `json:"action_type"`
	Method      string            `json:"method,omitempty"`
	Target      string            `json:"target"`
	Resource    string            `json:"resource,omitempty"`
	Brokered    bool              `json:"brokered"`
	Context     map[string]string `json:"context,omitempty"`
}

type Decision struct {
	Allow        bool              `json:"allow"`
	Deny         bool              `json:"deny"`
	Reason       string            `json:"reason,omitempty"`
	RuleID       string            `json:"rule_id,omitempty"`
	PolicyDigest string            `json:"policy_digest,omitempty"`
	AuditPayload map[string]string `json:"audit_payload,omitempty"`
}

type CapabilityUse struct {
	Path                CapabilityPath       `json:"path"`
	Used                bool                 `json:"used"`
	CredentialsInjected bool                 `json:"credentials_injected,omitempty"`
	BindingName         string               `json:"binding_name,omitempty"`
	ResponseDigest      string               `json:"response_digest,omitempty"`
	ResponseDigestAlgo  string               `json:"response_digest_algo,omitempty"`
	DenialMarker        string               `json:"denial_marker,omitempty"`
	Error               string               `json:"error,omitempty"`
	Approval            *approval.Check      `json:"approval,omitempty"`
	Lease               *lease.Check         `json:"lease,omitempty"`
	Escalation          *escalation.Evidence `json:"escalation,omitempty"`
	HostAction          *hostaction.Evidence `json:"host_action,omitempty"`
}

type CapabilityRecord struct {
	Request  Request       `json:"request"`
	Decision Decision      `json:"decision"`
	Use      CapabilityUse `json:"use"`
}

func NormalizeActionType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ActionHTTPRequest:
		return ActionHTTPRequest
	case ActionDependencyFetch:
		return ActionDependencyFetch
	case ActionNetworkConnect:
		return ActionNetworkConnect
	case ActionHostRepoApply:
		return ActionHostRepoApply
	default:
		return ""
	}
}

func IsValidActionType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ActionHTTPRequest, ActionDependencyFetch, ActionNetworkConnect, ActionHostRepoApply:
		return true
	default:
		return false
	}
}

func SanitizeTarget(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func DigestBrokerScope(scope contract.BrokerScope) string {
	payload := struct {
		AllowedDelegations []string `json:"allowed_delegations,omitempty"`
		AllowedDomains     []string `json:"allowed_domains,omitempty"`
		AllowedRepoLabels  []string `json:"allowed_repo_labels,omitempty"`
		AllowedActionTypes []string `json:"allowed_action_types,omitempty"`
		RequireHostConsent bool     `json:"require_host_consent,omitempty"`
	}{
		AllowedDelegations: append([]string(nil), scope.AllowedDelegations...),
		AllowedDomains:     append([]string(nil), scope.AllowedDomains...),
		AllowedRepoLabels:  append([]string(nil), scope.AllowedRepoLabels...),
		AllowedActionTypes: append([]string(nil), scope.AllowedActionTypes...),
		RequireHostConsent: scope.RequireHostConsent,
	}
	return digestJSON(payload)
}

func EffectiveBrokerActionTypes(scope contract.BrokerScope) []string {
	allowedTypes := append([]string(nil), scope.AllowedActionTypes...)
	if len(allowedTypes) == 0 && len(scope.AllowedDomains) > 0 {
		allowedTypes = []string{ActionHTTPRequest}
	}
	if len(allowedTypes) == 0 && len(scope.AllowedRepoLabels) > 0 {
		allowedTypes = []string{ActionHostRepoApply}
	}
	normalized := make([]string, 0, len(allowedTypes))
	seen := map[string]struct{}{}
	for _, candidate := range allowedTypes {
		value := NormalizeActionType(candidate)
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

func DigestIntent(intent contract.IntentContract) string {
	payload := struct {
		Version         string                 `json:"version"`
		ExecutionID     string                 `json:"execution_id"`
		WorkflowID      string                 `json:"workflow_id"`
		TaskClass       string                 `json:"task_class"`
		DeclaredPurpose string                 `json:"declared_purpose"`
		Language        string                 `json:"language"`
		ResourceScope   contract.ResourceScope `json:"resource_scope"`
		NetworkScope    contract.NetworkScope  `json:"network_scope"`
		ProcessScope    contract.ProcessScope  `json:"process_scope"`
		BrokerScope     contract.BrokerScope   `json:"broker_scope"`
		Budgets         contract.BudgetLimits  `json:"budgets"`
		Attributes      map[string]string      `json:"attributes,omitempty"`
	}{
		Version:         intent.Version,
		ExecutionID:     intent.ExecutionID,
		WorkflowID:      intent.WorkflowID,
		TaskClass:       intent.TaskClass,
		DeclaredPurpose: intent.DeclaredPurpose,
		Language:        intent.Language,
		ResourceScope:   intent.ResourceScope,
		NetworkScope:    intent.NetworkScope,
		ProcessScope:    intent.ProcessScope,
		BrokerScope:     intent.BrokerScope,
		Budgets:         intent.Budgets,
		Attributes:      cloneStringMap(intent.Attributes),
	}
	return digestJSON(payload)
}

func DirectConnectTarget(dstIP string, dstPort uint16) string {
	return fmt.Sprintf("tcp://%s:%d", strings.TrimSpace(dstIP), dstPort)
}

func IsLikelyHTTPPort(port uint16) bool {
	switch port {
	case 80, 443, 8080, 8443:
		return true
	default:
		return false
	}
}

func EvaluateBroker(scope contract.BrokerScope, req Request) Decision {
	actionType := NormalizeActionType(req.ActionType)
	if actionType == "" {
		return Decision{
			Deny:   true,
			Reason: fmt.Sprintf("action %q is invalid", strings.TrimSpace(req.ActionType)),
			RuleID: "governance.invalid_action_type",
		}
	}
	policyDigest := DigestBrokerScope(scope)
	resource := strings.ToLower(strings.TrimSpace(req.Resource))
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	decision := Decision{
		Allow:        true,
		Reason:       "governed action allowed by broker scope",
		RuleID:       "governance.allow",
		PolicyDigest: policyDigest,
		AuditPayload: map[string]string{"resource": resource},
	}

	allowedTypes := EffectiveBrokerActionTypes(scope)
	allowedAction := false
	for _, candidate := range allowedTypes {
		if NormalizeActionType(candidate) == actionType {
			allowedAction = true
			break
		}
	}
	if !allowedAction {
		decision.Allow = false
		decision.Deny = true
		decision.RuleID = "governance.action_type_denied"
		decision.Reason = fmt.Sprintf("action %q is not in broker_scope.allowed_action_types", actionType)
		return decision
	}
	if actionType == ActionDependencyFetch && method != "GET" && method != "HEAD" {
		decision.Allow = false
		decision.Deny = true
		decision.RuleID = "governance.dependency_fetch_method_denied"
		decision.Reason = "dependency_fetch requires GET or HEAD"
		return decision
	}
	switch actionType {
	case ActionHostRepoApply:
		decision.AuditPayload = map[string]string{"repo_label": resource}
		if !ResourceLabelAllowed(scope.AllowedRepoLabels, resource) {
			decision.Allow = false
			decision.Deny = true
			decision.RuleID = "broker.repo_label_denied"
			decision.Reason = fmt.Sprintf("repo label %q is not in broker_scope.allowed_repo_labels", resource)
			return decision
		}
	default:
		decision.AuditPayload = map[string]string{"target_domain": resource}
		if !DomainAllowed(scope.AllowedDomains, resource) {
			decision.Allow = false
			decision.Deny = true
			decision.RuleID = "broker.domain_denied"
			decision.Reason = fmt.Sprintf("domain %q is not in broker_scope.allowed_domains", resource)
			return decision
		}
	}
	return decision
}

func EvaluateBrokerCapability(scope contract.BrokerScope, req Request) CapabilityRecord {
	req.ActionType = NormalizeActionType(req.ActionType)
	if req.ActionType == "" {
		req.ActionType = ActionHTTPRequest
	}
	req.Target = SanitizeTarget(req.Target)
	req.Resource = strings.ToLower(strings.TrimSpace(req.Resource))
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Brokered = true
	return CapabilityRecord{
		Request:  req,
		Decision: EvaluateBroker(scope, req),
		Use: CapabilityUse{
			Path: CapabilityPathBroker,
		},
	}
}

func EvaluateDirectEgress(event models.RuntimeEvent, point models.PolicyPointDecision) (Request, Decision, bool) {
	if event.Type != models.EventNetConnect || point.CedarAction != models.ActionConnect || point.Decision != models.DecisionDeny {
		return Request{}, Decision{}, false
	}
	actionType := ActionNetworkConnect
	if IsLikelyHTTPPort(event.DstPort) {
		actionType = ActionHTTPRequest
	}
	target := DirectConnectTarget(event.DstIP, event.DstPort)
	resource := target
	if domain := strings.TrimSpace(event.Domain); domain != "" {
		resource = domain
	}
	request := Request{
		ExecutionID: event.ExecutionID,
		ActionType:  actionType,
		Method:      "CONNECT",
		Target:      target,
		Resource:    resource,
		Brokered:    false,
		Context: map[string]string{
			"dst_ip":   strings.TrimSpace(event.DstIP),
			"dst_port": fmt.Sprintf("%d", event.DstPort),
		},
	}
	if domain := strings.TrimSpace(event.Domain); domain != "" {
		request.Context["domain"] = domain
	}
	decision := Decision{
		Deny:         true,
		Reason:       point.Reason,
		RuleID:       directEgressRuleID(point.Reason),
		PolicyDigest: point.Metadata["policy_digest"],
		AuditPayload: cloneStringMap(request.Context),
	}
	return request, decision, true
}

func EvaluateDirectEgressCapability(event models.RuntimeEvent, point models.PolicyPointDecision) (CapabilityRecord, bool) {
	req, decision, ok := EvaluateDirectEgress(event, point)
	if !ok {
		return CapabilityRecord{}, false
	}
	return CapabilityRecord{
		Request:  req,
		Decision: decision,
		Use: CapabilityUse{
			Path:         CapabilityPathDirectEgress,
			Used:         false,
			DenialMarker: "direct_egress_denied",
		},
	}, true
}

func (record CapabilityRecord) ToGovernedActionData() telemetry.GovernedActionData {
	decision := "allow"
	if record.Decision.Deny || !record.Decision.Allow {
		decision = "deny"
	}
	outcome := "allowed"
	switch {
	case decision == "deny":
		outcome = "denied"
	case strings.TrimSpace(record.Use.Error) != "":
		outcome = "error"
	case record.Use.Used:
		outcome = "completed"
	}
	return telemetry.GovernedActionData{
		ExecutionID:         record.Request.ExecutionID,
		ActionType:          record.Request.ActionType,
		Target:              record.Request.Target,
		Resource:            record.Request.Resource,
		Method:              record.Request.Method,
		Decision:            decision,
		Outcome:             outcome,
		Reason:              record.Decision.Reason,
		RuleID:              record.Decision.RuleID,
		PolicyDigest:        record.Decision.PolicyDigest,
		Brokered:            record.Request.Brokered,
		BrokeredCredentials: record.Use.CredentialsInjected,
		BindingName:         record.Use.BindingName,
		ResponseDigest:      record.Use.ResponseDigest,
		ResponseDigestAlgo:  record.Use.ResponseDigestAlgo,
		DenialMarker:        record.Use.DenialMarker,
		AuditPayload:        cloneStringMap(record.Decision.AuditPayload),
		Error:               record.Use.Error,
		CapabilityPath:      string(record.Use.Path),
		Approval:            cloneApprovalCheck(record.Use.Approval),
		Lease:               cloneLeaseCheck(record.Use.Lease),
		Escalation:          cloneEscalationEvidence(record.Use.Escalation),
		HostAction:          cloneHostActionEvidence(record.Use.HostAction),
		Used:                record.Use.Used,
	}
}

func cloneApprovalCheck(src *approval.Check) *approval.Check {
	if src == nil {
		return nil
	}
	cloned := *src
	return &cloned
}

func cloneLeaseCheck(src *lease.Check) *lease.Check {
	if src == nil {
		return nil
	}
	cloned := *src
	if src.RemainingCount != nil {
		value := *src.RemainingCount
		cloned.RemainingCount = &value
	}
	return &cloned
}

func cloneEscalationEvidence(src *escalation.Evidence) *escalation.Evidence {
	if src == nil {
		return nil
	}
	cloned := &escalation.Evidence{Signals: append([]escalation.Signal(nil), src.Signals...)}
	return cloned
}

func cloneHostActionEvidence(src *hostaction.Evidence) *hostaction.Evidence {
	if src == nil {
		return nil
	}
	cloned := *src
	if src.RepoApplyPatch != nil {
		repoApplyPatch := *src.RepoApplyPatch
		repoApplyPatch.TargetScope = append([]string(nil), src.RepoApplyPatch.TargetScope...)
		repoApplyPatch.AffectedPaths = append([]string(nil), src.RepoApplyPatch.AffectedPaths...)
		cloned.RepoApplyPatch = &repoApplyPatch
	}
	return &cloned
}

func DomainAllowed(allowedDomains []string, domain string) bool {
	if len(allowedDomains) == 0 {
		return false
	}
	normalizedDomain := strings.TrimSpace(strings.ToLower(domain))
	if normalizedDomain == "" {
		return false
	}
	for _, allowed := range allowedDomains {
		allowed = strings.TrimSpace(strings.ToLower(allowed))
		if allowed == "" {
			continue
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:]
			if strings.HasSuffix(normalizedDomain, suffix) {
				return true
			}
			continue
		}
		allowedHost := allowed
		if idx := strings.LastIndex(allowed, ":"); idx >= 0 {
			allowedHost = allowed[:idx]
		}
		if normalizedDomain == allowedHost || normalizedDomain == allowed {
			return true
		}
	}
	return false
}

func ResourceLabelAllowed(allowed []string, label string) bool {
	normalized := strings.TrimSpace(strings.ToLower(label))
	if normalized == "" {
		return false
	}
	for _, candidate := range allowed {
		if strings.TrimSpace(strings.ToLower(candidate)) == normalized {
			return true
		}
	}
	return false
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

func digestJSON(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func directEgressRuleID(reason string) string {
	switch reason {
	case "network access is disabled by intent contract":
		return "governance.direct_egress_disabled"
	case "destination is outside network allowlists", "destination is blocked by runtime network baseline":
		return "governance.direct_egress_target_denied"
	default:
		return "governance.direct_egress_denied"
	}
}

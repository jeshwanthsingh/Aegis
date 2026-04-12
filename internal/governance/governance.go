package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

const (
	ActionHTTPRequest     = "http_request"
	ActionDependencyFetch = "dependency_fetch"
	ActionNetworkConnect  = "network_connect"
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

func NormalizeActionType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ActionHTTPRequest:
		return ActionHTTPRequest
	case ActionDependencyFetch:
		return ActionDependencyFetch
	case ActionNetworkConnect:
		return ActionNetworkConnect
	default:
		return ""
	}
}

func IsValidActionType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ActionHTTPRequest, ActionDependencyFetch, ActionNetworkConnect:
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
		AllowedActionTypes []string `json:"allowed_action_types,omitempty"`
		RequireHostConsent bool     `json:"require_host_consent,omitempty"`
	}{
		AllowedDelegations: append([]string(nil), scope.AllowedDelegations...),
		AllowedDomains:     append([]string(nil), scope.AllowedDomains...),
		AllowedActionTypes: append([]string(nil), scope.AllowedActionTypes...),
		RequireHostConsent: scope.RequireHostConsent,
	}
	return digestJSON(payload)
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
	domain := strings.ToLower(strings.TrimSpace(req.Resource))
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	decision := Decision{
		Allow:        true,
		Reason:       "governed action allowed by broker scope",
		RuleID:       "governance.allow",
		PolicyDigest: policyDigest,
		AuditPayload: map[string]string{"target_domain": domain},
	}

	allowedTypes := append([]string(nil), scope.AllowedActionTypes...)
	if len(allowedTypes) == 0 && len(scope.AllowedDomains) > 0 {
		allowedTypes = []string{ActionHTTPRequest}
	}
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
	if !DomainAllowed(scope.AllowedDomains, domain) {
		decision.Allow = false
		decision.Deny = true
		decision.RuleID = "broker.domain_denied"
		decision.Reason = fmt.Sprintf("domain %q is not in broker_scope.allowed_domains", domain)
		return decision
	}
	return decision
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
	case "destination is outside network allowlists":
		return "governance.direct_egress_target_denied"
	default:
		return "governance.direct_egress_denied"
	}
}

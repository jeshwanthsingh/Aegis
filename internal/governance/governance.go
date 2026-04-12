package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"aegis/internal/policy/contract"
)

const (
	ActionHTTPRequest     = "http_request"
	ActionDependencyFetch = "dependency_fetch"
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
	default:
		return ""
	}
}

func IsValidActionType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ActionHTTPRequest, ActionDependencyFetch:
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

func IsHTTPConnectPort(port uint16) bool {
	return port == 80 || port == 443
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

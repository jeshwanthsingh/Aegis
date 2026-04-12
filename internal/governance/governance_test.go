package governance

import (
	"net/http"
	"testing"

	"aegis/internal/models"
	"aegis/internal/policy/contract"
)

func TestEvaluateBrokerAllowsExplicitDependencyFetch(t *testing.T) {
	decision := EvaluateBroker(contract.BrokerScope{
		AllowedDomains:     []string{"packages.example.com"},
		AllowedActionTypes: []string{ActionDependencyFetch},
	}, Request{
		ExecutionID: "exec",
		ActionType:  ActionDependencyFetch,
		Method:      http.MethodGet,
		Target:      "https://packages.example.com/pkg.whl",
		Resource:    "packages.example.com",
		Brokered:    true,
	})
	if !decision.Allow || decision.Deny {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.RuleID != "governance.allow" {
		t.Fatalf("rule_id = %q", decision.RuleID)
	}
}

func TestEvaluateBrokerDeniesUnapprovedDomain(t *testing.T) {
	decision := EvaluateBroker(contract.BrokerScope{
		AllowedDomains:     []string{"packages.example.com"},
		AllowedActionTypes: []string{ActionHTTPRequest},
	}, Request{
		ExecutionID: "exec",
		ActionType:  ActionHTTPRequest,
		Method:      http.MethodGet,
		Target:      "https://api.example.com/data",
		Resource:    "api.example.com",
		Brokered:    true,
	})
	if !decision.Deny || decision.Allow {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.RuleID != "broker.domain_denied" {
		t.Fatalf("rule_id = %q", decision.RuleID)
	}
}

func TestEvaluateDirectEgressClassifiesNonHTTPConnect(t *testing.T) {
	req, decision, ok := EvaluateDirectEgress(
		models.RuntimeEvent{
			ExecutionID: "exec",
			Type:        models.EventNetConnect,
			DstIP:       "10.0.0.5",
			DstPort:     22,
		},
		models.PolicyPointDecision{
			ExecutionID: "exec",
			EventType:   models.EventNetConnect,
			CedarAction: models.ActionConnect,
			Decision:    models.DecisionDeny,
			Reason:      "network access is disabled by intent contract",
			Metadata:    map[string]string{"policy_digest": "digest"},
		},
	)
	if !ok {
		t.Fatal("expected direct egress decision")
	}
	if req.ActionType != ActionNetworkConnect {
		t.Fatalf("action_type = %q", req.ActionType)
	}
	if !decision.Deny || decision.RuleID != "governance.direct_egress_disabled" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

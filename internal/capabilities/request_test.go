package capabilities

import (
	"encoding/json"
	"testing"
)

func TestCompileDeterministic(t *testing.T) {
	req := Request{
		NetworkDomains: []string{"api.example.com"},
		WritePaths:     []string{"/workspace/out.txt"},
		Broker: &BrokerRequest{
			Delegations:     []Delegation{{Name: "github", Resource: "https://api.github.com/user"}},
			HTTPRequests:    true,
			DependencyFetch: true,
		},
	}
	first, err := Compile("11111111-1111-4111-8111-111111111111", "python", 10, req)
	if err != nil {
		t.Fatalf("Compile(first): %v", err)
	}
	second, err := Compile("11111111-1111-4111-8111-111111111111", "python", 10, req)
	if err != nil {
		t.Fatalf("Compile(second): %v", err)
	}
	if string(first.Raw) != string(second.Raw) {
		t.Fatalf("compiled raw mismatch:\nfirst=%s\nsecond=%s", first.Raw, second.Raw)
	}
	var wire map[string]any
	if err := json.Unmarshal(first.Raw, &wire); err != nil {
		t.Fatalf("Unmarshal(compiled): %v", err)
	}
	brokerScope, ok := wire["broker_scope"].(map[string]any)
	if !ok {
		t.Fatalf("missing broker scope: %#v", wire["broker_scope"])
	}
	allowedActionTypes, ok := brokerScope["allowed_action_types"].([]any)
	if !ok || len(allowedActionTypes) != 2 {
		t.Fatalf("unexpected allowed_action_types: %#v", brokerScope["allowed_action_types"])
	}
}

func TestCompileRejectsMissingDelegationResource(t *testing.T) {
	_, err := Compile("11111111-1111-4111-8111-111111111111", "python", 10, Request{
		Broker: &BrokerRequest{
			Delegations: []Delegation{{Name: "github"}},
		},
	})
	if err == nil {
		t.Fatal("expected missing resource error")
	}
}

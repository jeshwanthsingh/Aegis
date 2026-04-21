package escalation

import (
	"reflect"
	"testing"
)

func TestClassifySingleHTTPDenialsAreNotEscalation(t *testing.T) {
	tracker := NewTracker()
	cases := []Observation{
		{ActionType: "http_request", CapabilityPath: "broker", Decision: "deny", RuleID: "broker.domain_denied", Target: "https://api.example.com/v1", Resource: "api.example.com"},
		{ActionType: "http_request", CapabilityPath: "broker", Decision: "deny", RuleID: "broker.approval_ticket_missing", Target: "https://api.example.com/v1", Resource: "api.example.com"},
		{ActionType: "http_request", CapabilityPath: "direct_egress", Decision: "deny", RuleID: "governance.direct_egress_denied", Target: "api.example.com:443", Resource: "api.example.com"},
	}
	for _, tc := range cases {
		if evidence := tracker.Classify(tc); evidence != nil {
			t.Fatalf("Classify(%+v) = %+v, want nil", tc, evidence)
		}
	}
}

func TestClassifyHostBoundarySignals(t *testing.T) {
	tracker := NewTracker()
	cases := []struct {
		name     string
		input    Observation
		expected []Signal
	}{
		{
			name: "path traversal",
			input: Observation{
				ActionType:     "host_repo_apply_patch",
				CapabilityPath: "broker",
				Decision:       "deny",
				RuleID:         "broker.host_action_path_escape",
				Target:         "repo:demo",
				Resource:       "demo",
			},
			expected: []Signal{SignalDestructiveBoundaryProbe},
		},
		{
			name: "symlink escape",
			input: Observation{
				ActionType:     "host_repo_apply_patch",
				CapabilityPath: "broker",
				Decision:       "deny",
				RuleID:         "broker.host_action_symlink_escape",
				Target:         "repo:demo",
				Resource:       "demo",
			},
			expected: []Signal{SignalDestructiveBoundaryProbe},
		},
		{
			name: "host approval missing",
			input: Observation{
				ActionType:     "host_repo_apply_patch",
				CapabilityPath: "broker",
				Decision:       "deny",
				RuleID:         "broker.approval_ticket_missing",
				Target:         "repo:demo",
				Resource:       "demo",
			},
			expected: []Signal{SignalDestructiveBoundaryProbe},
		},
		{
			name: "unsupported host action",
			input: Observation{
				ActionType:      "host_repo_apply_patch",
				CapabilityPath:  "broker",
				Decision:        "deny",
				RuleID:          "broker.host_action_unsupported",
				HostActionClass: "host_file_delete_v1",
			},
			expected: []Signal{SignalUnsupportedDestructiveClassAccess},
		},
		{
			name: "host lease selector mismatch",
			input: Observation{
				ActionType:     "host_repo_apply_patch",
				CapabilityPath: "broker",
				Decision:       "deny",
				RuleID:         "broker.lease_resource_mismatch",
				Target:         "repo:demo",
				Resource:       "demo",
			},
			expected: []Signal{SignalAuthorityBroadeningAttempt, SignalDestructiveBoundaryProbe},
		},
		{
			name: "disallowed broker class",
			input: Observation{
				ActionType:     "network_connect",
				CapabilityPath: "broker",
				Decision:       "deny",
				RuleID:         "governance.action_type_denied",
				Target:         "api.example.com:443",
				Resource:       "api.example.com",
			},
			expected: []Signal{SignalAuthorityBroadeningAttempt},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := tracker.Classify(tc.input)
			if evidence == nil {
				t.Fatal("Classify(...) = nil")
			}
			if !reflect.DeepEqual(evidence.Signals, tc.expected) {
				t.Fatalf("signals = %v, want %v", evidence.Signals, tc.expected)
			}
		})
	}
}

func TestClassifyHTTPLeaseSelectorMismatchBecomesRepeatedAtThreshold(t *testing.T) {
	tracker := NewTracker()
	first := tracker.Classify(Observation{
		ActionType:     "http_request",
		CapabilityPath: "broker",
		Decision:       "deny",
		RuleID:         "broker.domain_denied",
		Target:         "https://api.example.com/v1",
		Resource:       "api.example.com",
	})
	second := tracker.Classify(Observation{
		ActionType:     "http_request",
		CapabilityPath: "direct_egress",
		Decision:       "deny",
		RuleID:         "governance.direct_egress_denied",
		Target:         "db.example.com:443",
		Resource:       "db.example.com",
	})
	third := tracker.Classify(Observation{
		ActionType:     "http_request",
		CapabilityPath: "broker",
		Decision:       "deny",
		RuleID:         "broker.lease_resource_mismatch",
		Target:         "https://cache.example.com/v1",
		Resource:       "cache.example.com",
	})
	if first != nil || second != nil {
		t.Fatalf("first=%+v second=%+v, want nil", first, second)
	}
	if third == nil || !reflect.DeepEqual(third.Signals, []Signal{SignalRepeatedProbingPattern}) {
		t.Fatalf("third = %+v, want repeated probing only", third)
	}
}

func TestClassifyRepeatedUnsupportedHostClassAddsRepeatedSignalOnThirdAttempt(t *testing.T) {
	tracker := NewTracker()
	input := Observation{
		ActionType:      "host_repo_apply_patch",
		CapabilityPath:  "broker",
		Decision:        "deny",
		RuleID:          "broker.host_action_unsupported",
		HostActionClass: "host_file_delete_v1",
	}
	first := tracker.Classify(input)
	second := tracker.Classify(input)
	third := tracker.Classify(input)
	if first == nil || !reflect.DeepEqual(first.Signals, []Signal{SignalUnsupportedDestructiveClassAccess}) {
		t.Fatalf("first = %+v", first)
	}
	if second == nil || !reflect.DeepEqual(second.Signals, []Signal{SignalUnsupportedDestructiveClassAccess}) {
		t.Fatalf("second = %+v", second)
	}
	if third == nil || !reflect.DeepEqual(third.Signals, []Signal{SignalRepeatedProbingPattern, SignalUnsupportedDestructiveClassAccess}) {
		t.Fatalf("third = %+v", third)
	}
}

package api

import (
	"encoding/json"
	"slices"
	"testing"

	"aegis/internal/authority"
	"aegis/internal/capabilities"
	"aegis/internal/governance"
	"aegis/internal/policy"
)

func TestPreviewAdmissionMatchesFrozenAuthority(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	assetsDir, rootfsPath := makeTestAssets(t)
	intentRaw := json.RawMessage(`{
		"version":"v1",
		"execution_id":"30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b",
		"workflow_id":"wf_demo_preview",
		"task_class":"demo_prepare",
		"declared_purpose":"preview frozen authority for demo issuance",
		"language":"python",
		"resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace"],"deny_paths":[],"max_distinct_files":16},
		"network_scope":{"allow_network":true,"allowed_domains":[],"allowed_ips":["127.0.0.1"],"max_dns_queries":0,"max_outbound_conns":4},
		"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":4},
		"broker_scope":{"allowed_delegations":["demo"],"allowed_domains":["127.0.0.1"],"allowed_repo_labels":["demo"],"allowed_action_types":["http_request","host_repo_apply_patch"],"require_host_consent":true},
		"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}
	}`)

	preview, err := PreviewAdmission(ExecuteRequest{
		Lang:      "python",
		Code:      "print(1)\n",
		TimeoutMs: 1000,
		Profile:   "standard",
		Intent:    intentRaw,
	}, pol, assetsDir, rootfsPath)
	if err != nil {
		t.Fatalf("PreviewAdmission: %v", err)
	}

	expectedReq := ExecuteRequest{
		Lang:      "python",
		Code:      "print(1)\n",
		TimeoutMs: 1000,
		Profile:   "standard",
		Intent:    intentRaw,
	}
	_, intent, err := buildPointEvaluator(&expectedReq, pol.DefaultTimeoutMs)
	if err != nil {
		t.Fatalf("buildPointEvaluator: %v", err)
	}
	effectiveNetwork, err := resolveEffectiveNetworkPolicy(pol.Network, intent)
	if err != nil {
		t.Fatalf("resolveEffectiveNetworkPolicy: %v", err)
	}
	execPolicy := clonePolicyWithNetwork(pol, effectiveNetwork)
	policyEvidence, err := policyEvidenceForExecution(expectedReq, execPolicy, expectedReq.TimeoutMs)
	if err != nil {
		t.Fatalf("policyEvidenceForExecution: %v", err)
	}
	execID, err := chooseExecutionID(requestedExecutionID(expectedReq, intent))
	if err != nil {
		t.Fatalf("chooseExecutionID: %v", err)
	}
	frozen, err := freezeAuthorityForExecution(execID, expectedReq, intent, policyEvidence, execPolicy, assetsDir, rootfsPath)
	if err != nil {
		t.Fatalf("freezeAuthorityForExecution: %v", err)
	}

	if preview.ExecutionID != frozen.ExecutionID {
		t.Fatalf("execution_id = %q, want %q", preview.ExecutionID, frozen.ExecutionID)
	}
	if preview.PolicyDigest != frozen.PolicyDigest {
		t.Fatalf("policy_digest = %q, want %q", preview.PolicyDigest, frozen.PolicyDigest)
	}
	if preview.AuthorityDigest != frozen.AuthorityDigest {
		t.Fatalf("authority_digest = %q, want %q", preview.AuthorityDigest, frozen.AuthorityDigest)
	}
	if preview.ApprovalMode != string(authority.ApprovalModeRequireHostConsent) {
		t.Fatalf("approval_mode = %q", preview.ApprovalMode)
	}
	if !slices.Equal(preview.BrokerActionTypes, frozen.BrokerActionTypes) {
		t.Fatalf("broker_action_types = %v, want %v", preview.BrokerActionTypes, frozen.BrokerActionTypes)
	}
	if !slices.Equal(preview.BrokerRepoLabels, frozen.BrokerRepoLabels) {
		t.Fatalf("broker_repo_labels = %v, want %v", preview.BrokerRepoLabels, frozen.BrokerRepoLabels)
	}
}

func TestPreviewAdmissionCompilesCapabilitiesBrokerHTTP(t *testing.T) {
	t.Parallel()

	pol := policy.Default()
	assetsDir, rootfsPath := makeTestAssets(t)
	preview, err := PreviewAdmission(ExecuteRequest{
		Lang:      "python",
		Code:      "print(1)\n",
		TimeoutMs: 1000,
		Capabilities: &capabilities.Request{
			NetworkDomains: []string{"api.example.com"},
			Broker: &capabilities.BrokerRequest{
				HTTPRequests: true,
			},
		},
	}, pol, assetsDir, rootfsPath)
	if err != nil {
		t.Fatalf("PreviewAdmission(capabilities): %v", err)
	}
	if preview.PolicyDigest == "" || preview.AuthorityDigest == "" {
		t.Fatalf("preview digests should be non-empty: %+v", preview)
	}
	if !slices.Contains(preview.BrokerActionTypes, governance.ActionHTTPRequest) {
		t.Fatalf("broker_action_types = %v", preview.BrokerActionTypes)
	}
}

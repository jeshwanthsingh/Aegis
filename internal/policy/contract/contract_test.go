package contract

import "testing"

func TestLoadIntentContractJSONValid(t *testing.T) {
	intent, err := LoadIntentContractJSON([]byte(validIntentJSON))
	if err != nil {
		t.Fatalf("LoadIntentContractJSON returned error: %v", err)
	}

	if intent.ExecutionID != "exec_123" {
		t.Fatalf("ExecutionID = %q", intent.ExecutionID)
	}
	if got := intent.ResourceScope.ReadPaths[0]; got != "/workspace/report.pdf" {
		t.Fatalf("ReadPaths[0] = %q", got)
	}
	if got := intent.ProcessScope.AllowedBinaries[0]; got != "python3" {
		t.Fatalf("AllowedBinaries[0] = %q", got)
	}
}

func TestLoadIntentContractJSONRejectsUnknownField(t *testing.T) {
	_, err := LoadIntentContractJSON([]byte(`{"version":"v1","execution_id":"exec_123","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":[],"write_paths":[],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024},"unexpected":true}`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadIntentContractJSONRejectsInvalidNetworkIP(t *testing.T) {
	_, err := LoadIntentContractJSON([]byte(`{"version":"v1","execution_id":"exec_123","workflow_id":"wf_1","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":[],"write_paths":[],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":true,"allowed_domains":[],"allowed_ips":["not-an-ip"],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`))
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

const validIntentJSON = `{
  "version": "v1",
  "execution_id": "exec_123",
  "workflow_id": "wf_9",
  "task_class": "summarize_document",
  "declared_purpose": "Summarize report.pdf into summary.md",
  "language": "python",
  "backend_hint": "firecracker",
  "resource_scope": {
    "workspace_root": "/workspace",
    "read_paths": ["/workspace/report.pdf"],
    "write_paths": ["/workspace/summary.md"],
    "deny_paths": ["/workspace/.git"],
    "max_distinct_files": 5
  },
  "network_scope": {
    "allow_network": false,
    "allowed_domains": [],
    "allowed_ips": [],
    "max_dns_queries": 0,
    "max_outbound_conns": 0
  },
  "process_scope": {
    "allowed_binaries": ["python3"],
    "allow_shell": false,
    "allow_package_install": false,
    "max_child_processes": 2
  },
  "broker_scope": {
    "allowed_delegations": [],
    "require_host_consent": false
  },
  "budgets": {
    "timeout_sec": 20,
    "memory_mb": 256,
    "cpu_quota": 100,
    "stdout_bytes": 1048576
  },
  "attributes": {
    "mode": "test"
  }
}`

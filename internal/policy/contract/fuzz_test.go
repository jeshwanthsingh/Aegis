package contract

import "testing"

func FuzzLoadIntentContractJSON(f *testing.F) {
	f.Add([]byte(validIntentJSON))
	f.Add([]byte(`{"version":"v1"}`))
	f.Add([]byte(`{"version":"v1","execution_id":"exec","workflow_id":"wf","task_class":"task","declared_purpose":"purpose","language":"python","resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},"network_scope":{"allow_network":false,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},"broker_scope":{"allowed_delegations":[],"allowed_domains":[],"allowed_action_types":[],"require_host_consent":false},"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadIntentContractJSON(data)
	})
}

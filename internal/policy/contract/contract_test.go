package contract

import (
	"strings"
	"testing"

	policycfg "aegis/internal/policy"
)

const validIntentJSON = `{
	"version":"v1",
	"execution_id":"11111111-1111-4111-8111-111111111111",
	"workflow_id":"wf-1",
	"task_class":"task",
	"declared_purpose":"purpose",
	"language":"python",
	"resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},
	"network_scope":{"allow_network":true,"allowed_domains":["api.github.com"],"allowed_ips":["198.51.100.0/24"],"max_dns_queries":1,"max_outbound_conns":1},
	"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},
	"broker_scope":{"allowed_delegations":[],"require_host_consent":false},
	"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}
}`

func TestResolveEffectiveAllowlist(t *testing.T) {
	t.Parallel()

	baseline := policycfg.NetworkAllowlist{
		FQDNs: []string{"api.github.com", "registry.npmjs.org"},
		CIDRs: []string{"198.51.100.0/24", "203.0.113.5/32"},
	}

	tests := []struct {
		name      string
		scope     NetworkScope
		wantFQDNs []string
		wantCIDRs []string
		wantErr   string
	}{
		{
			name: "equal baseline accepted",
			scope: NetworkScope{
				AllowedDomainsSpecified: true,
				AllowedDomains:          []string{"registry.npmjs.org", "api.github.com"},
				AllowedIPsSpecified:     true,
				AllowedIPs:              []string{"198.51.100.0/24", "203.0.113.5"},
			},
			wantFQDNs: []string{"api.github.com", "registry.npmjs.org"},
			wantCIDRs: []string{"198.51.100.0/24", "203.0.113.5/32"},
		},
		{
			name: "strict subset accepted",
			scope: NetworkScope{
				AllowedDomainsSpecified: true,
				AllowedDomains:          []string{"api.github.com"},
				AllowedIPsSpecified:     true,
				AllowedIPs:              []string{"198.51.100.0/25"},
			},
			wantFQDNs: []string{"api.github.com"},
			wantCIDRs: []string{"198.51.100.0/25"},
		},
		{
			name: "partial allowlist does not inherit omitted dimension",
			scope: NetworkScope{
				AllowedDomainsSpecified: true,
				AllowedDomains:          []string{"api.github.com"},
			},
			wantFQDNs: []string{"api.github.com"},
			wantCIDRs: []string{},
		},
		{
			name: "fqdn not in baseline rejected",
			scope: NetworkScope{
				AllowedDomainsSpecified: true,
				AllowedDomains:          []string{"example.com"},
			},
			wantErr: `network_scope.allowed_domains entry "example.com" is not present in baseline`,
		},
		{
			name: "cidr not contained rejected",
			scope: NetworkScope{
				AllowedIPsSpecified: true,
				AllowedIPs:          []string{"198.51.101.0/24"},
			},
			wantErr: `network_scope.allowed_ips entry "198.51.101.0/24" is not contained within baseline`,
		},
		{
			name: "exact cidr accepted",
			scope: NetworkScope{
				AllowedIPsSpecified: true,
				AllowedIPs:          []string{"198.51.100.0/24"},
			},
			wantCIDRs: []string{"198.51.100.0/24"},
		},
		{
			name:      "no allowlist fields inherits baseline",
			scope:     NetworkScope{},
			wantFQDNs: []string{"api.github.com", "registry.npmjs.org"},
			wantCIDRs: []string{"198.51.100.0/24", "203.0.113.5/32"},
		},
		{
			name: "explicit empty arrays yields empty",
			scope: NetworkScope{
				AllowedDomainsSpecified: true,
				AllowedDomains:          []string{},
				AllowedIPsSpecified:     true,
				AllowedIPs:              []string{},
			},
			wantFQDNs: []string{},
			wantCIDRs: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			effective, err := ResolveEffectiveAllowlist(tc.scope, baseline)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEffectiveAllowlist: %v", err)
			}
			if got := strings.Join(effective.FQDNs, ","); got != strings.Join(tc.wantFQDNs, ",") {
				t.Fatalf("effective fqdns = %q, want %q", got, strings.Join(tc.wantFQDNs, ","))
			}
			if got := strings.Join(effective.CIDRs, ","); got != strings.Join(tc.wantCIDRs, ",") {
				t.Fatalf("effective cidrs = %q, want %q", got, strings.Join(tc.wantCIDRs, ","))
			}
		})
	}
}

func TestLoadIntentContractJSONTracksAllowlistFieldPresence(t *testing.T) {
	t.Parallel()

	withoutFields, err := LoadIntentContractJSON([]byte(`{
		"version":"v1",
		"execution_id":"11111111-1111-4111-8111-111111111111",
		"workflow_id":"wf-1",
		"task_class":"task",
		"declared_purpose":"purpose",
		"language":"python",
		"resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},
		"network_scope":{"allow_network":true,"max_dns_queries":0,"max_outbound_conns":0},
		"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},
		"broker_scope":{"allowed_delegations":[],"require_host_consent":false},
		"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}
	}`))
	if err != nil {
		t.Fatalf("LoadIntentContractJSON(without fields): %v", err)
	}
	if withoutFields.NetworkScope.AllowedDomainsSpecified || withoutFields.NetworkScope.AllowedIPsSpecified {
		t.Fatalf("unexpected field presence flags: %+v", withoutFields.NetworkScope)
	}

	withEmptyFields, err := LoadIntentContractJSON([]byte(`{
		"version":"v1",
		"execution_id":"11111111-1111-4111-8111-111111111111",
		"workflow_id":"wf-1",
		"task_class":"task",
		"declared_purpose":"purpose",
		"language":"python",
		"resource_scope":{"workspace_root":"/workspace","read_paths":["/workspace"],"write_paths":["/workspace/out"],"deny_paths":[],"max_distinct_files":1},
		"network_scope":{"allow_network":true,"allowed_domains":[],"allowed_ips":[],"max_dns_queries":0,"max_outbound_conns":0},
		"process_scope":{"allowed_binaries":["python3"],"allow_shell":false,"allow_package_install":false,"max_child_processes":1},
		"broker_scope":{"allowed_delegations":[],"require_host_consent":false},
		"budgets":{"timeout_sec":10,"memory_mb":128,"cpu_quota":100,"stdout_bytes":1024}
	}`))
	if err != nil {
		t.Fatalf("LoadIntentContractJSON(with empty fields): %v", err)
	}
	if !withEmptyFields.NetworkScope.AllowedDomainsSpecified || !withEmptyFields.NetworkScope.AllowedIPsSpecified {
		t.Fatalf("expected explicit empty fields to be marked present: %+v", withEmptyFields.NetworkScope)
	}
}

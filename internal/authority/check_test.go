package authority

import (
	"testing"

	"aegis/internal/policy"
)

func TestComputeDigestIsStableUnderOrderingNoise(t *testing.T) {
	left := Context{
		ExecutionID:  "exec-1",
		PolicyDigest: "policy-digest",
		ApprovalMode: ApprovalModeNone,
		BrokerActionTypes: []string{
			"http_request",
			"host_repo_apply_patch",
		},
		BrokerAllowedDomains: []string{
			"b.example.com",
			"a.example.com",
		},
		BrokerRepoLabels: []string{
			"demo",
			"alpha",
		},
		Boot: BootContext{
			RootfsImage: "rootfs#abc123",
			Mounts: []MountSpec{
				{Name: "workspace", Kind: MountKindWorkspace, Target: "/workspace", Persistent: true},
				{Name: "rootfs", Kind: MountKindRootfs, Target: "/", ReadOnly: true},
			},
			NetworkMode: policy.NetworkModeEgressAllowlist,
			EgressAllowlist: policy.NetworkAllowlist{
				FQDNs: []string{"b.example.com", "a.example.com"},
				CIDRs: []string{"198.51.100.0/24", "203.0.113.0/24"},
			},
			ResolvedHosts: []ResolvedHost{
				{Host: "b.example.com", IPv4: []string{"198.51.100.2", "198.51.100.1"}},
				{Host: "a.example.com", IPv4: []string{"203.0.113.2", "203.0.113.1"}},
			},
		},
	}
	right := Context{
		ExecutionID:  "exec-1",
		PolicyDigest: "policy-digest",
		ApprovalMode: ApprovalModeNone,
		BrokerActionTypes: []string{
			"host_repo_apply_patch",
			"http_request",
		},
		BrokerAllowedDomains: []string{
			"a.example.com",
			"b.example.com",
		},
		BrokerRepoLabels: []string{
			"alpha",
			"demo",
		},
		Boot: BootContext{
			RootfsImage: "rootfs#abc123",
			Mounts: []MountSpec{
				{Name: "rootfs", Kind: MountKindRootfs, Target: "/", ReadOnly: true},
				{Name: "workspace", Kind: MountKindWorkspace, Target: "/workspace", Persistent: true},
			},
			NetworkMode: policy.NetworkModeEgressAllowlist,
			EgressAllowlist: policy.NetworkAllowlist{
				FQDNs: []string{"a.example.com", "b.example.com"},
				CIDRs: []string{"203.0.113.0/24", "198.51.100.0/24"},
			},
			ResolvedHosts: []ResolvedHost{
				{Host: "a.example.com", IPv4: []string{"203.0.113.1", "203.0.113.2"}},
				{Host: "b.example.com", IPv4: []string{"198.51.100.1", "198.51.100.2"}},
			},
		},
	}

	if ComputeDigest(left) != ComputeDigest(right) {
		t.Fatalf("ComputeDigest should ignore ordering noise")
	}
}

func TestCheckNoGainDetectsPolicyDigestMutation(t *testing.T) {
	frozen := Context{PolicyDigest: "policy-a"}
	observed := Context{PolicyDigest: "policy-b"}
	mutation := CheckNoGain(frozen, observed, "post_vm_acquisition")
	if mutation == nil || mutation.Field != "policy_digest" {
		t.Fatalf("expected policy_digest mutation, got %+v", mutation)
	}
}

func TestComputeDigestChangesWhenBrokerRepoLabelsChange(t *testing.T) {
	left := Context{ExecutionID: "exec-1", PolicyDigest: "policy-digest", BrokerRepoLabels: []string{"demo"}}
	right := Context{ExecutionID: "exec-1", PolicyDigest: "policy-digest", BrokerRepoLabels: []string{"alpha"}}
	if got, want := ComputeDigest(left) == ComputeDigest(right), false; got != want {
		t.Fatalf("ComputeDigest should change when broker repo labels change")
	}
}

func TestCheckNoGainDetectsBrokerActionTypesMutation(t *testing.T) {
	frozen := Context{BrokerActionTypes: []string{"http_request"}}
	observed := Context{BrokerActionTypes: []string{"host_repo_apply_patch", "http_request"}}
	mutation := CheckNoGain(frozen, observed, "post_vm_acquisition")
	if mutation == nil || mutation.Field != "broker_action_types" {
		t.Fatalf("expected broker_action_types mutation, got %+v", mutation)
	}
}

func TestCheckNoGainDetectsBrokerRepoLabelsMutation(t *testing.T) {
	frozen := Context{BrokerRepoLabels: []string{"demo"}}
	observed := Context{BrokerRepoLabels: []string{"alpha", "demo"}}
	mutation := CheckNoGain(frozen, observed, "post_vm_acquisition")
	if mutation == nil || mutation.Field != "broker_repo_labels" {
		t.Fatalf("expected broker_repo_labels mutation, got %+v", mutation)
	}
}

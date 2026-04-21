package authority

import (
	"strings"

	"aegis/internal/policy"
)

func CheckNoGain(frozen Context, observed Context, enforcementPoint string) *MutationAttempt {
	if strings.TrimSpace(frozen.PolicyDigest) != strings.TrimSpace(observed.PolicyDigest) {
		return mutation("policy_digest", frozen.PolicyDigest, observed.PolicyDigest, enforcementPoint)
	}
	if frozen.Boot.RootfsImage != observed.Boot.RootfsImage {
		return mutation("rootfs_image", frozen.Boot.RootfsImage, observed.Boot.RootfsImage, enforcementPoint)
	}
	if mountSetBroadens(frozen.Boot.Mounts, observed.Boot.Mounts) {
		return mutation("mounts", DescribeMounts(frozen.Boot.Mounts), DescribeMounts(observed.Boot.Mounts), enforcementPoint)
	}
	if networkModeBroadens(frozen.Boot.NetworkMode, observed.Boot.NetworkMode) {
		return mutation("network_mode", frozen.Boot.NetworkMode, observed.Boot.NetworkMode, enforcementPoint)
	}
	if allowlistBroadens(frozen.Boot.EgressAllowlist, observed.Boot.EgressAllowlist) {
		return mutation("egress_allowlist", DescribeAllowlist(frozen.Boot.EgressAllowlist), DescribeAllowlist(observed.Boot.EgressAllowlist), enforcementPoint)
	}
	if resolvedHostsBroadens(frozen.Boot.ResolvedHosts, observed.Boot.ResolvedHosts) {
		return mutation("pinned_resolved_hosts", DescribeResolvedHosts(frozen.Boot.ResolvedHosts), DescribeResolvedHosts(observed.Boot.ResolvedHosts), enforcementPoint)
	}
	if domainsBroadens(frozen.BrokerAllowedDomains, observed.BrokerAllowedDomains) {
		return mutation("broker_allowed_domains", DescribeDomains(frozen.BrokerAllowedDomains), DescribeDomains(observed.BrokerAllowedDomains), enforcementPoint)
	}
	if domainsBroadens(frozen.BrokerRepoLabels, observed.BrokerRepoLabels) {
		return mutation("broker_repo_labels", DescribeRepoLabels(frozen.BrokerRepoLabels), DescribeRepoLabels(observed.BrokerRepoLabels), enforcementPoint)
	}
	if domainsBroadens(frozen.BrokerActionTypes, observed.BrokerActionTypes) {
		return mutation("broker_action_types", DescribeActionTypes(frozen.BrokerActionTypes), DescribeActionTypes(observed.BrokerActionTypes), enforcementPoint)
	}
	if approvalModeBroadens(frozen.ApprovalMode, observed.ApprovalMode) {
		return mutation("approval_mode", DescribeApprovalMode(frozen.ApprovalMode), DescribeApprovalMode(observed.ApprovalMode), enforcementPoint)
	}
	return nil
}

func mutation(field string, expected string, observed string, enforcementPoint string) *MutationAttempt {
	return &MutationAttempt{
		Field:            field,
		Expected:         expected,
		Observed:         observed,
		EnforcementPoint: enforcementPoint,
	}
}

func mountSetBroadens(frozen []MountSpec, observed []MountSpec) bool {
	allowed := make(map[string]struct{}, len(frozen))
	for _, mount := range frozen {
		allowed[mountKey(mount)] = struct{}{}
	}
	for _, mount := range observed {
		if _, ok := allowed[mountKey(mount)]; !ok {
			return true
		}
	}
	return false
}

func mountKey(mount MountSpec) string {
	return strings.Join([]string{
		mount.Name,
		string(mount.Kind),
		mount.Target,
		boolString(mount.ReadOnly),
		boolString(mount.Persistent),
	}, "|")
}

func networkModeBroadens(frozen string, observed string) bool {
	return networkRank(observed) > networkRank(frozen)
}

func networkRank(mode string) int {
	switch policy.NormalizeNetworkMode(mode) {
	case policy.NetworkModeNone:
		return 0
	case policy.NetworkModeEgressAllowlist:
		return 1
	default:
		return 2
	}
}

func allowlistBroadens(frozen policy.NetworkAllowlist, observed policy.NetworkAllowlist) bool {
	return domainsBroadens(frozen.FQDNs, observed.FQDNs) || domainsBroadens(frozen.CIDRs, observed.CIDRs)
}

func resolvedHostsBroadens(frozen []ResolvedHost, observed []ResolvedHost) bool {
	allowed := map[string]map[string]struct{}{}
	for _, host := range frozen {
		ipSet := map[string]struct{}{}
		for _, ip := range host.IPv4 {
			ipSet[ip] = struct{}{}
		}
		allowed[host.Host] = ipSet
	}
	for _, host := range observed {
		ipSet, ok := allowed[host.Host]
		if !ok {
			return true
		}
		for _, ip := range host.IPv4 {
			if _, ok := ipSet[ip]; !ok {
				return true
			}
		}
	}
	return false
}

func domainsBroadens(frozen []string, observed []string) bool {
	allowed := map[string]struct{}{}
	for _, value := range frozen {
		allowed[value] = struct{}{}
	}
	for _, value := range observed {
		if _, ok := allowed[value]; !ok {
			return true
		}
	}
	return false
}

func approvalModeBroadens(frozen ApprovalMode, observed ApprovalMode) bool {
	return approvalRank(observed) < approvalRank(frozen)
}

func approvalRank(mode ApprovalMode) int {
	switch normalizeApprovalMode(mode) {
	case ApprovalModeRequireHostConsent:
		return 1
	case ApprovalModeNone:
		return 0
	default:
		return -1
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

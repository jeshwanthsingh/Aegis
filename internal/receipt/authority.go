package receipt

import (
	"sort"
	"strings"

	"aegis/internal/authority"
	"aegis/internal/policy"
)

func AuthorityEnvelopeFromContext(ctx authority.Context, mutation *authority.MutationAttempt) *AuthorityEnvelope {
	ctx = authorityContextForReceipt(ctx)
	envelope := &AuthorityEnvelope{
		Digest:               ctx.AuthorityDigest,
		RootfsImage:          ctx.Boot.RootfsImage,
		Mounts:               make([]AuthorityMountEnvelope, 0, len(ctx.Boot.Mounts)),
		NetworkMode:          policy.NormalizeNetworkMode(ctx.Boot.NetworkMode),
		BrokerAllowedDomains: append([]string(nil), ctx.BrokerAllowedDomains...),
		BrokerRepoLabels:     append([]string(nil), ctx.BrokerRepoLabels...),
		BrokerActionTypes:    append([]string(nil), ctx.BrokerActionTypes...),
		ApprovalMode:         string(ctx.ApprovalMode),
	}
	if envelope.NetworkMode != policy.NetworkModeNone {
		envelope.EgressAllowlist = &NetworkAllowlistEnvelope{
			FQDNs: append([]string(nil), ctx.Boot.EgressAllowlist.FQDNs...),
			CIDRs: append([]string(nil), ctx.Boot.EgressAllowlist.CIDRs...),
		}
	}
	for _, mount := range ctx.Boot.Mounts {
		envelope.Mounts = append(envelope.Mounts, AuthorityMountEnvelope{
			Name:       mount.Name,
			Kind:       string(mount.Kind),
			Target:     mount.Target,
			ReadOnly:   mount.ReadOnly,
			Persistent: mount.Persistent,
		})
	}
	for _, host := range ctx.Boot.ResolvedHosts {
		envelope.ResolvedHosts = append(envelope.ResolvedHosts, AuthorityResolvedHostEnvelope{
			Host: host.Host,
			IPv4: append([]string(nil), host.IPv4...),
		})
	}
	if mutation != nil {
		envelope.MutationAttempt = &AuthorityMutationEnvelope{
			Field:            mutation.Field,
			Expected:         mutation.Expected,
			Observed:         mutation.Observed,
			EnforcementPoint: mutation.EnforcementPoint,
		}
	}
	return envelope
}

func authorityContextForReceipt(ctx authority.Context) authority.Context {
	ctx.Boot.NetworkMode = policy.NormalizeNetworkMode(ctx.Boot.NetworkMode)
	ctx.Boot.EgressAllowlist = policy.CloneAllowlist(ctx.Boot.EgressAllowlist)
	ctx.BrokerAllowedDomains = append([]string(nil), ctx.BrokerAllowedDomains...)
	ctx.BrokerRepoLabels = canonicalRepoLabels(ctx.BrokerRepoLabels)
	ctx.BrokerActionTypes = append([]string(nil), ctx.BrokerActionTypes...)
	sort.Strings(ctx.BrokerAllowedDomains)
	sort.Strings(ctx.BrokerActionTypes)
	ctx.Boot.Mounts = append([]authority.MountSpec(nil), ctx.Boot.Mounts...)
	ctx.Boot.ResolvedHosts = append([]authority.ResolvedHost(nil), ctx.Boot.ResolvedHosts...)
	sort.Slice(ctx.Boot.Mounts, func(i, j int) bool {
		return ctx.Boot.Mounts[i].Target < ctx.Boot.Mounts[j].Target
	})
	for idx := range ctx.Boot.ResolvedHosts {
		ctx.Boot.ResolvedHosts[idx].Host = strings.TrimSpace(strings.ToLower(ctx.Boot.ResolvedHosts[idx].Host))
		ctx.Boot.ResolvedHosts[idx].IPv4 = append([]string(nil), ctx.Boot.ResolvedHosts[idx].IPv4...)
		sort.Strings(ctx.Boot.ResolvedHosts[idx].IPv4)
	}
	sort.Slice(ctx.Boot.ResolvedHosts, func(i, j int) bool {
		return ctx.Boot.ResolvedHosts[i].Host < ctx.Boot.ResolvedHosts[j].Host
	})
	ctx.AuthorityDigest = authority.ComputeDigest(ctx)
	return ctx
}

func authorityContextFromEnvelope(executionID string, policyDigest string, envelope *AuthorityEnvelope) authority.Context {
	if envelope == nil {
		return authority.Context{}
	}
	ctx := authority.Context{
		ExecutionID:          strings.TrimSpace(executionID),
		BrokerAllowedDomains: append([]string(nil), envelope.BrokerAllowedDomains...),
		BrokerRepoLabels:     append([]string(nil), envelope.BrokerRepoLabels...),
		BrokerActionTypes:    append([]string(nil), envelope.BrokerActionTypes...),
		ApprovalMode:         authority.ApprovalMode(strings.TrimSpace(envelope.ApprovalMode)),
		PolicyDigest:         strings.TrimSpace(policyDigest),
		AuthorityDigest:      strings.TrimSpace(envelope.Digest),
		Boot: authority.BootContext{
			RootfsImage:   strings.TrimSpace(envelope.RootfsImage),
			Mounts:        make([]authority.MountSpec, 0, len(envelope.Mounts)),
			NetworkMode:   policy.NormalizeNetworkMode(envelope.NetworkMode),
			ResolvedHosts: make([]authority.ResolvedHost, 0, len(envelope.ResolvedHosts)),
		},
	}
	if envelope.EgressAllowlist != nil {
		ctx.Boot.EgressAllowlist = policy.CloneAllowlist(policy.NetworkAllowlist{
			FQDNs: append([]string(nil), envelope.EgressAllowlist.FQDNs...),
			CIDRs: append([]string(nil), envelope.EgressAllowlist.CIDRs...),
		})
	} else {
		ctx.Boot.EgressAllowlist = policy.NetworkAllowlist{FQDNs: []string{}, CIDRs: []string{}}
	}
	for _, mount := range envelope.Mounts {
		ctx.Boot.Mounts = append(ctx.Boot.Mounts, authority.MountSpec{
			Name:       mount.Name,
			Kind:       authority.MountKind(mount.Kind),
			Target:     mount.Target,
			ReadOnly:   mount.ReadOnly,
			Persistent: mount.Persistent,
		})
	}
	for _, host := range envelope.ResolvedHosts {
		ctx.Boot.ResolvedHosts = append(ctx.Boot.ResolvedHosts, authority.ResolvedHost{
			Host: host.Host,
			IPv4: append([]string(nil), host.IPv4...),
		})
	}
	return authorityContextForReceipt(ctx)
}

func canonicalRepoLabels(values []string) []string {
	seen := map[string]struct{}{}
	canonical := make([]string, 0, len(values))
	for _, value := range values {
		label := strings.ToLower(strings.TrimSpace(value))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		canonical = append(canonical, label)
	}
	sort.Strings(canonical)
	return canonical
}

package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/policy"
)

var lookupHostIPv4 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	if resolver == nil {
		resolver = newUpstreamResolver()
	}
	return resolver.LookupIP(ctx, "ip4", host)
}

func Freeze(input FreezeInput) (Context, error) {
	boot, err := FreezeBoot(input.AssetsDir, input.RootfsPath, input.WorkspaceRequested, input.Network)
	if err != nil {
		return Context{}, err
	}
	ctx := Context{
		ExecutionID:          strings.TrimSpace(input.ExecutionID),
		Boot:                 boot,
		BrokerAllowedDomains: cleanDomains(input.BrokerAllowedDomains),
		BrokerRepoLabels:     cleanRepoLabels(input.BrokerRepoLabels),
		BrokerActionTypes:    cleanActionTypes(input.BrokerActionTypes),
		ApprovalMode:         normalizeApprovalMode(input.ApprovalMode),
		PolicyDigest:         strings.TrimSpace(input.PolicyDigest),
	}
	ctx.AuthorityDigest = ComputeDigest(ctx)
	return ctx, nil
}

func FreezeBoot(assetsDir string, rootfsPath string, workspaceRequested bool, np policy.NetworkPolicy) (BootContext, error) {
	resolvedRootfs, err := ResolveRootfsPath(assetsDir, rootfsPath)
	if err != nil {
		return BootContext{}, err
	}
	normalized := policy.NormalizeNetworkPolicy(np)
	boot := BootContext{
		RootfsPath:      resolvedRootfs,
		RootfsImage:     sanitizeRootfsIdentifier(resolvedRootfs),
		Mounts:          canonicalMounts(workspaceRequested, normalized),
		NetworkMode:     policy.NormalizeNetworkMode(normalized.Mode),
		EgressAllowlist: policy.CloneAllowlist(normalized.Allowlist),
		ResolvedHosts:   []ResolvedHost{},
	}
	if boot.NetworkMode == policy.NetworkModeNone {
		boot.EgressAllowlist = policy.NetworkAllowlist{FQDNs: []string{}, CIDRs: []string{}}
		return boot, nil
	}
	resolvedHosts, err := freezeResolvedHosts(boot.EgressAllowlist.FQDNs)
	if err != nil {
		return BootContext{}, err
	}
	boot.ResolvedHosts = resolvedHosts
	return boot, nil
}

func BootDigest(boot BootContext) string {
	return digestJSON(canonicalizeBoot(boot))
}

func ComputeDigest(ctx Context) string {
	canonical := canonicalizeContext(ctx)
	return digestJSON(struct {
		ExecutionID          string       `json:"execution_id"`
		Boot                 BootContext  `json:"boot"`
		BrokerAllowedDomains []string     `json:"broker_allowed_domains,omitempty"`
		BrokerRepoLabels     []string     `json:"broker_repo_labels,omitempty"`
		BrokerActionTypes    []string     `json:"broker_action_types,omitempty"`
		ApprovalMode         ApprovalMode `json:"approval_mode"`
		PolicyDigest         string       `json:"policy_digest"`
	}{
		ExecutionID:          canonical.ExecutionID,
		Boot:                 canonical.Boot,
		BrokerAllowedDomains: canonical.BrokerAllowedDomains,
		BrokerRepoLabels:     canonical.BrokerRepoLabels,
		BrokerActionTypes:    canonical.BrokerActionTypes,
		ApprovalMode:         canonical.ApprovalMode,
		PolicyDigest:         canonical.PolicyDigest,
	})
}

func ResolveRootfsPath(assetsDir string, explicit string) (string, error) {
	baseDir, err := resolveAssetsDir(assetsDir)
	if err != nil {
		return "", err
	}
	switch {
	case strings.TrimSpace(explicit) != "":
		return statRootfsPath(explicit)
	case strings.TrimSpace(os.Getenv("AEGIS_ROOTFS_PATH")) != "":
		return statRootfsPath(os.Getenv("AEGIS_ROOTFS_PATH"))
	default:
		return statRootfsPath(filepath.Join(baseDir, "alpine-base.ext4"))
	}
}

func canonicalMounts(workspaceRequested bool, np policy.NetworkPolicy) []MountSpec {
	mounts := []MountSpec{{
		Name:     "rootfs",
		Kind:     MountKindRootfs,
		Target:   "/",
		ReadOnly: true,
	}}
	if workspaceRequested {
		mounts = append(mounts, MountSpec{
			Name:       "workspace",
			Kind:       MountKindWorkspace,
			Target:     "/workspace",
			ReadOnly:   false,
			Persistent: true,
		})
	}
	if policy.NormalizeNetworkMode(np.Mode) == policy.NetworkModeEgressAllowlist && len(np.Allowlist.FQDNs) > 0 {
		mounts = append(mounts, MountSpec{
			Name:     "resolv_conf",
			Kind:     MountKindResolvConf,
			Target:   "/etc/resolv.conf",
			ReadOnly: false,
		})
	}
	return mounts
}

func freezeResolvedHosts(hosts []string) ([]ResolvedHost, error) {
	if len(hosts) == 0 {
		return []ResolvedHost{}, nil
	}
	resolver := newUpstreamResolver()
	resolved := make([]ResolvedHost, 0, len(hosts))
	for _, host := range cleanDomains(hosts) {
		ips, err := lookupHostIPv4(context.Background(), resolver, host)
		if err != nil {
			return nil, fmt.Errorf("resolve allowlist host %q: %w", host, err)
		}
		canonical := normalizeIPv4s(ips)
		if len(canonical) == 0 {
			return nil, fmt.Errorf("resolve allowlist host %q: no IPv4 addresses returned", host)
		}
		resolved = append(resolved, ResolvedHost{Host: host, IPv4: canonical})
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Host < resolved[j].Host })
	return resolved, nil
}

func normalizeApprovalMode(mode ApprovalMode) ApprovalMode {
	switch strings.TrimSpace(string(mode)) {
	case "", string(ApprovalModeNone):
		return ApprovalModeNone
	case string(ApprovalModeRequireHostConsent):
		return ApprovalModeRequireHostConsent
	default:
		return ApprovalModeNone
	}
}

func cleanDomains(values []string) []string {
	seen := map[string]struct{}{}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		cleaned = append(cleaned, host)
	}
	sort.Strings(cleaned)
	return cleaned
}

func cleanActionTypes(values []string) []string {
	seen := map[string]struct{}{}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		actionType := strings.TrimSpace(strings.ToLower(value))
		if actionType == "" {
			continue
		}
		if _, ok := seen[actionType]; ok {
			continue
		}
		seen[actionType] = struct{}{}
		cleaned = append(cleaned, actionType)
	}
	sort.Strings(cleaned)
	return cleaned
}

func cleanRepoLabels(values []string) []string {
	seen := map[string]struct{}{}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		label := strings.ToLower(strings.TrimSpace(value))
		if label == "" {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		cleaned = append(cleaned, label)
	}
	sort.Strings(cleaned)
	return cleaned
}

func normalizeIPv4s(values []net.IP) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		ip4 := raw.To4()
		if ip4 == nil {
			continue
		}
		value := ip4.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func digestJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sanitizeRootfsIdentifier(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	base := filepath.Base(cleaned)
	sum := sha256.Sum256([]byte(cleaned))
	return fmt.Sprintf("%s#%s", base, hex.EncodeToString(sum[:8]))
}

func statRootfsPath(path string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if _, err := os.Stat(cleaned); err != nil {
		return "", fmt.Errorf("stat rootfs image %s: %w", cleaned, err)
	}
	return cleaned, nil
}

func resolveAssetsDir(assetsDir string) (string, error) {
	if strings.TrimSpace(assetsDir) != "" {
		return filepath.Clean(assetsDir), nil
	}
	homeDir, err := resolveHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(homeDir, "aegis", "assets"), nil
}

func resolveHomeDir() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

func newUpstreamResolver() *net.Resolver {
	servers := []string{"8.8.8.8", "1.1.1.1"}
	if contents, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		servers = chooseUpstreamNameservers(string(contents))
	}
	var next int
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			server := servers[next%len(servers)]
			next++
			dialNetwork := "udp4"
			if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil && ip.To4() == nil {
				dialNetwork = "udp6"
			}
			d := net.Dialer{}
			return d.DialContext(ctx, dialNetwork, net.JoinHostPort(strings.Trim(server, "[]"), "53"))
		},
	}
}

func chooseUpstreamNameservers(contents string) []string {
	servers := parseNameserverList(contents)
	var nonLoopback []string
	hasSystemdStub := false
	for _, server := range servers {
		if strings.TrimSpace(server) == "127.0.0.53" {
			hasSystemdStub = true
		}
		if isLoopbackNameserver(server) {
			continue
		}
		nonLoopback = append(nonLoopback, server)
	}
	if len(nonLoopback) > 0 {
		return nonLoopback
	}
	if hasSystemdStub {
		return []string{"127.0.0.53"}
	}
	return []string{"8.8.8.8", "1.1.1.1"}
}

func parseNameserverList(contents string) []string {
	var servers []string
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		servers = append(servers, strings.Trim(fields[1], "[]"))
	}
	return servers
}

func isLoopbackNameserver(server string) bool {
	ip := net.ParseIP(strings.Trim(server, "[]"))
	return ip != nil && ip.IsLoopback()
}

func stringify(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(raw)
}

func FlattenResolvedIPs(hosts []ResolvedHost) []string {
	seen := map[string]struct{}{}
	var values []string
	for _, host := range hosts {
		for _, ip := range host.IPv4 {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			values = append(values, ip)
		}
	}
	sort.Strings(values)
	return values
}

func canonicalizeContext(ctx Context) Context {
	canonical := Context{
		ExecutionID:          strings.TrimSpace(ctx.ExecutionID),
		Boot:                 canonicalizeBoot(ctx.Boot),
		BrokerAllowedDomains: cleanDomains(ctx.BrokerAllowedDomains),
		BrokerRepoLabels:     cleanRepoLabels(ctx.BrokerRepoLabels),
		BrokerActionTypes:    cleanActionTypes(ctx.BrokerActionTypes),
		ApprovalMode:         normalizeApprovalMode(ctx.ApprovalMode),
		PolicyDigest:         strings.TrimSpace(ctx.PolicyDigest),
	}
	canonical.AuthorityDigest = strings.TrimSpace(ctx.AuthorityDigest)
	return canonical
}

func canonicalizeBoot(boot BootContext) BootContext {
	canonical := BootContext{
		RootfsPath:      filepath.Clean(strings.TrimSpace(boot.RootfsPath)),
		RootfsImage:     strings.TrimSpace(boot.RootfsImage),
		NetworkMode:     policy.NormalizeNetworkMode(boot.NetworkMode),
		EgressAllowlist: policy.NormalizeNetworkPolicy(policy.NetworkPolicy{Mode: boot.NetworkMode, Allowlist: policy.CloneAllowlist(boot.EgressAllowlist)}).Allowlist,
	}
	canonical.Mounts = append([]MountSpec(nil), boot.Mounts...)
	sort.Slice(canonical.Mounts, func(i, j int) bool {
		return mountSortKey(canonical.Mounts[i]) < mountSortKey(canonical.Mounts[j])
	})
	canonical.ResolvedHosts = make([]ResolvedHost, 0, len(boot.ResolvedHosts))
	for _, host := range boot.ResolvedHosts {
		canonical.ResolvedHosts = append(canonical.ResolvedHosts, ResolvedHost{
			Host: strings.TrimSpace(strings.ToLower(host.Host)),
			IPv4: append([]string(nil), host.IPv4...),
		})
	}
	for idx := range canonical.ResolvedHosts {
		sort.Strings(canonical.ResolvedHosts[idx].IPv4)
	}
	sort.Slice(canonical.ResolvedHosts, func(i, j int) bool {
		return canonical.ResolvedHosts[i].Host < canonical.ResolvedHosts[j].Host
	})
	return canonical
}

func mountSortKey(mount MountSpec) string {
	return strings.Join([]string{
		mount.Name,
		string(mount.Kind),
		mount.Target,
		strconv.FormatBool(mount.ReadOnly),
		strconv.FormatBool(mount.Persistent),
	}, "|")
}

func DescribeResolvedHosts(hosts []ResolvedHost) string {
	return stringify(hosts)
}

func DescribeMounts(mounts []MountSpec) string {
	return stringify(mounts)
}

func DescribeAllowlist(allowlist policy.NetworkAllowlist) string {
	return stringify(policy.CloneAllowlist(allowlist))
}

func DescribeDomains(domains []string) string {
	return stringify(cleanDomains(domains))
}

func DescribeActionTypes(actionTypes []string) string {
	return stringify(cleanActionTypes(actionTypes))
}

func DescribeRepoLabels(labels []string) string {
	return stringify(cleanRepoLabels(labels))
}

func DescribeApprovalMode(mode ApprovalMode) string {
	return strconv.Quote(string(normalizeApprovalMode(mode)))
}

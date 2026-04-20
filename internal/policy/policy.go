package policy

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	NetworkModeNone             = "none"
	NetworkModeLegacyIsolated   = "isolated"
	NetworkModeDirectWebEgress  = "direct_web_egress"
	NetworkModeAllowlist        = "allowlist"
	NetworkModeEgressAllowlist  = "egress_allowlist"
)

var NetworkPresets = map[string][]string{
	"pypi": {
		"pypi.org",
		"files.pythonhosted.org",
		"pypi.python.org",
	},
	"npm": {
		"registry.npmjs.org",
		"npmjs.com",
	},
	"huggingface": {
		"huggingface.co",
		"cdn-lfs.huggingface.co",
	},
	"docker": {
		"registry-1.docker.io",
		"auth.docker.io",
		"production.cloudflare.docker.com",
	},
}

type Policy struct {
	AllowedLanguages []string                  `yaml:"allowed_languages"`
	MaxCodeBytes     int                       `yaml:"max_code_bytes"`
	MaxOutputBytes   int                       `yaml:"max_output_bytes"`
	DefaultTimeoutMs int                       `yaml:"default_timeout_ms"`
	MaxTimeoutMs     int                       `yaml:"max_timeout_ms"`
	Profiles         map[string]ComputeProfile `yaml:"profiles"`
	DefaultProfile   string                    `yaml:"default_profile"`
	Network          NetworkPolicy             `yaml:"network"`
	Resources        ResourcePolicy            `yaml:"resources"`
}

type ComputeProfile struct {
	VCPUCount int `yaml:"vcpu_count"`
	MemoryMB  int `yaml:"memory_mb"`
}

type NetworkPolicy struct {
	Mode      string           `yaml:"mode"`
	Presets   []string         `yaml:"presets"`
	Allowlist NetworkAllowlist `yaml:"allowlist"`
}

type NetworkAllowlist struct {
	FQDNs []string `yaml:"fqdns"`
	CIDRs []string `yaml:"cidrs"`
}

type ResourcePolicy struct {
	MemoryMaxMB int `yaml:"memory_max_mb"`
	CPUPercent  int `yaml:"cpu_percent"`
	PidsMax     int `yaml:"pids_max"`
	TimeoutMs   int `yaml:"timeout_ms"`
}

var (
	deprecatedNetworkModeWarningMu     sync.Mutex
	deprecatedNetworkModeWarningWriter io.Writer = os.Stderr
	deprecatedNetworkModeLogger                  = log.New(deprecatedNetworkModeWarningWriter, "", 0)
)

func NormalizeNetworkMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", NetworkModeNone:
		return NetworkModeNone
	case NetworkModeLegacyIsolated, NetworkModeDirectWebEgress, NetworkModeAllowlist, NetworkModeEgressAllowlist:
		return NetworkModeEgressAllowlist
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func DeprecatedNetworkMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case NetworkModeLegacyIsolated:
		return NetworkModeLegacyIsolated
	case NetworkModeDirectWebEgress:
		return NetworkModeDirectWebEgress
	case NetworkModeAllowlist:
		return NetworkModeAllowlist
	default:
		return ""
	}
}

func Default() *Policy {
	return &Policy{
		AllowedLanguages: []string{"python", "bash", "node"},
		MaxCodeBytes:     65536,
		MaxOutputBytes:   65536,
		DefaultTimeoutMs: 5000,
		MaxTimeoutMs:     10000,
		Profiles: map[string]ComputeProfile{
			"nano": {
				VCPUCount: 1,
				MemoryMB:  128,
			},
			"standard": {
				VCPUCount: 2,
				MemoryMB:  512,
			},
			"crunch": {
				VCPUCount: 4,
				MemoryMB:  2048,
			},
		},
		DefaultProfile: "nano",
		Network: NetworkPolicy{
			Mode:    NetworkModeNone,
			Presets: []string{},
			Allowlist: NetworkAllowlist{
				FQDNs: []string{},
				CIDRs: []string{},
			},
		},
		Resources: ResourcePolicy{
			MemoryMaxMB: 128,
			CPUPercent:  50,
			PidsMax:     100,
			TimeoutMs:   5000,
		},
	}
}

func Load(path string) (*Policy, error) {
	if path == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	p := Default()
	if err := yaml.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}
	if deprecated := DeprecatedNetworkMode(p.Network.Mode); deprecated != "" {
		emitDeprecatedNetworkModeWarning(deprecated)
	}
	p.Network = NormalizeNetworkPolicy(p.Network)
	return p, nil
}

func (p *Policy) Validate(lang string, codeLen int, timeoutMs int) error {
	if !slices.Contains(p.AllowedLanguages, lang) {
		return fmt.Errorf("language not allowed: %s", lang)
	}
	if codeLen > p.MaxCodeBytes {
		return fmt.Errorf("code exceeds %d bytes", p.MaxCodeBytes)
	}
	if timeoutMs < 0 {
		return fmt.Errorf("timeout_ms must be greater than 0")
	}
	if timeoutMs > p.MaxTimeoutMs {
		return fmt.Errorf("timeout_ms exceeds maximum of %d", p.MaxTimeoutMs)
	}
	p.Network = NormalizeNetworkPolicy(p.Network)
	switch p.Network.Mode {
	case NetworkModeNone, NetworkModeEgressAllowlist:
	default:
		return fmt.Errorf("network.mode not allowed: %s", p.Network.Mode)
	}
	if p.Network.Mode == NetworkModeNone {
		if len(p.Network.Allowlist.FQDNs) > 0 || len(p.Network.Allowlist.CIDRs) > 0 {
			return fmt.Errorf("network.allowlist requires egress_allowlist mode")
		}
		return nil
	}
	fqdns, err := normalizeAllowlistFQDNs(p.Network.Allowlist.FQDNs)
	if err != nil {
		return err
	}
	cidrs, err := normalizePolicyCIDRs(p.Network.Allowlist.CIDRs)
	if err != nil {
		return err
	}
	p.Network.Allowlist.FQDNs = fqdns
	p.Network.Allowlist.CIDRs = cidrs
	return nil
}

func NormalizeNetworkPolicy(np NetworkPolicy) NetworkPolicy {
	mode := NormalizeNetworkMode(np.Mode)
	normalized := NetworkPolicy{
		Mode:    mode,
		Presets: []string{},
		Allowlist: NetworkAllowlist{
			FQDNs: append([]string(nil), np.Allowlist.FQDNs...),
			CIDRs: append([]string(nil), np.Allowlist.CIDRs...),
		},
	}
	if len(np.Presets) > 0 && mode == NetworkModeEgressAllowlist {
		hosts := expandPresetHosts(np.Presets)
		normalized.Allowlist.FQDNs = append(normalized.Allowlist.FQDNs, hosts...)
	}
	normalized.Allowlist.FQDNs = normalizeAllowlistFQDNsNoErr(normalized.Allowlist.FQDNs)
	normalized.Allowlist.CIDRs = normalizeCIDRsNoErr(normalized.Allowlist.CIDRs)
	return normalized
}

func NetworkPoliciesEqual(a, b NetworkPolicy) bool {
	left := NormalizeNetworkPolicy(a)
	right := NormalizeNetworkPolicy(b)
	return left.Mode == right.Mode &&
		slices.Equal(left.Allowlist.FQDNs, right.Allowlist.FQDNs) &&
		slices.Equal(left.Allowlist.CIDRs, right.Allowlist.CIDRs)
}

func CloneAllowlist(src NetworkAllowlist) NetworkAllowlist {
	return NetworkAllowlist{
		FQDNs: append([]string(nil), src.FQDNs...),
		CIDRs: append([]string(nil), src.CIDRs...),
	}
}

func emitDeprecatedNetworkModeWarning(old string) {
	deprecatedNetworkModeWarningMu.Lock()
	defer deprecatedNetworkModeWarningMu.Unlock()
	deprecatedNetworkModeLogger.SetOutput(deprecatedNetworkModeWarningWriter)
	deprecatedNetworkModeLogger.Printf("WARN: network.mode=%q is deprecated; normalized to %q.\n      Update your policy to use %q explicitly.", old, NetworkModeEgressAllowlist, NetworkModeEgressAllowlist)
}

func expandPresetHosts(presets []string) []string {
	var hosts []string
	for _, preset := range presets {
		entries, ok := NetworkPresets[strings.TrimSpace(preset)]
		if !ok {
			continue
		}
		hosts = append(hosts, entries...)
	}
	return hosts
}

func normalizeAllowlistFQDNs(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		host := strings.ToLower(strings.TrimSpace(raw))
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			continue
		}
		if strings.Contains(host, "*") {
			return nil, fmt.Errorf("network.allowlist.fqdns does not support wildcards: %s", raw)
		}
		if strings.Contains(host, "://") || strings.Contains(host, "/") {
			return nil, fmt.Errorf("network.allowlist.fqdns must contain bare hostnames: %s", raw)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		normalized = append(normalized, host)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeAllowlistFQDNsNoErr(values []string) []string {
	normalized, err := normalizeAllowlistFQDNs(values)
	if err != nil {
		return append([]string(nil), values...)
	}
	return normalized
}

func normalizePolicyCIDRs(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("network.allowlist.cidrs contains invalid CIDR %q", raw)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("network.allowlist.cidrs only supports IPv4 CIDRs: %s", raw)
		}
		canonical := network.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeCIDRsNoErr(values []string) []string {
	normalized, err := normalizePolicyCIDRs(values)
	if err != nil {
		return append([]string(nil), values...)
	}
	return normalized
}

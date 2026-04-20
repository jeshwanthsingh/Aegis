package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()

	if err := Default().Validate("python", 16, -1); err == nil {
		t.Fatal("Validate unexpectedly accepted negative timeout")
	}
}

func TestValidateAllowsDefaultTimeoutSentinel(t *testing.T) {
	t.Parallel()

	if err := Default().Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected default timeout sentinel: %v", err)
	}
}

func TestValidateAllowsEgressAllowlistWithEmptyAllowlist(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeEgressAllowlist

	if err := pol.Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected egress_allowlist with empty allowlist: %v", err)
	}
	if pol.Network.Mode != NetworkModeEgressAllowlist {
		t.Fatalf("network mode = %q, want %q", pol.Network.Mode, NetworkModeEgressAllowlist)
	}
}

func TestValidateAllowsEgressAllowlistWithFQDNs(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeEgressAllowlist
	pol.Network.Allowlist.FQDNs = []string{"Registry.NPMJS.org", "api.github.com"}

	if err := pol.Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected fqdn allowlist: %v", err)
	}
	if got := strings.Join(pol.Network.Allowlist.FQDNs, ","); got != "api.github.com,registry.npmjs.org" {
		t.Fatalf("normalized fqdns = %q", got)
	}
}

func TestValidateAllowsEgressAllowlistWithCIDRs(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeEgressAllowlist
	pol.Network.Allowlist.CIDRs = []string{"198.51.100.0/24", "203.0.113.5/32"}

	if err := pol.Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected cidr allowlist: %v", err)
	}
	if got := strings.Join(pol.Network.Allowlist.CIDRs, ","); got != "198.51.100.0/24,203.0.113.5/32" {
		t.Fatalf("normalized cidrs = %q", got)
	}
}

func TestValidateRejectsMalformedCIDR(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeEgressAllowlist
	pol.Network.Allowlist.CIDRs = []string{"not-a-cidr"}

	err := pol.Validate("python", 16, 0)
	if err == nil {
		t.Fatal("expected malformed cidr validation error")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNormalizesDeprecatedModesAndWarnsOnce(t *testing.T) {
	cases := []struct {
		name           string
		mode           string
		extraNetworkYAML string
		wantFQDNs      []string
	}{
		{name: "isolated", mode: NetworkModeLegacyIsolated},
		{name: "direct_web_egress", mode: NetworkModeDirectWebEgress},
		{name: "allowlist", mode: NetworkModeAllowlist, extraNetworkYAML: "  presets: [pypi]\n", wantFQDNs: []string{"files.pythonhosted.org", "pypi.org", "pypi.python.org"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var warning bytes.Buffer
			oldWriter := deprecatedNetworkModeWarningWriter
			deprecatedNetworkModeWarningWriter = &warning
			t.Cleanup(func() {
				deprecatedNetworkModeWarningWriter = oldWriter
			})

			path := filepath.Join(t.TempDir(), "policy.yaml")
			contents := "allowed_languages: [python]\n" +
				"max_code_bytes: 65536\n" +
				"max_output_bytes: 65536\n" +
				"default_timeout_ms: 10000\n" +
				"max_timeout_ms: 10000\n" +
				"network:\n" +
				"  mode: " + tc.mode + "\n" +
				tc.extraNetworkYAML +
				"resources:\n" +
				"  memory_max_mb: 128\n" +
				"  cpu_percent: 50\n" +
				"  pids_max: 100\n" +
				"  timeout_ms: 10000\n"
			if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
				t.Fatalf("WriteFile(policy): %v", err)
			}

			pol, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if pol.Network.Mode != NetworkModeEgressAllowlist {
				t.Fatalf("network mode = %q, want %q", pol.Network.Mode, NetworkModeEgressAllowlist)
			}
			if got := warning.String(); strings.Count(got, "WARN:") != 1 {
				t.Fatalf("warning count = %d, want 1: %q", strings.Count(got, "WARN:"), got)
			}
			if !strings.Contains(warning.String(), `network.mode="`+tc.mode+`" is deprecated; normalized to "egress_allowlist"`) {
				t.Fatalf("unexpected warning: %q", warning.String())
			}
			if got := strings.Join(pol.Network.Allowlist.FQDNs, ","); got != strings.Join(tc.wantFQDNs, ",") {
				t.Fatalf("allowlist fqdns = %q, want %q", got, strings.Join(tc.wantFQDNs, ","))
			}
		})
	}
}

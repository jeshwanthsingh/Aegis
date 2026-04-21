package authority

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"aegis/internal/policy"
)

func TestFreezeResolvesRootfsOnce(t *testing.T) {
	assetsDir := t.TempDir()
	rootfsOne := filepath.Join(assetsDir, "one.ext4")
	rootfsTwo := filepath.Join(assetsDir, "two.ext4")
	for _, path := range []string{rootfsOne, rootfsTwo} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", path, err)
		}
	}

	t.Setenv("AEGIS_ROOTFS_PATH", rootfsOne)
	frozen, err := Freeze(FreezeInput{
		ExecutionID:  "exec-1",
		AssetsDir:    assetsDir,
		Network:      policy.NetworkPolicy{Mode: policy.NetworkModeNone},
		PolicyDigest: "policy-digest",
	})
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	t.Setenv("AEGIS_ROOTFS_PATH", rootfsTwo)
	if frozen.Boot.RootfsPath != rootfsOne {
		t.Fatalf("RootfsPath = %q, want %q", frozen.Boot.RootfsPath, rootfsOne)
	}
	if frozen.Boot.RootfsImage == "" {
		t.Fatal("expected sanitized rootfs image identifier")
	}
}

func TestFreezeBootCanonicalMountSetIsStable(t *testing.T) {
	assetsDir := t.TempDir()
	rootfs := filepath.Join(assetsDir, "alpine-base.ext4")
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}
	oldLookup := lookupHostIPv4
	t.Cleanup(func() { lookupHostIPv4 = oldLookup })
	lookupHostIPv4 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}

	boot, err := FreezeBoot(assetsDir, rootfs, true, policy.NetworkPolicy{
		Mode: policy.NetworkModeEgressAllowlist,
		Allowlist: policy.NetworkAllowlist{
			FQDNs: []string{"api.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("FreezeBoot: %v", err)
	}

	want := []MountSpec{
		{Name: "rootfs", Kind: MountKindRootfs, Target: "/", ReadOnly: true},
		{Name: "workspace", Kind: MountKindWorkspace, Target: "/workspace", Persistent: true},
		{Name: "resolv_conf", Kind: MountKindResolvConf, Target: "/etc/resolv.conf"},
	}
	if !reflect.DeepEqual(boot.Mounts, want) {
		t.Fatalf("Mounts = %#v, want %#v", boot.Mounts, want)
	}
}

func TestFreezeBootResolvedHostsAreCanonical(t *testing.T) {
	assetsDir := t.TempDir()
	rootfs := filepath.Join(assetsDir, "alpine-base.ext4")
	if err := os.WriteFile(rootfs, []byte("rootfs"), 0o600); err != nil {
		t.Fatalf("WriteFile(rootfs): %v", err)
	}

	oldLookup := lookupHostIPv4
	t.Cleanup(func() { lookupHostIPv4 = oldLookup })
	lookupHostIPv4 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
		switch host {
		case "a.example.com":
			return []net.IP{net.ParseIP("203.0.113.11"), net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.10")}, nil
		case "b.example.com":
			return []net.IP{net.ParseIP("198.51.100.2"), net.ParseIP("198.51.100.1")}, nil
		default:
			return nil, nil
		}
	}

	boot, err := FreezeBoot(assetsDir, rootfs, false, policy.NetworkPolicy{
		Mode: policy.NetworkModeEgressAllowlist,
		Allowlist: policy.NetworkAllowlist{
			FQDNs: []string{"b.example.com", "a.example.com", "a.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("FreezeBoot: %v", err)
	}

	want := []ResolvedHost{
		{Host: "a.example.com", IPv4: []string{"203.0.113.10", "203.0.113.11"}},
		{Host: "b.example.com", IPv4: []string{"198.51.100.1", "198.51.100.2"}},
	}
	if !reflect.DeepEqual(boot.ResolvedHosts, want) {
		t.Fatalf("ResolvedHosts = %#v, want %#v", boot.ResolvedHosts, want)
	}
}

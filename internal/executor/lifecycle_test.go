package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"aegis/internal/authority"
	"aegis/internal/policy"
	"aegis/internal/telemetry"

	"golang.org/x/net/dns/dnsmessage"
)

var allowlistHookMu sync.Mutex

func TestResolveCgroupLimitsUsesMemoryOverride(t *testing.T) {
	t.Setenv("AEGIS_VM_MEMORY_MB", "768")

	limits := ResolveCgroupLimits(policy.ResourcePolicy{MemoryMaxMB: 640, CPUPercent: 50, PidsMax: 100})
	if limits.MemoryMaxMB != 768 {
		t.Fatalf("MemoryMaxMB = %d, want 768", limits.MemoryMaxMB)
	}
	if limits.MemoryHighMB != 384 {
		t.Fatalf("MemoryHighMB = %d, want 384", limits.MemoryHighMB)
	}
	if limits.PidsMax != 100 || limits.CPUMax != "50000 100000" || limits.SwapMax != "0" {
		t.Fatalf("unexpected cgroup limits: %+v", limits)
	}
	if len(limits.AppliedOverrides) != 1 || limits.AppliedOverrides[0] != "AEGIS_VM_MEMORY_MB" {
		t.Fatalf("unexpected overrides: %+v", limits.AppliedOverrides)
	}
}

func TestBuildDNSResponseAllowedEmitsAllowAndRuleAddEvents(t *testing.T) {
	t.Parallel()

	bus := telemetry.NewBus("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b")
	cfg := testNetworkConfig("tap-test0", "allowed.example")
	cfg.resolvedHostIPs["allowed.example"] = []string{"203.0.113.10"}

	resp, err := buildDNSResponse(cfg, mustDNSQuestion(t, "allowed.example.", dnsmessage.TypeA), bus)
	if err != nil {
		t.Fatalf("buildDNSResponse returned error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty DNS response")
	}

	events := bus.Drain()
	if len(events) != 1 {
		t.Fatalf("unexpected event count: got %d want 1", len(events))
	}

	var dnsData telemetry.DNSQueryData
	if events[0].Kind != telemetry.KindDNSQuery {
		t.Fatalf("unexpected event kind: %s", events[0].Kind)
	}

	if err := json.Unmarshal(events[0].Data, &dnsData); err != nil {
		t.Fatalf("unmarshal dns.query: %v", err)
	}
	if dnsData.Domain != "allowed.example" {
		t.Fatalf("unexpected domain: %q", dnsData.Domain)
	}
	if dnsData.Action != "allow" {
		t.Fatalf("unexpected action: %q", dnsData.Action)
	}
	if len(dnsData.Resolved) != 1 || dnsData.Resolved[0] != "203.0.113.10" {
		t.Fatalf("unexpected resolved IPs: %#v", dnsData.Resolved)
	}
}

func TestBuildDNSResponseDeniedEmitsDenyWithoutRuleAdd(t *testing.T) {
	t.Parallel()

	bus := telemetry.NewBus("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6c")
	cfg := testNetworkConfig("tap-test1")

	resp, err := buildDNSResponse(cfg, mustDNSQuestion(t, "denied.example.", dnsmessage.TypeA), bus)
	if err != nil {
		t.Fatalf("buildDNSResponse returned error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty DNS response")
	}

	events := bus.Drain()
	if len(events) != 1 {
		t.Fatalf("unexpected event count: got %d want 1", len(events))
	}
	if events[0].Kind != telemetry.KindDNSQuery {
		t.Fatalf("unexpected event kind: got %s want %s", events[0].Kind, telemetry.KindDNSQuery)
	}

	var dnsData telemetry.DNSQueryData
	if err := json.Unmarshal(events[0].Data, &dnsData); err != nil {
		t.Fatalf("unmarshal dns.query: %v", err)
	}
	if dnsData.Action != "deny" {
		t.Fatalf("unexpected action: %q", dnsData.Action)
	}
	if dnsData.Reason == "" {
		t.Fatal("expected deny reason")
	}
}

func TestBuildDNSResponseDoesNotAppendAllowedIPsAfterFreeze(t *testing.T) {
	t.Parallel()

	bus := telemetry.NewBus("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6e")
	cfg := testNetworkConfig("tap-test-stable", "allowed.example")
	cfg.resolvedHostIPs["allowed.example"] = []string{"203.0.113.10"}
	cfg.ResolvedIPs = []string{"203.0.113.10"}
	cfg.allowedIPs["203.0.113.10"] = struct{}{}

	if _, err := buildDNSResponse(cfg, mustDNSQuestion(t, "allowed.example.", dnsmessage.TypeA), bus); err != nil {
		t.Fatalf("buildDNSResponse: %v", err)
	}
	if got := cfg.ResolvedIPs; len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("ResolvedIPs mutated: %#v", got)
	}
	for _, event := range bus.Drain() {
		if event.Kind == telemetry.KindNetRuleAdd {
			t.Fatalf("unexpected in-band net.rule.add event after freeze")
		}
	}
}

func TestBuildDNSResponseAllowedWithoutPinnedIPsEmitsError(t *testing.T) {
	t.Parallel()

	bus := telemetry.NewBus("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6d")
	cfg := testNetworkConfig("tap-test2", "allowed.example")

	resp, err := buildDNSResponse(cfg, mustDNSQuestion(t, "allowed.example.", dnsmessage.TypeA), bus)
	if err != nil {
		t.Fatalf("buildDNSResponse returned error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty DNS response")
	}

	events := bus.Drain()
	if len(events) != 1 {
		t.Fatalf("unexpected event count: got %d want 1", len(events))
	}
	if events[0].Kind != telemetry.KindDNSQuery {
		t.Fatalf("unexpected event kind: got %s want %s", events[0].Kind, telemetry.KindDNSQuery)
	}

	var dnsData telemetry.DNSQueryData
	if err := json.Unmarshal(events[0].Data, &dnsData); err != nil {
		t.Fatalf("unmarshal dns.query: %v", err)
	}
	if dnsData.Action != "error" {
		t.Fatalf("unexpected action: %q", dnsData.Action)
	}
	if dnsData.Reason == "" {
		t.Fatal("expected error reason")
	}
}

func TestChooseUpstreamNameserversPrefersNonLoopback(t *testing.T) {
	t.Parallel()

	servers := chooseUpstreamNameservers("nameserver 127.0.0.53\nnameserver 10.0.0.2\n")
	if len(servers) != 1 || servers[0] != "10.0.0.2" {
		t.Fatalf("unexpected upstream servers: %#v", servers)
	}
}

func TestChooseUpstreamNameserversFallsBackToSystemdStub(t *testing.T) {
	t.Parallel()

	servers := chooseUpstreamNameservers("nameserver 127.0.0.53\nnameserver ::1\n")
	if len(servers) != 1 || servers[0] != "127.0.0.53" {
		t.Fatalf("unexpected upstream servers: %#v", servers)
	}
}

func TestNewNetworkConfigNormalizesLegacyIsolatedMode(t *testing.T) {
	t.Parallel()

	cfg := newNetworkConfig("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", authority.BootContext{NetworkMode: policy.NetworkModeLegacyIsolated})
	if cfg.Mode != policy.NetworkModeEgressAllowlist {
		t.Fatalf("cfg.Mode = %q, want %q", cfg.Mode, policy.NetworkModeEgressAllowlist)
	}
}

func TestSetupNetworkProgramsExpectedRules(t *testing.T) {
	allowlistHookMu.Lock()
	defer allowlistHookMu.Unlock()

	oldRunAllow := runAllowlistRuleCmd
	oldRunNetwork := runNetworkCmd
	oldStartDNS := startDNSInterceptorFunc
	defer func() {
		runAllowlistRuleCmd = oldRunAllow
		runNetworkCmd = oldRunNetwork
		startDNSInterceptorFunc = oldStartDNS
	}()

	var commands []string
	record := func(name string, args ...string) error {
		commands = append(commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		return nil
	}
	runAllowlistRuleCmd = record
	runNetworkCmd = record
	dnsStarted := false
	startDNSInterceptorFunc = func(cfg *NetworkConfig, bus *telemetry.Bus) error {
		dnsStarted = true
		return nil
	}

	cfg, err := SetupNetwork("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", authority.BootContext{
		NetworkMode: policy.NetworkModeEgressAllowlist,
		EgressAllowlist: policy.NetworkAllowlist{
			FQDNs: []string{"api.example.com"},
			CIDRs: []string{"198.51.100.0/24"},
		},
		ResolvedHosts: []authority.ResolvedHost{{Host: "api.example.com", IPv4: []string{"203.0.113.10"}}},
	}, telemetry.NewBus("exec-rules"))
	if err != nil {
		t.Fatalf("SetupNetwork: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected network config")
	}
	if !dnsStarted {
		t.Fatal("expected DNS interceptor to start for fqdn allowlist")
	}

	want := []string{
		"ip tuntap add dev tap-30454c31 mode tap",
		"ip addr add " + cfg.HostIP + "/30 dev " + cfg.TapName,
		"ip link set " + cfg.TapName + " up",
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -t nat -A POSTROUTING -s " + cfg.SubnetCIDR + " ! -d " + cfg.SubnetCIDR + " -j MASQUERADE",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p tcp -d 198.51.100.0/24 --dport 80 -j ACCEPT",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p tcp -d 198.51.100.0/24 --dport 443 -j ACCEPT",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p tcp -d 203.0.113.10 --dport 80 -j ACCEPT",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p tcp -d 203.0.113.10 --dport 443 -j ACCEPT",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -d 10.0.0.0/8 -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -d 172.16.0.0/12 -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -d 192.168.0.0/16 -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -d 169.254.169.254 -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p udp --dport 53 -j DROP",
		"iptables -I FORWARD 1 -i " + cfg.TapName + " -p tcp --dport 53 -j DROP",
	}
	if strings.Join(commands, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected command sequence:\n%s", strings.Join(commands, "\n"))
	}

	finalForward := applyInsertOneForwardRules(commands)
	firstAccept := firstIndexContaining(finalForward, "-j ACCEPT")
	lastHardDeny := lastIndexContaining(finalForward, "-d 169.254.169.254 -j DROP")
	if firstAccept == -1 || lastHardDeny == -1 {
		t.Fatalf("unexpected simulated forward chain: %v", finalForward)
	}
	if lastHardDeny > firstAccept {
		t.Fatalf("hard deny rules must precede accept rules in final chain: %v", finalForward)
	}
}

func TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent(t *testing.T) {
	allowlistHookMu.Lock()
	defer allowlistHookMu.Unlock()

	oldRunAllow := runAllowlistRuleCmd
	oldRunNetwork := runNetworkCmd
	oldStartDNS := startDNSInterceptorFunc
	defer func() {
		runAllowlistRuleCmd = oldRunAllow
		runNetworkCmd = oldRunNetwork
		startDNSInterceptorFunc = oldStartDNS
	}()
	runAllowlistRuleCmd = func(name string, args ...string) error { return nil }
	runNetworkCmd = func(name string, args ...string) error { return nil }

	tests := []struct {
		name      string
		allowlist policy.NetworkAllowlist
		wantDNS   bool
	}{
		{name: "fqdn_only", allowlist: policy.NetworkAllowlist{FQDNs: []string{"api.example.com"}}, wantDNS: true},
		{name: "cidr_only", allowlist: policy.NetworkAllowlist{CIDRs: []string{"198.51.100.0/24"}}, wantDNS: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dnsStarted := false
			startDNSInterceptorFunc = func(cfg *NetworkConfig, bus *telemetry.Bus) error {
				dnsStarted = true
				return nil
			}
			boot := authority.BootContext{
				NetworkMode:     policy.NetworkModeEgressAllowlist,
				EgressAllowlist: tc.allowlist,
			}
			if len(tc.allowlist.FQDNs) > 0 {
				boot.ResolvedHosts = []authority.ResolvedHost{{Host: tc.allowlist.FQDNs[0], IPv4: []string{"203.0.113.10"}}}
			}
			_, err := SetupNetwork("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", boot, telemetry.NewBus("exec-dns"))
			if err != nil {
				t.Fatalf("SetupNetwork: %v", err)
			}
			if dnsStarted != tc.wantDNS {
				t.Fatalf("dnsStarted = %t, want %t", dnsStarted, tc.wantDNS)
			}
		})
	}
}

func testNetworkConfig(tapName string, allowedHosts ...string) *NetworkConfig {
	cfg := &NetworkConfig{
		TapName:         tapName,
		Allowlist:       policy.NetworkAllowlist{FQDNs: append([]string(nil), allowedHosts...)},
		allowedHosts:    make(map[string]struct{}, len(allowedHosts)),
		resolvedHostIPs: map[string][]string{},
		allowedIPs:      map[string]struct{}{},
		ResolvedIPs:     []string{},
	}
	for _, host := range allowedHosts {
		cfg.allowedHosts[normalizeHostname(host)] = struct{}{}
	}
	return cfg
}

func TestTeardownIsIdempotent(t *testing.T) {
	t.Setenv("AEGIS_CGROUP_PARENT", t.TempDir())

	root := t.TempDir()
	scratch := filepath.Join(root, "scratch.ext4")
	socket := filepath.Join(root, "fc.sock")
	vsock := filepath.Join(root, "vsock.sock")
	for _, path := range []string{scratch, socket, vsock} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	cgPath := CgroupPath(DefaultCgroupParent(), "exec-idempotent")
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		t.Fatalf("MkdirAll cgroup: %v", err)
	}

	vm := &VMInstance{
		UUID:           "exec-idempotent",
		CgroupID:       "exec-idempotent",
		FirecrackerPID: 999999,
		ScratchPath:    scratch,
		SocketPath:     socket,
		VsockPath:      vsock,
	}

	if err := Teardown(vm, telemetry.NewBus("exec-idempotent")); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := Teardown(vm, telemetry.NewBus("exec-idempotent")); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func mustDNSQuestion(t *testing.T, domain string, qtype dnsmessage.Type) []byte {
	t.Helper()

	name, err := dnsmessage.NewName(domain)
	if err != nil {
		t.Fatalf("dnsmessage.NewName: %v", err)
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	msg, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func applyInsertOneForwardRules(commands []string) []string {
	var chain []string
	for _, command := range commands {
		if !strings.HasPrefix(command, "iptables -I FORWARD 1 ") {
			continue
		}
		rule := strings.TrimPrefix(command, "iptables -I FORWARD 1 ")
		chain = append([]string{rule}, chain...)
	}
	return chain
}

func firstIndexContaining(values []string, needle string) int {
	for idx, value := range values {
		if strings.Contains(value, needle) {
			return idx
		}
	}
	return -1
}

func lastIndexContaining(values []string, needle string) int {
	for idx := len(values) - 1; idx >= 0; idx-- {
		if strings.Contains(values[idx], needle) {
			return idx
		}
	}
	return -1
}

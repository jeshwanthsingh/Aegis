package executor

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"

	"aegis/internal/telemetry"

	"golang.org/x/net/dns/dnsmessage"
)

var allowlistHookMu sync.Mutex

func TestBuildDNSResponseAllowedEmitsAllowAndRuleAddEvents(t *testing.T) {
	t.Parallel()

	restore := stubAllowlistHooks(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	defer restore()

	bus := telemetry.NewBus("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b")
	cfg := testNetworkConfig("tap-test0", "allowed.example")

	resp, err := buildDNSResponse(cfg, mustDNSQuestion(t, "allowed.example.", dnsmessage.TypeA), bus)
	if err != nil {
		t.Fatalf("buildDNSResponse returned error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty DNS response")
	}

	events := bus.Drain()
	if len(events) != 3 {
		t.Fatalf("unexpected event count: got %d want 3", len(events))
	}

	var dnsData telemetry.DNSQueryData
	if events[0].Kind != telemetry.KindNetRuleAdd && events[0].Kind != telemetry.KindDNSQuery {
		t.Fatalf("unexpected first event kind: %s", events[0].Kind)
	}

	var dnsEventFound bool
	var rulePorts []string
	for _, event := range events {
		switch event.Kind {
		case telemetry.KindDNSQuery:
			dnsEventFound = true
			if err := json.Unmarshal(event.Data, &dnsData); err != nil {
				t.Fatalf("unmarshal dns.query: %v", err)
			}
		case telemetry.KindNetRuleAdd:
			var rule telemetry.NetRuleData
			if err := json.Unmarshal(event.Data, &rule); err != nil {
				t.Fatalf("unmarshal net.rule.add: %v", err)
			}
			rulePorts = append(rulePorts, rule.Ports)
			if rule.Rule != "ACCEPT" {
				t.Fatalf("unexpected rule: %q", rule.Rule)
			}
			if rule.Dst != "203.0.113.10" {
				t.Fatalf("unexpected dst: %q", rule.Dst)
			}
		default:
			t.Fatalf("unexpected event kind: %s", event.Kind)
		}
	}

	if !dnsEventFound {
		t.Fatal("expected dns.query event")
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
	if !containsAll(rulePorts, "80", "443") {
		t.Fatalf("expected per-port rule events, got %v", rulePorts)
	}
}

func TestBuildDNSResponseDeniedEmitsDenyWithoutRuleAdd(t *testing.T) {
	t.Parallel()

	restore := stubAllowlistHooks(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	defer restore()

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

func TestBuildDNSResponseAllowedEmitsErrorOnUpstreamFailure(t *testing.T) {
	t.Parallel()

	restore := stubAllowlistHooks(t, nil, context.DeadlineExceeded)
	defer restore()

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

func testNetworkConfig(tapName string, allowedHosts ...string) *NetworkConfig {
	cfg := &NetworkConfig{
		TapName:      tapName,
		allowedHosts: make(map[string]struct{}, len(allowedHosts)),
		allowedIPs:   map[string]struct{}{},
	}
	for _, host := range allowedHosts {
		cfg.allowedHosts[normalizeHostname(host)] = struct{}{}
	}
	return cfg
}

func stubAllowlistHooks(t *testing.T, ips []net.IP, lookupErr error) func() {
	t.Helper()

	allowlistHookMu.Lock()

	oldLookup := lookupAllowlistIPv4
	oldRun := runAllowlistRuleCmd

	lookupAllowlistIPv4 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
		return ips, lookupErr
	}
	runAllowlistRuleCmd = func(name string, args ...string) error {
		return nil
	}

	return func() {
		lookupAllowlistIPv4 = oldLookup
		runAllowlistRuleCmd = oldRun
		allowlistHookMu.Unlock()
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

func containsAll(values []string, want ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, item := range want {
		if _, ok := seen[item]; !ok {
			return false
		}
	}
	return true
}

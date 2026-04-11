package executor

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"aegis/internal/observability"
	"aegis/internal/policy"
	"aegis/internal/telemetry"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

func currentProcessCgroupPath() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" {
			continue
		}
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func isWritableDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	return unix.Access(path, unix.W_OK) == nil
}

func preferredUserCgroupBase() string {
	uid := os.Getuid()
	base := filepath.Join(cgroupRoot, "user.slice", fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid))
	if isWritableDir(base) {
		return base
	}
	return ""
}

func chooseWritableCgroupBase() string {
	if base := preferredUserCgroupBase(); base != "" {
		return base
	}
	if rel := currentProcessCgroupPath(); rel != "" {
		base := filepath.Join(cgroupRoot, strings.TrimPrefix(rel, "/"))
		for dir := base; dir != cgroupRoot && dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
			if isWritableDir(dir) {
				name := filepath.Base(dir)
				if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".scope") {
					continue
				}
				return dir
			}
		}
	}
	return cgroupRoot
}

func DefaultCgroupParent() string {
	if override := strings.TrimSpace(os.Getenv("AEGIS_CGROUP_PARENT")); override != "" {
		return override
	}
	return filepath.Join(chooseWritableCgroupBase(), "aegis")
}

func ValidateCgroupParent(parent string) error {
	parent = strings.TrimSpace(parent)
	if parent == "" {
		return fmt.Errorf("cgroup parent is empty")
	}
	cleanParent := filepath.Clean(parent)
	if !strings.HasPrefix(cleanParent, cgroupRoot) {
		return fmt.Errorf("cgroup parent must live under %s: %s", cgroupRoot, cleanParent)
	}
	parts := []string{}
	for dir := cleanParent; dir != cgroupRoot; dir = filepath.Dir(dir) {
		parts = append(parts, dir)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		dir := parts[i]
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				return fmt.Errorf("create cgroup dir %s: %w", dir, err)
			}
		} else if err != nil {
			return fmt.Errorf("stat cgroup dir %s: %w", dir, err)
		} else if !isWritableDir(dir) {
			continue
		}
		subtreePath := filepath.Join(dir, "cgroup.subtree_control")
		if err := os.WriteFile(subtreePath, []byte("+cpu +memory +pids"), 0o644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("enable controllers in cgroup parent %s: %w", dir, err)
		}
	}
	return nil
}

func CgroupPath(parent string, uuid string) string {
	return filepath.Join(parent, uuid)
}

func resolveCgroupMemoryMaxMB(defaultMB int) int {
	if raw := strings.TrimSpace(os.Getenv("AEGIS_VM_MEMORY_MB")); raw != "" {
		if memoryMB, err := strconv.Atoi(raw); err == nil && memoryMB > 0 {
			return memoryMB
		}
	}
	return defaultMB
}

type NetworkConfig struct {
	TapName      string
	SubnetCIDR   string
	HostIP       string
	GuestIP      string
	GatewayIP    string
	GuestMAC     string
	Mode         string
	Presets      []string
	allowedHosts map[string]struct{}
	allowedIPs   map[string]struct{}
	dnsConn      net.PacketConn
	upstreamDNS  *net.Resolver
	dnsMu        sync.Mutex
}

func SetupCgroup(uuid string, pid int, resources policy.ResourcePolicy, bus *telemetry.Bus) error {
	parent := DefaultCgroupParent()
	if err := ValidateCgroupParent(parent); err != nil {
		return err
	}

	cgPath := CgroupPath(parent, uuid)
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		return fmt.Errorf("create cgroup dir: %w", err)
	}

	memoryMaxMB := resolveCgroupMemoryMaxMB(resources.MemoryMaxMB)
	if memoryMaxMB != resources.MemoryMaxMB {
		observability.Info("cgroup_memory_override", observability.Fields{"execution_id": uuid, "policy_memory_mb": resources.MemoryMaxMB, "effective_memory_mb": memoryMaxMB})
	}

	limits := []struct {
		file  string
		value string
	}{
		{"memory.max", fmt.Sprintf("%dM", memoryMaxMB)},
		{"memory.high", fmt.Sprintf("%dM", memoryMaxMB/2)},
		{"pids.max", strconv.Itoa(resources.PidsMax)},
		{"cpu.max", fmt.Sprintf("%d 100000", resources.CPUPercent*1000)},
		{"memory.swap.max", "0"},
	}
	for _, w := range limits {
		path := filepath.Join(cgPath, w.file)
		if err := os.WriteFile(path, []byte(w.value), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", w.file, err)
		}
	}

	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write cgroup.procs: %w", err)
	}
	emitIfBus(bus, telemetry.KindCgroupConfigured, telemetry.CgroupConfiguredData{
		MemoryMax:  limits[0].value,
		MemoryHigh: limits[1].value,
		PidsMax:    limits[2].value,
		CpuMax:     limits[3].value,
		SwapMax:    limits[4].value,
	})
	return nil
}

func CreateScratchDisk(uuid string) (string, error) {
	path := fmt.Sprintf("/tmp/aegis/scratch-%s.ext4", uuid)
	if err := createExt4Disk(path, 50); err != nil {
		return "", err
	}
	return path, nil
}

func SetupNetwork(execID string, np policy.NetworkPolicy, bus *telemetry.Bus) (*NetworkConfig, error) {
	mode := np.Mode
	if mode == "" || mode == "none" {
		return nil, nil
	}

	cfg := newNetworkConfig(execID, np)
	cleanup := true
	defer func() {
		if cleanup {
			_ = teardownNetwork(cfg)
		}
	}()

	if err := runCmd("ip", "tuntap", "add", "dev", cfg.TapName, "mode", "tap"); err != nil {
		return nil, err
	}
	if err := runCmd("ip", "addr", "add", cfg.HostIP+"/30", "dev", cfg.TapName); err != nil {
		return nil, err
	}
	if err := runCmd("ip", "link", "set", cfg.TapName, "up"); err != nil {
		return nil, err
	}
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return nil, err
	}
	if err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.SubnetCIDR, "!", "-d", cfg.SubnetCIDR, "-j", "MASQUERADE"); err != nil {
		return nil, err
	}
	if err := runCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-j", "DROP"); err != nil {
		return nil, err
	}
	emitIfBus(bus, telemetry.KindNetRuleDrop, telemetry.NetRuleData{
		Rule:      "DROP",
		Chain:     "FORWARD",
		Direction: "outbound",
	})

	if mode == "allowlist" {
		hosts, err := resolvePresetHosts(np.Presets)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			cfg.allowedHosts[normalizeHostname(host)] = struct{}{}
		}
		if err := startDNSInterceptor(cfg, bus); err != nil {
			return nil, err
		}
	} else {
		for _, port := range []string{"80", "443"} {
			if err := runCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-p", "tcp", "--dport", port, "-j", "ACCEPT"); err != nil {
				return nil, err
			}
		}
		emitIfBus(bus, telemetry.KindNetRuleAdd, telemetry.NetRuleData{
			Rule:  "ACCEPT",
			Ports: "80,443",
		})
	}

	for _, rule := range forwardRules(cfg, false) {
		if err := runCmd("iptables", rule...); err != nil {
			return nil, err
		}
	}

	cleanup = false
	return cfg, nil
}

func Teardown(vm *VMInstance, bus *telemetry.Bus) error {
	var errs []error
	emitIfBus(bus, telemetry.KindCleanupStart, map[string]string{})
	cleanup := telemetry.CleanupDoneData{}
	fcSocketRemoved := false
	vsockSocketRemoved := false

	if err := vm.Kill(); err != nil {
		observability.Error("teardown_kill_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
		errs = append(errs, err)
	} else {
		observability.Info("teardown_firecracker_killed", observability.Fields{"execution_id": vm.UUID, "pid": vm.FirecrackerPID})
	}

	if vm.Network != nil {
		if err := teardownNetwork(vm.Network); err != nil {
			observability.Error("teardown_network_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
			errs = append(errs, err)
		} else {
			observability.Info("teardown_tap_removed", observability.Fields{"execution_id": vm.UUID, "tap_name": vm.Network.TapName})
			cleanup.TapRemoved = true
		}
	} else {
		cleanup.TapRemoved = true
	}

	if vm.IsPersistent {
		observability.Info("teardown_workspace_preserved", observability.Fields{"execution_id": vm.UUID, "scratch_path": vm.ScratchPath})
		cleanup.ScratchRemoved = true
	} else if err := os.Remove(vm.ScratchPath); err != nil && !os.IsNotExist(err) {
		observability.Error("teardown_scratch_remove_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
		errs = append(errs, err)
	} else {
		observability.Info("teardown_scratch_removed", observability.Fields{"execution_id": vm.UUID})
		cleanup.ScratchRemoved = true
	}

	if err := os.Remove(vm.SocketPath); err != nil && !os.IsNotExist(err) {
		observability.Error("teardown_fc_socket_remove_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
		errs = append(errs, err)
	} else {
		observability.Info("teardown_fc_socket_removed", observability.Fields{"execution_id": vm.UUID})
		fcSocketRemoved = true
	}

	if err := os.Remove(vm.VsockPath); err != nil && !os.IsNotExist(err) {
		observability.Error("teardown_vsock_socket_remove_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
		errs = append(errs, err)
	} else {
		observability.Info("teardown_vsock_socket_removed", observability.Fields{"execution_id": vm.UUID})
		vsockSocketRemoved = true
	}
	cleanup.SocketRemoved = fcSocketRemoved && vsockSocketRemoved

	parent := DefaultCgroupParent()
	cgroupID := vm.CgroupID
	if strings.TrimSpace(cgroupID) == "" {
		cgroupID = vm.UUID
	}
	cgPath := CgroupPath(parent, cgroupID)
	cgRemoved := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := os.Remove(cgPath); err == nil || os.IsNotExist(err) {
			observability.Info("teardown_cgroup_removed", observability.Fields{"execution_id": vm.UUID})
			cgRemoved = true
			cleanup.CgroupRemoved = true
			break
		}
	}
	if !cgRemoved {
		err := fmt.Errorf("cgroup dir still busy after retries: %s", cgPath)
		observability.Error("teardown_cgroup_remove_failed", observability.Fields{"execution_id": vm.UUID, "error": err.Error()})
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		cleanup.AllClean = cleanup.TapRemoved && cleanup.CgroupRemoved && cleanup.ScratchRemoved && cleanup.SocketRemoved
		vm.Cleanup = cleanup
		emitIfBus(bus, telemetry.KindCleanupDone, cleanup)
		return fmt.Errorf("teardown had %d error(s), first: %w", len(errs), errs[0])
	}
	cleanup.AllClean = cleanup.TapRemoved && cleanup.CgroupRemoved && cleanup.ScratchRemoved && cleanup.SocketRemoved
	vm.Cleanup = cleanup
	emitIfBus(bus, telemetry.KindCleanupDone, cleanup)
	return nil
}

func CleanupLeakedNetworks() error {
	out, err := exec.Command("ip", "-o", "link", "show").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link show: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(name, "tap-") {
			continue
		}
		id := strings.TrimPrefix(name, "tap-")
		cfg := newNetworkConfig(id, policy.NetworkPolicy{})
		cfg.TapName = name
		if err := teardownNetwork(cfg); err != nil {
			observability.Warn("reconcile_network_cleanup_failed", observability.Fields{"tap_name": name, "error": err.Error()})
		} else {
			observability.Info("reconcile_network_removed", observability.Fields{"tap_name": name})
		}
	}
	return nil
}

func teardownNetwork(cfg *NetworkConfig) error {
	var errs []error

	if err := runCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-j", "DROP"); err != nil && !isMissingRule(err) {
		errs = append(errs, err)
	}

	for _, rule := range forwardRules(cfg, true) {
		if err := runCmd("iptables", rule...); err != nil && !isMissingRule(err) {
			errs = append(errs, err)
		}
	}

	if cfg.Mode == "allowlist" {
		if cfg.dnsConn != nil {
			if err := cfg.dnsConn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		for _, ip := range snapshotAllowedIPs(cfg) {
			for _, port := range []string{"80", "443"} {
				if err := runCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-p", "tcp", "-d", ip, "--dport", port, "-j", "ACCEPT"); err != nil && !isMissingRule(err) {
					errs = append(errs, err)
				}
			}
		}
	} else if cfg.Mode == "isolated" {
		for _, port := range []string{"80", "443"} {
			if err := runCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-p", "tcp", "--dport", port, "-j", "ACCEPT"); err != nil && !isMissingRule(err) {
				errs = append(errs, err)
			}
		}
	}

	if err := runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cfg.SubnetCIDR, "!", "-d", cfg.SubnetCIDR, "-j", "MASQUERADE"); err != nil && !isMissingRule(err) {
		errs = append(errs, err)
	}
	if err := runCmd("ip", "link", "del", cfg.TapName); err != nil && !strings.Contains(err.Error(), "Cannot find device") {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("network teardown had %d error(s), first: %w", len(errs), errs[0])
	}
	return nil
}

func newNetworkConfig(execID string, np policy.NetworkPolicy) *NetworkConfig {
	short := shortID(execID)
	subnet, hostIP, guestIP := subnetForID(short)
	return &NetworkConfig{
		TapName:      "tap-" + short,
		SubnetCIDR:   subnet,
		HostIP:       hostIP,
		GuestIP:      guestIP,
		GatewayIP:    hostIP,
		GuestMAC:     "AA:FC:00:00:00:01",
		Mode:         np.Mode,
		Presets:      append([]string(nil), np.Presets...),
		allowedHosts: map[string]struct{}{},
		allowedIPs:   map[string]struct{}{},
	}
}

func subnetForID(id string) (string, string, string) {
	sum := crc32.ChecksumIEEE([]byte(id))
	second := 16 + int(sum&0x0f)
	third := int((sum >> 8) & 0xff)
	fourth := int((sum >> 16) & 0xfc)
	base := fmt.Sprintf("172.%d.%d.%d", second, third, fourth)
	return base + "/30", fmt.Sprintf("172.%d.%d.%d", second, third, fourth+1), fmt.Sprintf("172.%d.%d.%d", second, third, fourth+2)
}

func shortID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func resolvePresetHosts(presets []string) ([]string, error) {
	seen := map[string]struct{}{}
	var hosts []string
	for _, preset := range presets {
		entries, ok := policy.NetworkPresets[preset]
		if !ok {
			return nil, fmt.Errorf("unknown network preset: %s", preset)
		}
		for _, host := range entries {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func normalizeHostname(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func snapshotAllowedIPs(cfg *NetworkConfig) []string {
	cfg.dnsMu.Lock()
	defer cfg.dnsMu.Unlock()
	ips := make([]string, 0, len(cfg.allowedIPs))
	for ip := range cfg.allowedIPs {
		ips = append(ips, ip)
	}
	return ips
}

var runAllowlistRuleCmd = runCmd

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

func newUpstreamResolver() *net.Resolver {
	servers := []string{"8.8.8.8", "1.1.1.1"}
	if contents, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		servers = chooseUpstreamNameservers(string(contents))
	}

	var next uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			idx := atomic.AddUint32(&next, 1) - 1
			server := servers[int(idx)%len(servers)]
			dialNetwork := "udp4"
			if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil && ip.To4() == nil {
				dialNetwork = "udp6"
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, dialNetwork, net.JoinHostPort(strings.Trim(server, "[]"), "53"))
		},
	}
}

func allowResolvedIP(cfg *NetworkConfig, ip string, bus *telemetry.Bus) error {
	cfg.dnsMu.Lock()
	if _, ok := cfg.allowedIPs[ip]; ok {
		cfg.dnsMu.Unlock()
		return nil
	}
	cfg.allowedIPs[ip] = struct{}{}
	cfg.dnsMu.Unlock()

	addedPorts := make([]string, 0, 2)
	for _, port := range []string{"80", "443"} {
		if err := runAllowlistRuleCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-p", "tcp", "-d", ip, "--dport", port, "-j", "ACCEPT"); err != nil {
			for _, rollbackPort := range addedPorts {
				_ = runAllowlistRuleCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-p", "tcp", "-d", ip, "--dport", rollbackPort, "-j", "ACCEPT")
			}
			cfg.dnsMu.Lock()
			delete(cfg.allowedIPs, ip)
			cfg.dnsMu.Unlock()
			return err
		}
		addedPorts = append(addedPorts, port)
		emitIfBus(bus, telemetry.KindNetRuleAdd, telemetry.NetRuleData{
			Rule:  "ACCEPT",
			Dst:   ip,
			Ports: port,
		})
	}
	return nil
}

var lookupAllowlistIPv4 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	if resolver == nil {
		resolver = newUpstreamResolver()
	}
	return resolver.LookupIP(ctx, "ip4", host)
}

func startDNSInterceptor(cfg *NetworkConfig, bus *telemetry.Bus) error {
	addr := net.JoinHostPort(cfg.HostIP, "53")
	cfg.upstreamDNS = newUpstreamResolver()
	observability.Info("dns_interceptor_start", observability.Fields{"tap_name": cfg.TapName, "addr": addr, "presets": cfg.Presets})
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("start dns interceptor: %w", err)
	}
	cfg.dnsConn = conn
	go serveDNS(cfg, conn, bus)
	return nil
}

func serveDNS(cfg *NetworkConfig, conn net.PacketConn, bus *telemetry.Bus) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return
		}
		msg := append([]byte(nil), buf[:n]...)
		observability.Info("dns_query_received", observability.Fields{"tap_name": cfg.TapName, "client_addr": addr.String()})

		resp, err := buildDNSResponse(cfg, msg, bus)
		if err != nil {
			observability.Error("dns_build_response_failed", observability.Fields{"tap_name": cfg.TapName, "error": err.Error()})
			continue
		}
		if len(resp) == 0 {
			observability.Warn("dns_empty_response", observability.Fields{"tap_name": cfg.TapName, "client_addr": addr.String()})
			continue
		}

		if _, err := conn.WriteTo(resp, addr); err != nil {
			observability.Error("dns_write_response_failed", observability.Fields{"tap_name": cfg.TapName, "client_addr": addr.String(), "error": err.Error()})
		}
	}
}

func buildDNSResponse(cfg *NetworkConfig, req []byte, bus *telemetry.Bus) ([]byte, error) {
	var parser dnsmessage.Parser
	head, err := parser.Start(req)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	for {
		if _, err := parser.Question(); err != nil {
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}
			return nil, err
		}
	}

	respHeader := dnsmessage.Header{
		ID:                 head.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RecursionDesired:   head.RecursionDesired,
	}

	name := normalizeHostname(question.Name.String())
	allowed := false
	if _, ok := cfg.allowedHosts[name]; ok {
		allowed = true
	}
	observability.Info("dns_question", observability.Fields{"tap_name": cfg.TapName, "name": name, "query_type": question.Type.String(), "allowed": allowed})

	builder := dnsmessage.NewBuilder(nil, respHeader)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}

	if !allowed {
		emitIfBus(bus, telemetry.KindDNSQuery, telemetry.DNSQueryData{
			Domain: name,
			Action: "deny",
			Reason: "not in allowlist",
		})
		builder = dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:                 head.ID,
			Response:           true,
			Authoritative:      true,
			RecursionAvailable: true,
			RecursionDesired:   head.RecursionDesired,
			RCode:              dnsmessage.RCodeNameError,
		})
		builder.EnableCompression()
		if err := builder.StartQuestions(); err != nil {
			return nil, err
		}
		if err := builder.Question(question); err != nil {
			return nil, err
		}
		if err := builder.StartAnswers(); err != nil {
			return nil, err
		}
		observability.Info("dns_nxdomain", observability.Fields{"tap_name": cfg.TapName, "name": name})
		return builder.Finish()
	}

	if question.Type == dnsmessage.TypeA {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ips, err := lookupAllowlistIPv4(ctx, cfg.upstreamDNS, name)
		observability.Info("dns_upstream_resolve", observability.Fields{"tap_name": cfg.TapName, "name": name, "ips": ips, "resolve_error": err})
		if err != nil {
			emitIfBus(bus, telemetry.KindDNSQuery, telemetry.DNSQueryData{
				Domain: name,
				Action: "error",
				Reason: err.Error(),
			})
			return dnsErrorResponse(head, question, dnsmessage.RCodeServerFailure)
		}
		answerCount := 0
		resolvedIPs := make([]string, 0, len(ips))
		for _, ip := range ips {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if err := allowResolvedIP(cfg, ip4.String(), bus); err != nil {
				return dnsErrorResponse(head, question, dnsmessage.RCodeServerFailure)
			}
			resolvedIPs = append(resolvedIPs, ip4.String())
			var arr [4]byte
			copy(arr[:], ip4)
			if err := builder.AResource(dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   30,
			}, dnsmessage.AResource{A: arr}); err != nil {
				return nil, err
			}
			answerCount++
		}
		emitIfBus(bus, telemetry.KindDNSQuery, telemetry.DNSQueryData{
			Domain:   name,
			Action:   "allow",
			Resolved: resolvedIPs,
		})
		observability.Info("dns_answered_a", observability.Fields{"tap_name": cfg.TapName, "name": name, "answer_count": answerCount})
	} else {
		observability.Info("dns_empty_noerror", observability.Fields{"tap_name": cfg.TapName, "name": name, "query_type": question.Type.String()})
	}

	return builder.Finish()
}

func dnsErrorResponse(head dnsmessage.Header, question dnsmessage.Question, code dnsmessage.RCode) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 head.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RecursionDesired:   head.RecursionDesired,
		RCode:              code,
	})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func forwardRules(cfg *NetworkConfig, delete bool) [][]string {
	verb := "-I"
	args := []string{"FORWARD", "1"}
	if delete {
		verb = "-D"
		args = []string{"FORWARD"}
	}
	return [][]string{
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-d", "10.0.0.0/8", "-j", "DROP"),
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-d", "172.16.0.0/12", "-j", "DROP"),
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-d", "192.168.0.0/16", "-j", "DROP"),
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-d", "169.254.169.254", "-j", "DROP"),
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-p", "udp", "--dport", "53", "-j", "DROP"),
		append(append([]string{verb}, args...), "-i", cfg.TapName, "-p", "tcp", "--dport", "53", "-j", "DROP"),
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func isMissingRule(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Bad rule") || strings.Contains(msg, "No chain/target/match by that name") || strings.Contains(msg, "does a matching rule exist")
}

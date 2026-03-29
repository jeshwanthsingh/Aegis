package executor

import (
	"context"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegis/internal/policy"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	cgroupRoot   = "/sys/fs/cgroup"
	cgroupParent = "/sys/fs/cgroup/aegis"
)

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
	dnsMu        sync.Mutex
}

func SetupCgroup(uuid string, pid int, resources policy.ResourcePolicy) error {
	_ = os.WriteFile(cgroupRoot+"/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0o644)

	if err := os.MkdirAll(cgroupParent, 0o755); err != nil {
		return fmt.Errorf("create aegis cgroup parent: %w", err)
	}
	if err := os.WriteFile(cgroupParent+"/cgroup.subtree_control", []byte("+cpu +memory +pids"), 0o644); err != nil {
		return fmt.Errorf("enable controllers in aegis parent: %w", err)
	}

	cgPath := fmt.Sprintf("%s/%s", cgroupParent, uuid)
	if err := os.MkdirAll(cgPath, 0o755); err != nil {
		return fmt.Errorf("create cgroup dir: %w", err)
	}

	limits := []struct {
		file  string
		value string
	}{
		{"memory.max", fmt.Sprintf("%dM", resources.MemoryMaxMB)},
		{"memory.high", fmt.Sprintf("%dM", resources.MemoryMaxMB/2)},
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
	return nil
}

func CreateScratchDisk(uuid string) (string, error) {
	path := fmt.Sprintf("/tmp/aegis/scratch-%s.ext4", uuid)
	if err := createExt4Disk(path, 50); err != nil {
		return "", err
	}
	return path, nil
}

func SetupNetwork(execID string, np policy.NetworkPolicy) (*NetworkConfig, error) {
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

	if mode == "allowlist" {
		hosts, err := resolvePresetHosts(np.Presets)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			cfg.allowedHosts[normalizeHostname(host)] = struct{}{}
		}
		if err := startDNSInterceptor(cfg); err != nil {
			return nil, err
		}
	} else {
		for _, port := range []string{"80", "443"} {
			if err := runCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-p", "tcp", "--dport", port, "-j", "ACCEPT"); err != nil {
				return nil, err
			}
		}
	}

	for _, rule := range forwardRules(cfg, false) {
		if err := runCmd("iptables", rule...); err != nil {
			return nil, err
		}
	}

	cleanup = false
	return cfg, nil
}

func Teardown(vm *VMInstance) error {
	var errs []error

	if err := vm.Kill(); err != nil {
		log.Printf("teardown [%s]: kill: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: killed firecracker pid %d", vm.UUID, vm.FirecrackerPID)
	}

	if vm.Network != nil {
		if err := teardownNetwork(vm.Network); err != nil {
			log.Printf("teardown [%s]: network: %v", vm.UUID, err)
			errs = append(errs, err)
		} else {
			log.Printf("teardown [%s]: removed TAP device %s", vm.UUID, vm.Network.TapName)
		}
	}

	if vm.IsPersistent {
		log.Printf("teardown [%s]: preserved workspace image %s", vm.UUID, vm.ScratchPath)
	} else if err := os.Remove(vm.ScratchPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove scratch: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed scratch image", vm.UUID)
	}

	if err := os.Remove(vm.SocketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove fc socket: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed fc socket", vm.UUID)
	}

	if err := os.Remove(vm.VsockPath); err != nil && !os.IsNotExist(err) {
		log.Printf("teardown [%s]: remove vsock socket: %v", vm.UUID, err)
		errs = append(errs, err)
	} else {
		log.Printf("teardown [%s]: removed vsock socket", vm.UUID)
	}

	cgPath := fmt.Sprintf("%s/%s", cgroupParent, vm.UUID)
	cgRemoved := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := os.Remove(cgPath); err == nil || os.IsNotExist(err) {
			log.Printf("teardown [%s]: removed cgroup", vm.UUID)
			cgRemoved = true
			break
		}
	}
	if !cgRemoved {
		err := fmt.Errorf("cgroup dir still busy after retries: %s", cgPath)
		log.Printf("teardown [%s]: %v", vm.UUID, err)
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown had %d error(s), first: %w", len(errs), errs[0])
	}
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
			log.Printf("reconcile network [%s]: %v", name, err)
		} else {
			log.Printf("reconcile network [%s]: removed leaked TAP device", name)
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

func allowResolvedIP(cfg *NetworkConfig, ip string) error {
	cfg.dnsMu.Lock()
	if _, ok := cfg.allowedIPs[ip]; ok {
		cfg.dnsMu.Unlock()
		return nil
	}
	cfg.allowedIPs[ip] = struct{}{}
	cfg.dnsMu.Unlock()

	addedPorts := make([]string, 0, 2)
	for _, port := range []string{"80", "443"} {
		if err := runCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-p", "tcp", "-d", ip, "--dport", port, "-j", "ACCEPT"); err != nil {
			for _, rollbackPort := range addedPorts {
				_ = runCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-p", "tcp", "-d", ip, "--dport", rollbackPort, "-j", "ACCEPT")
			}
			cfg.dnsMu.Lock()
			delete(cfg.allowedIPs, ip)
			cfg.dnsMu.Unlock()
			return err
		}
		addedPorts = append(addedPorts, port)
	}
	return nil
}

func startDNSInterceptor(cfg *NetworkConfig) error {
	addr := net.JoinHostPort(cfg.HostIP, "53")
	log.Printf("dns [%s]: starting interceptor on %s for presets=%v", cfg.TapName, addr, cfg.Presets)
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("start dns interceptor: %w", err)
	}
	cfg.dnsConn = conn
	go serveDNS(cfg, conn)
	return nil
}

func serveDNS(cfg *NetworkConfig, conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return
		}
		msg := append([]byte(nil), buf[:n]...)
		log.Printf("dns [%s]: received query from %v", cfg.TapName, addr)

		resp, err := buildDNSResponse(cfg, msg)
		if err != nil {
			log.Printf("dns [%s]: build response error: %v", cfg.TapName, err)
			continue
		}
		if len(resp) == 0 {
			log.Printf("dns [%s]: empty response for %v", cfg.TapName, addr)
			continue
		}

		if _, err := conn.WriteTo(resp, addr); err != nil {
			log.Printf("dns [%s]: write response to %v failed: %v", cfg.TapName, addr, err)
		}
	}
}

func buildDNSResponse(cfg *NetworkConfig, req []byte) ([]byte, error) {
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
			if err == dnsmessage.ErrSectionDone {
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
	log.Printf("dns [%s]: question name=%q type=%v allowed=%t", cfg.TapName, name, question.Type, allowed)

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
		log.Printf("dns [%s]: returning NXDOMAIN for %q", cfg.TapName, name)
		return builder.Finish()
	}

	if question.Type == dnsmessage.TypeA {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		log.Printf("dns [%s]: resolve %q -> ips=%v err=%v", cfg.TapName, name, ips, err)
		if err != nil {
			return dnsErrorResponse(head, question, dnsmessage.RCodeServerFailure)
		}
		answerCount := 0
		for _, ip := range ips {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if err := allowResolvedIP(cfg, ip4.String()); err != nil {
				return dnsErrorResponse(head, question, dnsmessage.RCodeServerFailure)
			}
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
		log.Printf("dns [%s]: answered %d A record(s) for %q", cfg.TapName, answerCount, name)
	} else {
		log.Printf("dns [%s]: no records for query type=%v for %q, returning empty NOERROR", cfg.TapName, question.Type, name)
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

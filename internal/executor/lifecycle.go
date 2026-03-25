package executor

import (
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aegis/internal/policy"
)

const (
	cgroupRoot   = "/sys/fs/cgroup"
	cgroupParent = "/sys/fs/cgroup/aegis"
)

type NetworkConfig struct {
	TapName    string
	SubnetCIDR string
	HostIP     string
	GuestIP    string
	GatewayIP  string
	GuestMAC   string
	Mode       string
	Presets    []string
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

	cmd := exec.Command("dd", "if=/dev/zero", fmt.Sprintf("of=%s", path), "bs=1M", "count=50")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("dd: %w: %s", err, string(output))
	}

	cmd = exec.Command("/usr/sbin/mkfs.ext4", "-F", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.ext4: %w: %s", err, string(output))
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
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					for _, port := range []string{"80", "443"} {
						if err := runCmd("iptables", "-I", "FORWARD", "1", "-i", cfg.TapName, "-p", "tcp", "-d", ip4.String(), "--dport", port, "-j", "ACCEPT"); err != nil {
							return nil, err
						}
					}
				}
			}
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

	if err := os.Remove(vm.ScratchPath); err != nil && !os.IsNotExist(err) {
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
		hosts, err := resolvePresetHosts(cfg.Presets)
		if err == nil {
			for _, host := range hosts {
				ips, err := net.LookupIP(host)
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if ip4 := ip.To4(); ip4 != nil {
						for _, port := range []string{"80", "443"} {
							if err := runCmd("iptables", "-D", "FORWARD", "-i", cfg.TapName, "-p", "tcp", "-d", ip4.String(), "--dport", port, "-j", "ACCEPT"); err != nil && !isMissingRule(err) {
								errs = append(errs, err)
							}
						}
					}
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
		TapName:    "tap-" + short,
		SubnetCIDR: subnet,
		HostIP:     hostIP,
		GuestIP:    guestIP,
		GatewayIP:  hostIP,
		GuestMAC:   "AA:FC:00:00:00:01",
		Mode:       np.Mode,
		Presets:    append([]string(nil), np.Presets...),
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

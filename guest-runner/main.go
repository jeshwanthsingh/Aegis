package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

type Payload struct {
	Lang               string `json:"lang"`
	Code               string `json:"code"`
	TimeoutMs          int    `json:"timeout_ms"`
	PidsLimit          int    `json:"pids_limit,omitempty"`
	WorkspaceRequested bool   `json:"workspace_requested,omitempty"`
	NetworkRequested   bool   `json:"network_requested,omitempty"`
	GuestIP            string `json:"guest_ip,omitempty"`
	GatewayIP          string `json:"gateway_ip,omitempty"`
	DNSServer          string `json:"dns_server,omitempty"`
}

type GuestChunk struct {
	Type       string          `json:"type"`
	Name       string          `json:"name,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Chunk      string          `json:"chunk,omitempty"`
	ExitCode   int             `json:"exit_code,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	DurationMs int64           `json:"duration_ms,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type guestProcSampleData struct {
	PidsCurrent int `json:"pids_current"`
	PidsLimit   int `json:"pids_limit"`
	PidsPct     int `json:"pids_pct"`
}

const (
	guestExecUID            = 65534
	guestExecGID            = 65534
	guestProcSampleInterval = 100 * time.Millisecond
	guestProcSampleKind     = "guest.proc.sample"
	guestStreamChunkBytes   = 16 * 1024
)

var managedChildren atomic.Int32

func beginManagedChild() {
	managedChildren.Add(1)
}

func endManagedChild() {
	if managedChildren.Add(-1) == 0 {
		reapChildren()
	}
}

func reapChildren() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
	}
}

func sendError(conn net.Conn, msg string) {
	_ = json.NewEncoder(conn).Encode(GuestChunk{Type: "error", Error: msg})
}

func sendChunkError(chunks chan<- GuestChunk, msg string) {
	chunks <- GuestChunk{Type: "error", Error: msg}
}

func emitDiag(chunks chan<- GuestChunk, msg string) {
	chunks <- GuestChunk{Type: "stderr", Chunk: "DIAG: " + msg + "\n"}
}

func nodeEnvDiag() string {
	var sb strings.Builder
	run := func(name string, args ...string) string {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Sprintf("(error: %v)", err)
		}
		return strings.TrimSpace(string(out))
	}
	readFile := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Sprintf("(error: %v)", err)
		}
		return strings.TrimSpace(string(b))
	}
	statLine := func(path string) string {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Sprintf("%s: (missing: %v)", path, err)
		}
		return fmt.Sprintf("%s: mode=%s size=%d", path, info.Mode(), info.Size())
	}

	sb.WriteString("=== node preflight ===\n")
	sb.WriteString("-- mounts --\n" + run("mount") + "\n")
	sb.WriteString("-- /dev --\n" + run("ls", "-l", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom") + "\n")
	sb.WriteString("-- /proc --\n" + run("ls", "/proc") + "\n")
	sb.WriteString("-- entropy_avail --\n" + readFile("/proc/sys/kernel/random/entropy_avail") + "\n")
	sb.WriteString("-- node binaries --\n")
	for _, p := range []string{"/usr/bin/node", "/usr/bin/nodejs", "/usr/local/bin/node", "/usr/local/bin/nodejs"} {
		sb.WriteString(statLine(p) + "\n")
	}
	sb.WriteString("-- node --version --\n" + run("timeout", "3", "/usr/local/bin/node", "--version") + "\n")
	sb.WriteString("-- PATH --\n" + os.Getenv("PATH") + "\n")
	sb.WriteString("=== end preflight ===\n")
	return sb.String()
}

func setupWorkspace(requested bool) (bool, error) {
	const workspaceDir = "/workspace"
	const blockDevice = "/dev/vdb"

	if !requested {
		return false, nil
	}

	if _, err := os.Stat(blockDevice); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		return false, err
	}

	if err := unix.Mount(blockDevice, workspaceDir, "ext4", 0, ""); err != nil {
		return false, err
	}
	if err := os.Chmod(workspaceDir, 0o777); err != nil {
		_ = unix.Unmount(workspaceDir, 0)
		return false, err
	}

	return true, nil
}

func createLauncher(limit int) (string, error) {
	f, err := os.CreateTemp("", "launcher-*.sh")
	if err != nil {
		return "", err
	}
	// Use bash instead of /bin/sh because `ulimit -u` is not portable across
	// all /bin/sh implementations used by our guest images. Bash is an explicit
	// guest dependency in the supported rootfs builds.
	script := "#!/bin/bash\nulimit -u \"$1\"\nshift\nexec \"$@\"\n"
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if err := os.Chmod(f.Name(), 0o755); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func createTempResolvConf(dnsServer string) (string, error) {
	resolvPath, err := os.CreateTemp("", "resolv-*.conf")
	if err != nil {
		return "", err
	}
	cleanupPath := resolvPath.Name()
	contents := fmt.Sprintf("nameserver %s\noptions timeout:5 attempts:2\n", dnsServer)
	if _, err := resolvPath.WriteString(contents); err != nil {
		resolvPath.Close()
		os.Remove(cleanupPath)
		return "", err
	}
	if err := resolvPath.Close(); err != nil {
		os.Remove(cleanupPath)
		return "", err
	}
	// The executed child runs as nobody, so the bind-mounted resolver file must
	// be readable by non-root code that performs name resolution.
	if err := os.Chmod(cleanupPath, 0o644); err != nil {
		os.Remove(cleanupPath)
		return "", err
	}
	return cleanupPath, nil
}

func countProcessTree(rootPID int) (int, error) {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", rootPID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}

	children := make(map[int][]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		ppid := -1
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "PPid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if parsed, err := strconv.Atoi(fields[1]); err == nil {
					ppid = parsed
				}
			}
			break
		}
		if ppid >= 0 {
			children[ppid] = append(children[ppid], pid)
		}
	}

	count := 0
	queue := []int{rootPID}
	seen := map[int]struct{}{}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			continue
		}
		count++
		queue = append(queue, children[pid]...)
	}
	return count, nil
}

func sampleGuestProcesses(rootPID int, limit int, send func(GuestChunk) bool, stop <-chan struct{}, limitHit *atomic.Bool) {
	ticker := time.NewTicker(guestProcSampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			count, err := countProcessTree(rootPID)
			if err != nil || count == 0 {
				continue
			}
			if limit > 0 && count >= limit {
				limitHit.Store(true)
			}
			data, err := json.Marshal(guestProcSampleData{
				PidsCurrent: count,
				PidsLimit:   limit,
				PidsPct:     percentInt(count, limit),
			})
			if err != nil {
				continue
			}
			if !send(GuestChunk{Type: "telemetry", Name: guestProcSampleKind, Data: data}) {
				return
			}
		}
	}
}

func percentInt(current int, limit int) int {
	if limit <= 0 {
		return 0
	}
	return (current * 100) / limit
}

func classifyExitReason(timedOut bool, guestPidsLimitHit bool, fallback string) string {
	if guestPidsLimitHit {
		return "pids_limit"
	}
	if timedOut {
		return "timeout"
	}
	if fallback != "" {
		return fallback
	}
	return "completed"
}

func findCommand(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func runGuestCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	beginManagedChild()
	defer endManagedChild()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), msg, err)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func setupNetwork(p Payload, emit func(string)) (func() error, error) {
	if !p.NetworkRequested {
		return nil, nil
	}
	emit("setupNetwork start")
	if p.GuestIP == "" || p.GatewayIP == "" || p.DNSServer == "" {
		return nil, errors.New("incomplete network configuration")
	}
	if _, err := os.Stat("/sys/class/net/eth0"); err != nil {
		return nil, fmt.Errorf("eth0 unavailable: %w", err)
	}

	ipCmd := findCommand("ip", "/sbin/ip", "/usr/sbin/ip")
	emit("using ip command: " + ipCmd)
	if ipCmd == "" {
		return nil, errors.New("ip command not found")
	}
	emit("ip link set lo up")
	if err := runGuestCmd(ipCmd, "link", "set", "lo", "up"); err != nil {
		return nil, err
	}
	emit("ip link set eth0 up")
	if err := runGuestCmd(ipCmd, "link", "set", "eth0", "up"); err != nil {
		return nil, err
	}
	emit("ip addr flush dev eth0")
	if err := runGuestCmd(ipCmd, "addr", "flush", "dev", "eth0"); err != nil {
		return nil, err
	}
	emit("ip addr add " + p.GuestIP + "/30 dev eth0")
	if err := runGuestCmd(ipCmd, "addr", "add", p.GuestIP+"/30", "dev", "eth0"); err != nil {
		return nil, err
	}
	emit("ip route del default")
	_ = runGuestCmd(ipCmd, "route", "del", "default")
	emit("ip route add default via " + p.GatewayIP + " dev eth0")
	if err := runGuestCmd(ipCmd, "route", "add", "default", "via", p.GatewayIP, "dev", "eth0"); err != nil {
		return nil, err
	}

	emit("create temp resolv.conf")
	emit("write temp resolv.conf for " + p.DNSServer)
	cleanupPath, err := createTempResolvConf(p.DNSServer)
	if err != nil {
		return nil, err
	}
	emit("bind mount resolv.conf")
	if err := unix.Mount(cleanupPath, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		os.Remove(cleanupPath)
		return nil, err
	}

	emit("setupNetwork complete")
	cleanup := func() error {
		var errs []string
		if err := unix.Unmount("/etc/resolv.conf", 0); err != nil {
			errs = append(errs, "unmount /etc/resolv.conf: "+err.Error())
		}
		if err := os.Remove(cleanupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, "remove resolv temp: "+err.Error())
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}
	return cleanup, nil
}

func main() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGCHLD)
		for range c {
			if managedChildren.Load() > 0 {
				continue
			}
			reapChildren()
		}
	}()

	var l net.Listener
	for i := 0; ; i++ {
		var listenErr error
		l, listenErr = vsock.Listen(1024, nil)
		if listenErr == nil {
			break
		}
		if i >= 20 {
			fmt.Fprintf(os.Stderr, "vsock.Listen failed: %v\n", listenErr)
			os.Exit(1)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock.Accept failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	var p Payload
	if err := json.NewDecoder(conn).Decode(&p); err != nil {
		sendError(conn, "decode payload: "+err.Error())
		return
	}
	if len(p.Code) > 64*1024 {
		sendError(conn, "payload too large")
		return
	}

	chunks := make(chan GuestChunk, 64)
	writeErr := make(chan error, 1)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		bw := bufio.NewWriter(conn)
		enc := json.NewEncoder(bw)
		for ch := range chunks {
			if err := enc.Encode(ch); err != nil {
				writeErr <- err
				return
			}
			if err := bw.Flush(); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	sendChunk := func(ch GuestChunk) bool {
		select {
		case chunks <- ch:
			return true
		case <-writerDone:
			return false
		}
	}

	mountedWorkspace, err := setupWorkspace(p.WorkspaceRequested)
	if err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: "setup workspace: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}

	debugEnabled := os.Getenv("AEGIS_DEBUG") == "1"

	networkCleanup, err := setupNetwork(p, func(msg string) {
		if debugEnabled {
			emitDiag(chunks, msg)
		}
	})
	if p.NetworkRequested {
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: "setup network: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}

	interpreter, ext, ok := resolveInterpreter(p.Lang)
	if !ok {
		if !sendChunk(GuestChunk{Type: "error", Error: "unsupported lang: " + p.Lang}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}

	var diagPrefix string
	if p.Lang == "node" {
		diagPrefix = nodeEnvDiag()
	}

	f, err := os.CreateTemp("", "exec-*"+ext)
	if err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "create temp file: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(p.Code); err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "write temp file: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}
	_ = f.Close()
	_ = os.Chmod(f.Name(), 0o644)

	interpArgs := []string{f.Name()}
	if p.Lang == "python" {
		interpArgs = []string{"-S", "-u", f.Name()}
	}
	execPath := interpreter
	execArgs := interpArgs
	var launcherPath string
	if p.PidsLimit > 0 {
		launcherPath, err = createLauncher(p.PidsLimit)
		if err != nil {
			if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "create launcher: " + err.Error()}) {
				return
			}
			close(chunks)
			_ = <-writeErr
			return
		}
		defer os.Remove(launcherPath)
		execPath = launcherPath
		execArgs = append([]string{strconv.Itoa(p.PidsLimit), interpreter}, interpArgs...)
	}
	cmd := exec.Command(execPath, execArgs...)
	workDir := "/tmp"
	if mountedWorkspace {
		workDir = "/workspace"
	}
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "HOME="+workDir, "USER=nobody", "LOGNAME=nobody")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: guestExecUID, Gid: guestExecGID},
		Setpgid:    true,
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "stdout pipe: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "stderr pipe: " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "start " + interpreter + ": " + err.Error()}) {
			return
		}
		close(chunks)
		_ = <-writeErr
		return
	}
	beginManagedChild()
	defer endManagedChild()
	if diagPrefix != "" {
		if !sendChunk(GuestChunk{Type: "stderr", Chunk: diagPrefix}) {
			return
		}
	}

	var timedOut atomic.Bool
	var guestPidsLimitHit atomic.Bool
	timer := time.AfterFunc(time.Duration(p.TimeoutMs)*time.Millisecond, func() {
		timedOut.Store(true)
		if cmd.Process == nil {
			return
		}
		// The child runs in its own process group. Kill the whole group so
		// descendants like `sleep` do not keep stdout/stderr open after the
		// parent shell is gone.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	samplerStop := make(chan struct{})
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		sampleGuestProcesses(cmd.Process.Pid, p.PidsLimit, sendChunk, samplerStop, &guestPidsLimitHit)
	}()
	defer func() {
		close(samplerStop)
		samplerWG.Wait()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go streamPipe(&wg, stdoutPipe, "stdout", chunks, writerDone)
	go streamPipe(&wg, stderrPipe, "stderr", chunks, writerDone)

	wg.Wait()

	exitCode := 0
	exitReason := "completed"
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if timedOut.Load() {
			exitCode = -1
			exitReason = classifyExitReason(true, guestPidsLimitHit.Load(), exitReason)
			_ = sendChunk(GuestChunk{Type: "stderr", Chunk: "execution timeout\n"})
		} else if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			if guestPidsLimitHit.Load() {
				exitReason = classifyExitReason(false, true, exitReason)
			}
		} else {
			exitCode = 1
		}
	}

	if networkCleanup != nil {
		if err := networkCleanup(); err != nil {
			_ = sendChunk(GuestChunk{Type: "stderr", Chunk: "network cleanup: " + err.Error() + "\n"})
		}
	}
	if mountedWorkspace {
		unix.Sync()
		if err := unix.Unmount("/workspace", 0); err != nil {
			_ = sendChunk(GuestChunk{Type: "stderr", Chunk: "workspace unmount: " + err.Error() + "\n"})
		}
		unix.Sync()
	}
	if !sendChunk(GuestChunk{Type: "done", ExitCode: exitCode, Reason: exitReason, DurationMs: time.Since(start).Milliseconds()}) {
		_ = <-writeErr
		return
	}
	close(chunks)
	_ = <-writeErr
}

func streamPipe(wg *sync.WaitGroup, pipe io.Reader, chunkType string, chunks chan<- GuestChunk, writerDone <-chan struct{}) {
	defer wg.Done()
	reader := bufio.NewReaderSize(pipe, guestStreamChunkBytes)
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			select {
			case chunks <- GuestChunk{Type: chunkType, Chunk: string(chunk)}:
			case <-writerDone:
				return
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return
		}
	}
}

func resolveInterpreter(lang string) (string, string, bool) {
	switch lang {
	case "python":
		return "/usr/bin/python3", ".py", true
	case "node":
		return "/usr/local/bin/node", ".js", true
	case "bash":
		return "/bin/bash", ".sh", true
	default:
		return "", "", false
	}
}

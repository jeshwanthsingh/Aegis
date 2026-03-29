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
	WorkspaceRequested bool   `json:"workspace_requested,omitempty"`
	NetworkRequested   bool   `json:"network_requested,omitempty"`
	GuestIP            string `json:"guest_ip,omitempty"`
	GatewayIP          string `json:"gateway_ip,omitempty"`
	DNSServer          string `json:"dns_server,omitempty"`
}

type GuestChunk struct {
	Type       string `json:"type"`
	Chunk      string `json:"chunk,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

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

	return true, nil
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
	resolvPath, err := os.CreateTemp("", "resolv-*.conf")
	if err != nil {
		return nil, err
	}
	cleanupPath := resolvPath.Name()
	contents := fmt.Sprintf("nameserver %s\noptions timeout:5 attempts:2\n", p.DNSServer)
	emit("write temp resolv.conf for " + p.DNSServer)
	if _, err := resolvPath.WriteString(contents); err != nil {
		resolvPath.Close()
		os.Remove(cleanupPath)
		return nil, err
	}
	if err := resolvPath.Close(); err != nil {
		os.Remove(cleanupPath)
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

	l, err := vsock.Listen(1024, nil)
	if err != nil {
		os.Exit(1)
	}
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
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

	cmdArgs := []string{f.Name()}
	if p.Lang == "python" {
		cmdArgs = []string{"-S", "-u", f.Name()}
	}
	cmd := exec.Command(interpreter, cmdArgs...)
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
	timer := time.AfterFunc(time.Duration(p.TimeoutMs)*time.Millisecond, func() {
		timedOut.Store(true)
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go streamPipe(&wg, stdoutPipe, "stdout", chunks, writerDone)
	go streamPipe(&wg, stderrPipe, "stderr", chunks, writerDone)

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if timedOut.Load() {
			exitCode = -1
			_ = sendChunk(GuestChunk{Type: "stderr", Chunk: "execution timeout\n"})
		} else if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	wg.Wait()
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
	if !sendChunk(GuestChunk{Type: "done", ExitCode: exitCode, DurationMs: time.Since(start).Milliseconds()}) {
		_ = <-writeErr
		return
	}
	close(chunks)
	_ = <-writeErr
}

func streamPipe(wg *sync.WaitGroup, pipe io.Reader, chunkType string, chunks chan<- GuestChunk, writerDone <-chan struct{}) {
	defer wg.Done()
	scanner := bufio.NewScanner(pipe)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		select {
		case chunks <- GuestChunk{Type: chunkType, Chunk: scanner.Text() + "\n"}:
		case <-writerDone:
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

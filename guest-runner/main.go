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
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
)

type Payload struct {
	Lang      string `json:"lang"`
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
}

type GuestChunk struct {
	Type       string `json:"type"`
	Chunk      string `json:"chunk,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

func sendError(conn net.Conn, msg string) {
	_ = json.NewEncoder(conn).Encode(GuestChunk{Type: "error", Error: msg})
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

func main() {
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGCHLD)
		for range c {
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
			}
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

	interpreter, ext, ok := resolveInterpreter(p.Lang)
	if !ok {
		sendError(conn, "unsupported lang: "+p.Lang)
		return
	}

	var diagPrefix string
	if p.Lang == "node" {
		diagPrefix = nodeEnvDiag()
	}

	f, err := os.CreateTemp("", "exec-*"+ext)
	if err != nil {
		sendError(conn, diagPrefix+"create temp file: "+err.Error())
		return
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(p.Code); err != nil {
		sendError(conn, diagPrefix+"write temp file: "+err.Error())
		return
	}
	_ = f.Close()

	cmd := exec.Command(interpreter, f.Name())
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		sendError(conn, diagPrefix+"stdout pipe: "+err.Error())
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		sendError(conn, diagPrefix+"stderr pipe: "+err.Error())
		return
	}

	chunks := make(chan GuestChunk, 32)
	writeErr := make(chan error, 1)
	go func() {
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



	start := time.Now()
	if err := cmd.Start(); err != nil {
		sendError(conn, diagPrefix+"start "+interpreter+": "+err.Error())
		return
	}
	if diagPrefix != "" {
		chunks <- GuestChunk{Type: "stderr", Chunk: diagPrefix}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go streamPipe(&wg, stdoutPipe, "stdout", chunks)
	go streamPipe(&wg, stderrPipe, "stderr", chunks)

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	wg.Wait()
	chunks <- GuestChunk{Type: "done", ExitCode: exitCode, DurationMs: time.Since(start).Milliseconds()}
	close(chunks)
	_ = <-writeErr
}

func streamPipe(wg *sync.WaitGroup, pipe io.Reader, chunkType string, chunks chan<- GuestChunk) {
	defer wg.Done()
	scanner := bufio.NewScanner(pipe)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		chunks <- GuestChunk{Type: chunkType, Chunk: scanner.Text() + "\n"}
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

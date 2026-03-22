package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/mdlayher/vsock"
)

const maxOutputBytes = 65536 // 64KB per stream

type Payload struct {
	Lang string `json:"lang"`
	Code string `json:"code"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}

func sendError(conn net.Conn, msg string) {
	json.NewEncoder(conn).Encode(Result{Stderr: msg, ExitCode: 1})
}

// nodeEnvDiag collects guest environment info relevant to Node.js startup.
// Returns a multi-line string to prepend to stderr when node fails/hangs.
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

	// For node: run preflight diagnostics before attempting execution.
	// This surfaces guest environment state in stderr regardless of outcome.
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
	f.Close()

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

	if err := cmd.Start(); err != nil {
		sendError(conn, diagPrefix+"start "+interpreter+": "+err.Error())
		return
	}

	var (
		stdoutData, stderrData   []byte
		stdoutTrunc, stderrTrunc bool
		wg                       sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		data, _ := io.ReadAll(io.LimitReader(stdoutPipe, maxOutputBytes+1))
		if len(data) > maxOutputBytes {
			stdoutTrunc = true
			data = data[:maxOutputBytes]
		}
		stdoutData = data
	}()
	go func() {
		defer wg.Done()
		data, _ := io.ReadAll(io.LimitReader(stderrPipe, maxOutputBytes+1))
		if len(data) > maxOutputBytes {
			stderrTrunc = true
			data = data[:maxOutputBytes]
		}
		stderrData = data
	}()
	wg.Wait()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	json.NewEncoder(conn).Encode(Result{
		Stdout:          string(stdoutData),
		Stderr:          diagPrefix + string(stderrData),
		ExitCode:        exitCode,
		OutputTruncated: stdoutTrunc || stderrTrunc,
	})
}

// resolveInterpreter maps a lang name to (binary, file-extension, ok).
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

//go:build linux

package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCountProcessTreeIncludesDescendants(t *testing.T) {
	cmd := exec.Command("/bin/bash", "-lc", "for i in $(seq 1 6); do sleep 2 & done; sleep 2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	time.Sleep(200 * time.Millisecond)
	count, err := countProcessTree(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("countProcessTree: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected descendant processes, got %d", count)
	}
}

func TestSampleGuestProcessesEmitsTelemetry(t *testing.T) {
	cmd := exec.Command("/bin/bash", "-lc", "for i in $(seq 1 8); do sleep 2 & done; sleep 2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	stop := make(chan struct{})
	defer close(stop)
	var limitHit atomic.Bool
	got := make(chan GuestChunk, 8)
	go sampleGuestProcesses(cmd.Process.Pid, 16, func(ch GuestChunk) bool {
		got <- ch
		return true
	}, stop, &limitHit)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ch := <-got:
			if ch.Type != "telemetry" || ch.Name != guestProcSampleKind {
				continue
			}
			var data guestProcSampleData
			if err := json.Unmarshal(ch.Data, &data); err != nil {
				t.Fatalf("unmarshal telemetry: %v", err)
			}
			if data.PidsCurrent > 1 {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for guest proc telemetry")
		}
	}
}

func TestLauncherEnforcesProcessLimit(t *testing.T) {
	launcher, err := createLauncher(16)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	defer os.Remove(launcher)

	script, err := os.CreateTemp("", "proc-limit-*.py")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(script.Name())
	if _, err := script.WriteString("import os, sys, time\nchildren=[]\nwhile True:\n    try:\n        pid = os.fork()\n    except OSError as exc:\n        print(exc, file=sys.stderr)\n        sys.exit(1)\n    if pid == 0:\n        time.sleep(5)\n        os._exit(0)\n    children.append(pid)\n"); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := script.Close(); err != nil {
		t.Fatalf("close script: %v", err)
	}
	if err := os.Chmod(script.Name(), 0o644); err != nil {
		t.Fatalf("chmod script: %v", err)
	}

	cmd := exec.Command(launcher, "16", "/usr/bin/python3", script.Name())
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected process limit failure")
	}
	msg := string(output)
	if !strings.Contains(msg, "Resource temporarily unavailable") && !strings.Contains(msg, "fork") {
		t.Fatalf("expected fork failure output, got %q", msg)
	}
}

func TestCreateTempResolvConfReadableByGuestUser(t *testing.T) {
	path, err := createTempResolvConf("10.0.2.1")
	if err != nil {
		t.Fatalf("createTempResolvConf: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat resolv conf: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("expected mode 0644, got %#o", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read resolv conf as current user: %v", err)
	}
	if string(data) != "nameserver 10.0.2.1\noptions timeout:5 attempts:2\n" {
		t.Fatalf("unexpected resolv conf contents: %q", string(data))
	}
}

func TestClassifyExitReason(t *testing.T) {
	t.Parallel()

	if got := classifyExitReason(true, true, "completed"); got != "pids_limit" {
		t.Fatalf("expected pids_limit to win over timeout, got %q", got)
	}
	if got := classifyExitReason(true, false, "completed"); got != "timeout" {
		t.Fatalf("expected timeout, got %q", got)
	}
	if got := classifyExitReason(false, true, "completed"); got != "pids_limit" {
		t.Fatalf("expected pids_limit, got %q", got)
	}
	if got := classifyExitReason(false, false, "completed"); got != "completed" {
		t.Fatalf("expected completed, got %q", got)
	}
}

func TestStreamPipeCapturesTrailingPartialLine(t *testing.T) {
	t.Parallel()

	reader, writer := io.Pipe()
	chunks := make(chan GuestChunk, 4)
	writerDone := make(chan struct{})
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		streamPipe(&wg, reader, "stdout", chunks, writerDone)
		close(done)
	}()

	if _, err := writer.Write([]byte("GOOD: connection blocked")); err != nil {
		t.Fatalf("write partial line: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	wg.Wait()
	close(chunks)

	var got []string
	for ch := range chunks {
		got = append(got, ch.Chunk)
	}
	if len(got) != 1 || got[0] != "GOOD: connection blocked" {
		t.Fatalf("unexpected chunks: %#v", got)
	}
}

func TestStreamPipeCapturesMultipleLines(t *testing.T) {
	t.Parallel()

	reader, writer := io.Pipe()
	chunks := make(chan GuestChunk, 4)
	writerDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go streamPipe(&wg, reader, "stdout", chunks, writerDone)

	if _, err := writer.Write([]byte("line one\nline two\n")); err != nil {
		t.Fatalf("write lines: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	wg.Wait()
	close(chunks)

	var got []string
	for ch := range chunks {
		got = append(got, ch.Chunk)
	}
	want := []string{"line one\n", "line two\n"}
	if len(got) != len(want) {
		t.Fatalf("unexpected chunk count: got %d want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chunk %d mismatch: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestStreamPipeSplitsLargeOutputWithoutNewline(t *testing.T) {
	t.Parallel()

	reader, writer := io.Pipe()
	chunks := make(chan GuestChunk, 16)
	writerDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go streamPipe(&wg, reader, "stdout", chunks, writerDone)

	payload := strings.Repeat("A", 70000)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	wg.Wait()
	close(chunks)

	var (
		gotChunks int
		totalLen  int
	)
	for ch := range chunks {
		gotChunks++
		totalLen += len(ch.Chunk)
		if len(ch.Chunk) > guestStreamChunkBytes {
			t.Fatalf("chunk exceeded limit: got %d want <= %d", len(ch.Chunk), guestStreamChunkBytes)
		}
	}
	if gotChunks < 2 {
		t.Fatalf("expected large output to split across multiple chunks, got %d", gotChunks)
	}
	if totalLen != len(payload) {
		t.Fatalf("unexpected total length: got %d want %d", totalLen, len(payload))
	}
}

func captureCommandOutput(t *testing.T, command string, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.Command(command, args...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}

	chunks := make(chan GuestChunk, 32)
	writerDone := make(chan struct{})

	var readers sync.WaitGroup
	readers.Add(2)
	go streamPipe(&readers, stdoutPipe, "stdout", chunks, writerDone)
	go streamPipe(&readers, stderrPipe, "stderr", chunks, writerDone)

	readers.Wait()
	close(writerDone)

	waitErr := cmd.Wait()
	close(chunks)

	var stdout, stderr strings.Builder
	for ch := range chunks {
		switch ch.Type {
		case "stdout":
			stdout.WriteString(ch.Chunk)
		case "stderr":
			stderr.WriteString(ch.Chunk)
		}
	}
	return stdout.String(), stderr.String(), waitErr
}

func TestCaptureBlockedConnectOutputSurvivesSocketClose(t *testing.T) {
	t.Parallel()

	script, err := os.CreateTemp("", "blocked-connect-*.py")
	if err != nil {
		t.Fatalf("create temp script: %v", err)
	}
	defer os.Remove(script.Name())

	code := `import os, socket
s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
    if rc == 0:
        msg = "BAD: connected\n"
    else:
        msg = f"GOOD: connection blocked: errno={rc}\n"
except Exception as e:
    msg = f"GOOD: connection blocked: {type(e).__name__}: {e}\n"
finally:
    try:
        s.close()
    except Exception:
        pass
os.write(1, msg.encode())
`
	if _, err := script.WriteString(code); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := script.Close(); err != nil {
		t.Fatalf("close script: %v", err)
	}
	if err := os.Chmod(script.Name(), 0o644); err != nil {
		t.Fatalf("chmod script: %v", err)
	}

	stdout, stderr, err := captureCommandOutput(t, "/usr/bin/python3", "-S", "-u", script.Name())
	if err != nil {
		t.Fatalf("expected zero exit, got err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "GOOD: connection blocked: errno=") {
		t.Fatalf("expected blocked connect stdout, got stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestCaptureHelloOutput(t *testing.T) {
	t.Parallel()

	script, err := os.CreateTemp("", "hello-*.py")
	if err != nil {
		t.Fatalf("create temp script: %v", err)
	}
	defer os.Remove(script.Name())
	if _, err := script.WriteString("print(\"HELLO\")\n"); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := script.Close(); err != nil {
		t.Fatalf("close script: %v", err)
	}
	if err := os.Chmod(script.Name(), 0o644); err != nil {
		t.Fatalf("chmod script: %v", err)
	}

	stdout, stderr, err := captureCommandOutput(t, "/usr/bin/python3", "-S", "-u", script.Name())
	if err != nil {
		t.Fatalf("expected zero exit, got err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	if stdout != "HELLO\n" || stderr != "" {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout, stderr)
	}
}

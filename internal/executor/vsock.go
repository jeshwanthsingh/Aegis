package executor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"aegis/internal/models"
)

const maxOutputBytes = 65536 // 64KB

func DialWithRetry(vsockPath string, port uint32, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := dialVsockProxy(vsockPath, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().Add(10*time.Millisecond).After(deadline) {
			return nil, fmt.Errorf("vsock dial timeout after %v: %w", timeout, lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialVsockProxy(vsockPath string, port uint32) (net.Conn, error) {
	conn, err := net.Dial("unix", vsockPath)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake send: %w", err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake read: %w", err)
	}
	if !strings.HasPrefix(resp, "OK ") {
		conn.Close()
		return nil, fmt.Errorf("unexpected handshake response: %q", resp)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// SendPayload sends the execution payload and waits for a result.
// deadline is the absolute time after which the call must return; it is set
// directly on the conn so that a fork-bomb or infinite-loop in the guest
// cannot block longer than the request timeout allows.
func SendPayload(conn net.Conn, payload models.Payload, deadline time.Time) (models.Result, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return models.Result{}, fmt.Errorf("set deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		return models.Result{}, fmt.Errorf("encode payload: %w", err)
	}
	var result models.Result
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return models.Result{}, fmt.Errorf("decode result: %w", err)
	}

	// Record raw byte counts before truncation
	result.StdoutBytes = len(result.Stdout)
	result.StderrBytes = len(result.Stderr)

	// Enforce output caps
	if len(result.Stdout) > maxOutputBytes {
		result.Stdout = result.Stdout[:maxOutputBytes]
		result.OutputTruncated = true
	}
	if len(result.Stderr) > maxOutputBytes {
		result.Stderr = result.Stderr[:maxOutputBytes]
		result.OutputTruncated = true
	}

	return result, nil
}

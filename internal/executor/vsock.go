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

func SendPayload(conn net.Conn, payload models.Payload, deadline time.Time) (models.Result, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return models.Result{}, fmt.Errorf("set deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		return models.Result{}, fmt.Errorf("encode payload: %w", err)
	}
	result, err := ReadChunks(conn, deadline, nil)
	if err != nil {
		return models.Result{}, err
	}
	return *result, nil
}

// ReadChunks reads streaming chunks from vsock until type=="done" or type=="error".
// Calls onChunk for each stdout/stderr chunk and returns the aggregated result on done.
func ReadChunks(conn net.Conn, deadline time.Time, onChunk func(chunkType, chunk string)) (*models.Result, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	dec := json.NewDecoder(conn)
	var result models.Result
	for {
		var chunk models.GuestChunk
		if err := dec.Decode(&chunk); err != nil {
			return nil, fmt.Errorf("decode chunk: %w", err)
		}

		switch chunk.Type {
		case "stdout":
			result.StdoutBytes += len(chunk.Chunk)
			if onChunk != nil {
				onChunk("stdout", chunk.Chunk)
			}
			appendChunk(&result.Stdout, chunk.Chunk, &result.OutputTruncated)
		case "stderr":
			result.StderrBytes += len(chunk.Chunk)
			if onChunk != nil {
				onChunk("stderr", chunk.Chunk)
			}
			appendChunk(&result.Stderr, chunk.Chunk, &result.OutputTruncated)
		case "done":
			result.ExitCode = chunk.ExitCode
			result.DurationMs = chunk.DurationMs
			return &result, nil
		case "error":
			return nil, fmt.Errorf(chunk.Error)
		default:
			return nil, fmt.Errorf("unknown chunk type: %s", chunk.Type)
		}
	}
}

func appendChunk(dst *string, chunk string, truncated *bool) {
	remaining := maxOutputBytes - len(*dst)
	if remaining <= 0 {
		*truncated = true
		return
	}
	if len(chunk) > remaining {
		*dst += chunk[:remaining]
		*truncated = true
		return
	}
	*dst += chunk
}
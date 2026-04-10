package executor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"aegis/internal/models"
	policydivergence "aegis/internal/policy/divergence"
	policyevaluator "aegis/internal/policy/evaluator"
	"aegis/internal/telemetry"
)

const (
	maxOutputBytes     = 65536
	maxGuestChunkBytes = 262144
	GuestExecPort      = 1024
	GuestReadyPort     = 1023
)

func DialWithRetry(vsockPath string, port uint32, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := dialVsockProxy(vsockPath, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().Add(10 * time.Millisecond).After(deadline) {
			return nil, fmt.Errorf("vsock dial timeout after %v: %w", timeout, lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func WaitForGuestReady(vsockPath string, timeout time.Duration) error {
	conn, err := DialWithRetry(vsockPath, GuestReadyPort, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
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

func SendPayload(conn net.Conn, payload models.Payload, deadline time.Time, bus *telemetry.Bus, pointEvaluator *policyevaluator.Evaluator, divergenceEvaluator *policydivergence.Evaluator, enforce func(models.PolicyDivergenceResult) error) (models.Result, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return models.Result{}, fmt.Errorf("set deadline: %w", err)
	}
	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		return models.Result{}, fmt.Errorf("encode payload: %w", err)
	}
	result, err := ReadChunks(conn, deadline, nil, bus, pointEvaluator, divergenceEvaluator, enforce)
	if err != nil {
		return models.Result{}, err
	}
	return *result, nil
}

func ReadChunks(conn net.Conn, deadline time.Time, onChunk func(chunkType, chunk string), bus *telemetry.Bus, pointEvaluator *policyevaluator.Evaluator, divergenceEvaluator *policydivergence.Evaluator, enforce func(models.PolicyDivergenceResult) error) (*models.Result, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxGuestChunkBytes)
	var result models.Result
	var runtimeNormalizer *runtimeEventNormalizer
	if bus != nil {
		runtimeNormalizer = newRuntimeEventNormalizer(bus.ExecID(), pointEvaluator, divergenceEvaluator, enforce)
	}

	for {
		var chunk models.GuestChunk
		if !scanner.Scan() {
			if runtimeNormalizer != nil {
				if enforced, ok := runtimeNormalizer.enforcedResult(); ok {
					emitIfBus(bus, telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: enforced.ExitCode, Reason: enforced.ExitReason})
					enforced.Stdout = result.Stdout
					enforced.Stderr = result.Stderr
					enforced.StdoutBytes = result.StdoutBytes
					enforced.StderrBytes = result.StderrBytes
					enforced.OutputTruncated = result.OutputTruncated
					return &enforced, nil
				}
			}
			if err := scanner.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return nil, fmt.Errorf("decode chunk: guest message exceeds %d bytes", maxGuestChunkBytes)
				}
				return nil, fmt.Errorf("decode chunk: %w", err)
			}
			return nil, fmt.Errorf("decode chunk: %w", io.EOF)
		}
		if err := json.Unmarshal(scanner.Bytes(), &chunk); err != nil {
			return nil, fmt.Errorf("decode chunk: %w", err)
		}

		switch chunk.Type {
		case "stdout":
			result.StdoutBytes += len(chunk.Chunk)
			emitIfBus(bus, telemetry.KindExecStdout, map[string]interface{}{"bytes": len(chunk.Chunk), "truncated": false})
			if onChunk != nil {
				onChunk("stdout", chunk.Chunk)
			}
			appendChunk(&result.Stdout, chunk.Chunk, &result.OutputTruncated)
		case "stderr":
			result.StderrBytes += len(chunk.Chunk)
			emitIfBus(bus, telemetry.KindExecStderr, map[string]interface{}{"bytes": len(chunk.Chunk)})
			if onChunk != nil {
				onChunk("stderr", chunk.Chunk)
			}
			appendChunk(&result.Stderr, chunk.Chunk, &result.OutputTruncated)
		case "done":
			if runtimeNormalizer != nil {
				if enforced, ok := runtimeNormalizer.enforcedResult(); ok {
					result.ExitCode = enforced.ExitCode
					result.ExitReason = enforced.ExitReason
				} else {
					result.ExitCode = chunk.ExitCode
					result.ExitReason = chunk.Reason
				}
			} else {
				result.ExitCode = chunk.ExitCode
				result.ExitReason = chunk.Reason
			}
			result.DurationMs = chunk.DurationMs
			reason := "completed"
			if result.ExitReason != "" {
				reason = result.ExitReason
			}
			emitIfBus(bus, telemetry.KindExecExit, telemetry.ExecExitData{ExitCode: result.ExitCode, Reason: reason})
			return &result, nil
		case "telemetry":
			switch chunk.Name {
			case telemetry.KindGuestProcSample:
				var data telemetry.GuestProcSampleData
				if err := json.Unmarshal(chunk.Data, &data); err != nil {
					return nil, fmt.Errorf("decode guest proc telemetry: %w", err)
				}
				emitIfBus(bus, telemetry.KindGuestProcSample, data)
			case guestRuntimeEventBatchKind:
				if runtimeNormalizer == nil {
					continue
				}
				var batch guestRuntimeEventBatch
				if err := json.Unmarshal(chunk.Data, &batch); err != nil {
					return nil, fmt.Errorf("decode runtime event batch: %w", err)
				}
				if err := runtimeNormalizer.emitBatch(batch, bus); err != nil {
					return nil, fmt.Errorf("normalize runtime event batch: %w", err)
				}
			case guestRuntimeSensorStatusKind:
				if runtimeNormalizer == nil {
					continue
				}
				var status guestRuntimeSensorStatus
				if err := json.Unmarshal(chunk.Data, &status); err != nil {
					return nil, fmt.Errorf("decode runtime sensor status: %w", err)
				}
				runtimeNormalizer.emitStatus(status, bus)
			}
		case "error":
			return nil, errors.New(chunk.Error)
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

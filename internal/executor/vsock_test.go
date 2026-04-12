package executor

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"aegis/internal/governance"
	"aegis/internal/models"
	policycontract "aegis/internal/policy/contract"
	policydivergence "aegis/internal/policy/divergence"
	policyevaluator "aegis/internal/policy/evaluator"
	"aegis/internal/telemetry"
)

func TestReadChunksEmitsGuestProcTelemetry(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bus := telemetry.NewBus("exec-telemetry")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: telemetry.KindGuestProcSample,
			Data: mustJSON(t, telemetry.GuestProcSampleData{PidsCurrent: 8, PidsLimit: 16, PidsPct: 50}),
		})
		_ = enc.Encode(models.GuestChunk{
			Type:     "done",
			ExitCode: 1,
			Reason:   "guest_pids_limit",
		})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, nil, nil, nil)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.ExitReason != "guest_pids_limit" {
		t.Fatalf("unexpected exit reason: %q", result.ExitReason)
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindGuestProcSample {
				continue
			}
			var data telemetry.GuestProcSampleData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatalf("unmarshal event data: %v", err)
			}
			if data.PidsCurrent != 8 || data.PidsLimit != 16 {
				t.Fatalf("unexpected guest proc sample: %+v", data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for guest proc sample event")
		}
	}
}

func TestReadChunksEmitsRuntimeEvents(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bus := telemetry.NewBus("exec-runtime")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	exitCode := 0
	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Dropped:       2,
				FloodDetected: true,
				QueueCapacity: 256,
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "process.exec", PID: 42, PPID: 1, Comm: "python3", Exe: "/usr/bin/python3"},
					{TsUnixNano: 102, Type: "file.open", PID: 42, Path: "/tmp/out.txt", Flags: 0x241, Metadata: map[string]string{"source": "ptrace", "syscall": "openat"}},
					{TsUnixNano: 103, Type: "process.exit", PID: 42, ExitCode: &exitCode},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, nil, nil, nil)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.ExitReason != "completed" {
		t.Fatalf("unexpected exit reason: %q", result.ExitReason)
	}

	var runtimeEvents []models.RuntimeEvent
	var status telemetry.RuntimeSensorStatusData
	deadline := time.After(time.Second)
	for len(runtimeEvents) < 3 || status.DroppedEvents == 0 {
		select {
		case event := <-ch:
			switch event.Kind {
			case telemetry.KindRuntimeEvent:
				var runtimeEvent models.RuntimeEvent
				if err := json.Unmarshal(event.Data, &runtimeEvent); err != nil {
					t.Fatalf("unmarshal runtime event: %v", err)
				}
				runtimeEvents = append(runtimeEvents, runtimeEvent)
			case telemetry.KindRuntimeSensorStatus:
				if err := json.Unmarshal(event.Data, &status); err != nil {
					t.Fatalf("unmarshal runtime sensor status: %v", err)
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for runtime events, got %d", len(runtimeEvents))
		}
	}

	if runtimeEvents[0].Seq != 1 || runtimeEvents[1].Seq != 2 || runtimeEvents[2].Seq != 3 {
		t.Fatalf("unexpected runtime event sequence: %+v", runtimeEvents)
	}
	if runtimeEvents[0].DroppedSinceLast != 2 || runtimeEvents[1].DroppedSinceLast != 0 {
		t.Fatalf("unexpected dropped_since_last values: %+v", runtimeEvents)
	}
	if runtimeEvents[0].Backend != models.BackendFirecracker {
		t.Fatalf("unexpected backend: %q", runtimeEvents[0].Backend)
	}
	if runtimeEvents[1].Type != models.EventFileOpen || runtimeEvents[1].Path != "/tmp/out.txt" {
		t.Fatalf("unexpected file.open event: %+v", runtimeEvents[1])
	}
	if runtimeEvents[1].Flags != 0x241 || runtimeEvents[1].Metadata["source"] != "ptrace" || runtimeEvents[1].Metadata["syscall"] != "openat" {
		t.Fatalf("unexpected file.open metadata: %+v", runtimeEvents[1])
	}
	if runtimeEvents[2].ExitCode != 0 {
		t.Fatalf("unexpected process.exit event: %+v", runtimeEvents[2])
	}
	if !status.FloodDetected || status.DroppedEvents != 2 {
		t.Fatalf("unexpected runtime sensor status: %+v", status)
	}
}

func TestReadChunksPromotesBlockedSymlinkToSecurityDenied(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	bus := telemetry.NewBus("exec-security")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeSensorStatusKind,
			Data: mustJSON(t, guestRuntimeSensorStatus{
				Source: "guest-runtime-trace",
				Detail: "blocked-symlink-open pid=42 raw=/tmp/link resolved=/etc/passwd",
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, nil, nil, nil)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.ExitCode != 137 {
		t.Fatalf("unexpected exit code: %d", result.ExitCode)
	}
	if result.ExitReason != runtimeSecurityDeniedSymlink {
		t.Fatalf("unexpected exit reason: %q", result.ExitReason)
	}

	deadline := time.After(time.Second)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindPolicyEnforcement {
				continue
			}
			var data telemetry.PolicyEnforcementData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatalf("unmarshal policy enforcement: %v", err)
			}
			if data.RuleID != "file.symlink_race_denied" || data.Verdict != "security_denied" {
				t.Fatalf("unexpected policy enforcement: %+v", data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for policy enforcement event")
		}
	}
}

func TestReadChunksEmitsPolicyPointDecisions(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec-runtime",
		WorkflowID:      "wf-1",
		TaskClass:       "unit_test",
		DeclaredPurpose: "exercise point decisions",
		Language:        "python",
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace", "/etc/hostname"},
			WritePaths:       []string{"/workspace/out"},
			DenyPaths:        []string{"/workspace/.git"},
			MaxDistinctFiles: 8,
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     true,
			AllowedIPs:       []string{"127.0.0.1"},
			MaxDNSQueries:    0,
			MaxOutboundConns: 1,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:     []string{"python3"},
			AllowShell:          false,
			AllowPackageInstall: false,
			MaxChildProcesses:   2,
		},
		Budgets: policycontract.BudgetLimits{
			TimeoutSec:  10,
			MemoryMB:    128,
			CPUQuota:    100,
			StdoutBytes: 1024,
		},
	}
	eval := policyevaluator.New(intent)

	bus := telemetry.NewBus("exec-runtime")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "process.exec", PID: 42, Comm: "python3", Exe: "/usr/bin/python3"},
					{TsUnixNano: 102, Type: "net.connect", PID: 42, DstIP: "127.0.0.1", DstPort: 17777},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, eval, nil, nil); err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}

	var decisions []models.PolicyPointDecision
	deadline := time.After(time.Second)
	for len(decisions) < 2 {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindPolicyPointDecision {
				continue
			}
			var decision models.PolicyPointDecision
			if err := json.Unmarshal(event.Data, &decision); err != nil {
				t.Fatalf("unmarshal policy point decision: %v", err)
			}
			decisions = append(decisions, decision)
		case <-deadline:
			t.Fatalf("timed out waiting for policy decisions, got %d", len(decisions))
		}
	}

	if decisions[0].Decision != models.DecisionAllow || decisions[0].CedarAction != models.ActionExec {
		t.Fatalf("unexpected exec decision: %+v", decisions[0])
	}
	if decisions[1].Decision != models.DecisionAllow || decisions[1].CedarAction != models.ActionConnect {
		t.Fatalf("unexpected connect decision: %+v", decisions[1])
	}
}

func TestReadChunksEmitsGovernedActionForDeniedDirectEgress(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec-governed",
		WorkflowID:      "wf-1",
		TaskClass:       "unit_test",
		DeclaredPurpose: "exercise governed direct egress evidence",
		Language:        "python",
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace"},
			WritePaths:       []string{"/workspace"},
			MaxDistinctFiles: 8,
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     false,
			MaxDNSQueries:    0,
			MaxOutboundConns: 0,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:   []string{"python3"},
			MaxChildProcesses: 2,
		},
		Budgets: policycontract.BudgetLimits{
			TimeoutSec:  10,
			MemoryMB:    128,
			CPUQuota:    100,
			StdoutBytes: 1024,
		},
	}
	eval := policyevaluator.New(intent)
	bus := telemetry.NewBus("exec-governed")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "net.connect", PID: 42, DstIP: "1.1.1.1", DstPort: 80},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, eval, nil, nil); err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}

	deadline := time.After(time.Second)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindGovernedAction {
				continue
			}
			var data telemetry.GovernedActionData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatalf("unmarshal governed action: %v", err)
			}
			if data.ActionType != governance.ActionHTTPRequest || data.Decision != "deny" || data.DenialMarker != "direct_egress_denied" {
				t.Fatalf("unexpected governed action data: %+v", data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for governed action telemetry")
		}
	}
}

func TestReadChunksEmitsGovernedActionForDeniedNonHTTPDirectEgress(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec-governed-non-http",
		WorkflowID:      "wf-1",
		TaskClass:       "unit_test",
		DeclaredPurpose: "exercise broader direct egress evidence",
		Language:        "python",
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace"},
			WritePaths:       []string{"/workspace"},
			MaxDistinctFiles: 8,
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     false,
			MaxDNSQueries:    0,
			MaxOutboundConns: 0,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:   []string{"python3"},
			MaxChildProcesses: 2,
		},
		Budgets: policycontract.BudgetLimits{
			TimeoutSec:  10,
			MemoryMB:    128,
			CPUQuota:    100,
			StdoutBytes: 1024,
		},
	}
	eval := policyevaluator.New(intent)
	bus := telemetry.NewBus("exec-governed-non-http")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "net.connect", PID: 42, DstIP: "10.0.0.5", DstPort: 22},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, eval, nil, nil); err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}

	deadline := time.After(time.Second)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindGovernedAction {
				continue
			}
			var data telemetry.GovernedActionData
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatalf("unmarshal governed action: %v", err)
			}
			if data.ActionType != governance.ActionNetworkConnect || data.Decision != "deny" || data.DenialMarker != "direct_egress_denied" {
				t.Fatalf("unexpected governed action data: %+v", data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for governed action telemetry")
		}
	}
}

func TestReadChunksEmitsPolicyDivergenceResults(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec-runtime",
		WorkflowID:      "wf-1",
		TaskClass:       "unit_test",
		DeclaredPurpose: "exercise divergence",
		Language:        "python",
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace/report.pdf"},
			WritePaths:       []string{"/workspace/out"},
			DenyPaths:        []string{"/workspace/.git"},
			MaxDistinctFiles: 3,
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     false,
			AllowedIPs:       []string{},
			MaxDNSQueries:    0,
			MaxOutboundConns: 0,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:     []string{"python3"},
			AllowShell:          false,
			AllowPackageInstall: false,
			MaxChildProcesses:   1,
		},
		Budgets: policycontract.BudgetLimits{TimeoutSec: 10, MemoryMB: 128, CPUQuota: 100, StdoutBytes: 1024},
	}
	pointEval := policyevaluator.New(intent)
	divergenceEval := policydivergence.New(intent)

	bus := telemetry.NewBus("exec-runtime")
	ch, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{
					{TsUnixNano: 101, Type: "process.exec", PID: 42, Comm: "python3", Exe: "/usr/bin/python3"},
					{TsUnixNano: 102, Type: "net.connect", PID: 42, DstIP: "127.0.0.1", DstPort: 17777},
				},
			}),
		})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed"})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, pointEval, divergenceEval, nil); err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}

	var result models.PolicyDivergenceResult
	deadline := time.After(time.Second)
	for {
		select {
		case event := <-ch:
			if event.Kind != telemetry.KindPolicyDivergence {
				continue
			}
			if err := json.Unmarshal(event.Data, &result); err != nil {
				t.Fatalf("unmarshal policy divergence: %v", err)
			}
			if result.CurrentVerdict == models.DivergenceKillCandidate {
				if result.LastSeq != 2 {
					t.Fatalf("unexpected last seq: %d", result.LastSeq)
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for divergence result")
		}
	}
}

func TestReadChunksRejectsUnknownRuntimeEventType(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{{TsUnixNano: 1, Type: "bad.event"}},
			}),
		})
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, telemetry.NewBus("exec-runtime"), nil, nil, nil); err == nil || !strings.Contains(err.Error(), "unknown runtime event type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadChunksRejectsOversizedMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		oversized := `{"type":"stdout","chunk":"` + strings.Repeat("A", maxGuestChunkBytes) + `"}`
		_, _ = server.Write([]byte(oversized + "\n"))
	}()

	if _, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "guest message exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadChunksDecodesNormalMessageWithScanner(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{Type: "stdout", Chunk: "ok\n"})
		_ = enc.Encode(models.GuestChunk{Type: "done", ExitCode: 0, Reason: "completed", DurationMs: 12})
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if result.Stdout != "ok\n" {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}
	if result.ExitCode != 0 || result.ExitReason != "completed" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReadChunksEnforcesKillCandidate(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	intent := policycontract.IntentContract{
		Version:         "v1",
		ExecutionID:     "exec-runtime",
		WorkflowID:      "wf-1",
		TaskClass:       "unit_test",
		DeclaredPurpose: "exercise enforcement",
		Language:        "python",
		ResourceScope: policycontract.ResourceScope{
			WorkspaceRoot:    "/workspace",
			ReadPaths:        []string{"/workspace/report.pdf"},
			WritePaths:       []string{"/workspace/out"},
			DenyPaths:        []string{},
			MaxDistinctFiles: 3,
		},
		NetworkScope: policycontract.NetworkScope{
			AllowNetwork:     false,
			AllowedIPs:       []string{},
			MaxDNSQueries:    0,
			MaxOutboundConns: 0,
		},
		ProcessScope: policycontract.ProcessScope{
			AllowedBinaries:     []string{"python3"},
			AllowShell:          false,
			AllowPackageInstall: false,
			MaxChildProcesses:   1,
		},
		Budgets: policycontract.BudgetLimits{TimeoutSec: 10, MemoryMB: 128, CPUQuota: 100, StdoutBytes: 1024},
	}
	pointEval := policyevaluator.New(intent)
	divergenceEval := policydivergence.New(intent)
	bus := telemetry.NewBus("exec-runtime")

	enforced := 0
	go func() {
		enc := json.NewEncoder(server)
		_ = enc.Encode(models.GuestChunk{
			Type: "telemetry",
			Name: guestRuntimeEventBatchKind,
			Data: mustJSON(t, guestRuntimeEventBatch{
				Events: []guestRuntimeEvent{{TsUnixNano: 101, Type: "net.connect", PID: 42, DstIP: "127.0.0.1", DstPort: 17777}},
			}),
		})
		_ = server.Close()
	}()

	result, err := ReadChunks(client, time.Now().Add(2*time.Second), nil, bus, pointEval, divergenceEval, func(models.PolicyDivergenceResult) error {
		enforced++
		return nil
	})
	if err != nil {
		t.Fatalf("ReadChunks: %v", err)
	}
	if enforced != 1 {
		t.Fatalf("enforcement callback count = %d", enforced)
	}
	if result.ExitReason != "divergence_terminated" || result.ExitCode != 137 {
		t.Fatalf("unexpected enforced result: %+v", result)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return b
}

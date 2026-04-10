//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiffProcessSnapshotsEmitsExpectedEvents(t *testing.T) {
	now := time.Unix(1700000000, 0)
	rootOnly := map[int]runtimeProcSnapshot{
		100: {
			PID:   100,
			PPID:  1,
			Comm:  "python3",
			Exe:   "/usr/bin/python3",
			Files: map[string]runtimeFileObservation{"/etc/hostname": {Flags: 0}},
			Connections: map[string]runtimeConnection{
				"inode-1": {DstIP: "1.1.1.1", DstPort: 80, State: "02", Inode: "inode-1"},
			},
		},
	}

	events := diffProcessSnapshots(100, map[int]runtimeProcSnapshot{}, rootOnly, now)
	if len(events) != 3 {
		t.Fatalf("unexpected event count for root snapshot: got %d want 3", len(events))
	}
	if events[0].Type != "process.exec" || events[0].PID != 100 {
		t.Fatalf("unexpected root exec event: %+v", events[0])
	}
	if events[1].Type != "file.open" || events[1].Path != "/etc/hostname" {
		t.Fatalf("unexpected file.open event: %+v", events[1])
	}
	if events[2].Type != "net.connect" || events[2].DstIP != "1.1.1.1" || events[2].DstPort != 80 {
		t.Fatalf("unexpected net.connect event: %+v", events[2])
	}

	withChild := map[int]runtimeProcSnapshot{
		100: rootOnly[100],
		101: {
			PID:   101,
			PPID:  100,
			Comm:  "sh",
			Exe:   "/bin/sh",
			Files: map[string]runtimeFileObservation{"/tmp/exec-demo.py": {Flags: 0}},
		},
	}
	events = diffProcessSnapshots(100, rootOnly, withChild, now)
	if len(events) != 3 {
		t.Fatalf("unexpected event count for child snapshot: got %d want 3", len(events))
	}
	if events[0].Type != "process.fork" || events[1].Type != "process.exec" {
		t.Fatalf("unexpected child lifecycle events: %+v", events)
	}
	if events[2].Type != "file.open" || events[2].Path != "/tmp/exec-demo.py" {
		t.Fatalf("unexpected child file event: %+v", events[2])
	}

	events = diffProcessSnapshots(100, withChild, rootOnly, now)
	if len(events) != 1 || events[0].Type != "process.exit" || events[0].PID != 101 {
		t.Fatalf("unexpected child exit event: %+v", events)
	}
	if events[0].ExitCode == nil || *events[0].ExitCode != -1 {
		t.Fatalf("unexpected child exit code: %+v", events[0])
	}
}

func TestParseProcNetTCPFileParsesIPv4Remote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	contents := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:9C4C 01010101:0050 02 00000000:00000000 01:00000019 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write proc net fixture: %v", err)
	}

	connections, err := parseProcNetTCPFile(path)
	if err != nil {
		t.Fatalf("parseProcNetTCPFile: %v", err)
	}
	conn, ok := connections["4242"]
	if !ok {
		t.Fatalf("expected inode 4242 in connection map: %+v", connections)
	}
	if conn.DstIP != "1.1.1.1" || conn.DstPort != 80 || conn.State != "02" {
		t.Fatalf("unexpected connection payload: %+v", conn)
	}
}

func TestParseTraceSockaddrIPv4(t *testing.T) {
	buf := []byte{0x02, 0x00, 0x00, 0x50, 127, 0, 0, 1}
	addr, err := parseTraceSockaddr(buf)
	if err != nil {
		t.Fatalf("parseTraceSockaddr: %v", err)
	}
	if addr.IP != "127.0.0.1" || addr.Port != 80 {
		t.Fatalf("unexpected sockaddr: %+v", addr)
	}
}

func TestDiffFileSnapshotsOnlyEmitsNewFiles(t *testing.T) {
	now := time.Unix(1700000001, 0)
	prev := map[int]runtimeProcSnapshot{
		100: {PID: 100, Files: map[string]runtimeFileObservation{"/etc/hostname": {Flags: 0}}},
	}
	current := map[int]runtimeProcSnapshot{
		100: {PID: 100, Files: map[string]runtimeFileObservation{"/etc/hostname": {Flags: 0}, "/tmp/runtime-child.txt": {Flags: 0}}},
	}
	events := diffFileSnapshots(prev, current, now)
	if len(events) != 1 {
		t.Fatalf("unexpected event count: got %d want 1", len(events))
	}
	if events[0].Type != "file.open" || events[0].Path != "/tmp/runtime-child.txt" {
		t.Fatalf("unexpected file event: %+v", events[0])
	}
}

func TestDiffFileSnapshotsEmitsWriteIntentFlagChanges(t *testing.T) {
	now := time.Unix(1700000002, 0)
	prev := map[int]runtimeProcSnapshot{
		100: {PID: 100, Files: map[string]runtimeFileObservation{"/workspace/out.txt": {Flags: 0}}},
	}
	current := map[int]runtimeProcSnapshot{
		100: {PID: 100, Files: map[string]runtimeFileObservation{"/workspace/out.txt": {Flags: 0x241}}},
	}
	events := diffFileSnapshots(prev, current, now)
	if len(events) != 1 {
		t.Fatalf("unexpected event count: got %d want 1", len(events))
	}
	if events[0].Flags != 0x241 {
		t.Fatalf("unexpected file flags: %+v", events[0])
	}
}

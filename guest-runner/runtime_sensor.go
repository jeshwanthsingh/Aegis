package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	guestRuntimeEventBatchKind   = "guest.runtime.event.batch.v1"
	guestRuntimeSensorStatusKind = "guest.runtime.sensor.status.v1"
	runtimeSensorPollInterval    = 10 * time.Millisecond
	runtimeSensorFlushInterval   = 25 * time.Millisecond
	runtimeSensorQueueCapacity   = 256
	runtimeSensorMaxBatch        = 16
	runtimeSensorFloodThreshold  = 32
)

type runtimeSensorEvent struct {
	TsUnixNano int64             `json:"ts_unix_nano"`
	Type       string            `json:"type"`
	PID        int               `json:"pid,omitempty"`
	PPID       int               `json:"ppid,omitempty"`
	Comm       string            `json:"comm,omitempty"`
	Exe        string            `json:"exe,omitempty"`
	Path       string            `json:"path,omitempty"`
	Flags      uint64            `json:"flags,omitempty"`
	DstIP      string            `json:"dst_ip,omitempty"`
	DstPort    uint16            `json:"dst_port,omitempty"`
	ExitCode   *int              `json:"exit_code,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type runtimeSensorBatch struct {
	Events        []runtimeSensorEvent `json:"events"`
	Dropped       uint32               `json:"dropped"`
	FloodDetected bool                 `json:"flood_detected,omitempty"`
	QueueCapacity int                  `json:"queue_capacity,omitempty"`
}

type runtimeSensorStatus struct {
	DroppedEvents uint64 `json:"dropped_events"`
	FloodDetected bool   `json:"flood_detected"`
	QueueCapacity int    `json:"queue_capacity,omitempty"`
	BatchEvents   int    `json:"batch_events,omitempty"`
	Source        string `json:"source,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type runtimeConnection struct {
	DstIP   string
	DstPort uint16
	State   string
	Inode   string
}

type runtimeProcSnapshot struct {
	PID         int
	PPID        int
	Comm        string
	Exe         string
	Files       map[string]struct{}
	Connections map[string]runtimeConnection
}

type runtimeSensor struct {
	rootPID          int
	send             func(GuestChunk) bool
	events           chan runtimeSensorEvent
	stopCh           chan struct{}
	wg               sync.WaitGroup
	dropped          atomic.Uint32
	flood            atomic.Bool
	closed           atomic.Bool
	firstEventLogged atomic.Bool
	firstBatchSent   atomic.Bool
	firstConnLogged  atomic.Bool
	traceDone        chan runtimeTraceResult
	traceOnce        sync.Once
}

func startRuntimeSensor(rootPID int, send func(GuestChunk) bool) *runtimeSensor {
	s := &runtimeSensor{
		rootPID: rootPID,
		send:    send,
		events:  make(chan runtimeSensorEvent, runtimeSensorQueueCapacity),
		stopCh:  make(chan struct{}),
	}
	detail := fmt.Sprintf("started pid=%d", rootPID)
	if meta, err := os.ReadFile("/etc/aegis-guest-runner.json"); err == nil {
		detail = detail + " meta=" + truncateStatusDetail(strings.TrimSpace(string(meta)))
	}
	s.sendStatus(runtimeSensorStatus{QueueCapacity: runtimeSensorQueueCapacity, Source: "guest-runtime-sensor", Detail: detail})
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.runPoller()
	}()
	go func() {
		defer s.wg.Done()
		s.runSender()
	}()
	return s
}

func (s *runtimeSensor) RecordRootExit(exitCode int) {
	s.enqueue(runtimeSensorEvent{TsUnixNano: time.Now().UnixNano(), Type: "process.exit", PID: s.rootPID, ExitCode: intPtr(exitCode), Metadata: map[string]string{}})
}

func (s *runtimeSensor) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(s.dropped.Load()), FloodDetected: s.flood.Load(), QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: fmt.Sprintf("stopping pid=%d", s.rootPID)})
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

func (s *runtimeSensor) runPoller() {
	prev := make(map[int]runtimeProcSnapshot)
	ticker := time.NewTicker(runtimeSensorPollInterval)
	defer ticker.Stop()
	var lastErr string

	for {
		now := time.Now()
		current, err := snapshotRuntimeProcessTree(s.rootPID)
		if err == nil {
			if lastErr != "" {
				s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-sensor", Detail: "snapshot-recovered"})
				lastErr = ""
			}
			for _, event := range diffFileSnapshots(prev, current, now) {
				s.enqueue(event)
			}
			prev = current
		} else if err.Error() != lastErr {
			lastErr = err.Error()
			s.sendStatus(runtimeSensorStatus{Source: "guest-runtime-sensor", Detail: "snapshot-error: " + truncateStatusDetail(lastErr)})
		}

		select {
		case <-s.stopCh:
			close(s.events)
			return
		case <-ticker.C:
		}
	}
}

func (s *runtimeSensor) runSender() {
	ticker := time.NewTicker(runtimeSensorFlushInterval)
	defer ticker.Stop()
	batch := make([]runtimeSensorEvent, 0, runtimeSensorMaxBatch)

	flush := func() bool {
		dropped := s.dropped.Swap(0)
		flood := s.flood.Swap(false)
		if len(batch) == 0 {
			if dropped == 0 && !flood {
				return true
			}
			return s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(dropped), FloodDetected: flood, QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: "drop-accounting-only"})
		}

		payload, err := json.Marshal(runtimeSensorBatch{Events: append([]runtimeSensorEvent(nil), batch...), Dropped: dropped, FloodDetected: flood, QueueCapacity: cap(s.events)})
		if err != nil {
			return true
		}
		if s.firstBatchSent.CompareAndSwap(false, true) {
			s.sendStatus(runtimeSensorStatus{DroppedEvents: uint64(dropped), FloodDetected: flood, QueueCapacity: cap(s.events), BatchEvents: len(batch), Source: "guest-runtime-sensor", Detail: "first-batch-sent"})
		}
		batch = batch[:0]
		return s.send(GuestChunk{Type: "telemetry", Name: guestRuntimeEventBatchKind, Data: payload})
	}

	for {
		select {
		case event, ok := <-s.events:
			if !ok {
				_ = flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= runtimeSensorMaxBatch {
				if !flush() {
					return
				}
			}
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

func (s *runtimeSensor) enqueue(event runtimeSensorEvent) {
	if s.firstEventLogged.CompareAndSwap(false, true) {
		s.sendStatus(runtimeSensorStatus{QueueCapacity: cap(s.events), Source: "guest-runtime-sensor", Detail: fmt.Sprintf("first-event type=%s pid=%d", event.Type, event.PID)})
	}
	select {
	case s.events <- event:
	default:
		dropped := s.dropped.Add(1)
		if dropped >= runtimeSensorFloodThreshold {
			s.flood.Store(true)
		}
	}
}

func (s *runtimeSensor) sendStatus(status runtimeSensorStatus) bool {
	payload, err := json.Marshal(status)
	if err != nil {
		return true
	}
	return s.send(GuestChunk{Type: "telemetry", Name: guestRuntimeSensorStatusKind, Data: payload})
}

func (s *runtimeSensor) logFirstConnection(current map[int]runtimeProcSnapshot) {
	if !s.firstConnLogged.CompareAndSwap(false, true) {
		return
	}
	for _, pid := range sortedSnapshotPIDs(current) {
		snapshot := current[pid]
		if len(snapshot.Connections) == 0 {
			continue
		}
		keys := make([]string, 0, len(snapshot.Connections))
		for key := range snapshot.Connections {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		conn := snapshot.Connections[keys[0]]
		s.sendStatus(runtimeSensorStatus{
			Source: "guest-runtime-sensor",
			Detail: fmt.Sprintf("first-connection pid=%d dst=%s:%d state=%s", snapshot.PID, conn.DstIP, conn.DstPort, conn.State),
		})
		return
	}
	s.firstConnLogged.Store(false)
}

func diffFileSnapshots(prev, current map[int]runtimeProcSnapshot, now time.Time) []runtimeSensorEvent {
	var events []runtimeSensorEvent
	for _, pid := range sortedSnapshotPIDs(current) {
		snapshot := current[pid]
		previous, exists := prev[pid]
		if !exists {
			events = append(events, diffFileEvents(nil, snapshot.Files, snapshot, now)...)
			continue
		}
		events = append(events, diffFileEvents(previous.Files, snapshot.Files, snapshot, now)...)
	}
	return events
}

func diffProcessSnapshots(rootPID int, prev, current map[int]runtimeProcSnapshot, now time.Time) []runtimeSensorEvent {
	var events []runtimeSensorEvent
	currentPIDs := sortedSnapshotPIDs(current)
	for _, pid := range currentPIDs {
		snapshot := current[pid]
		previous, exists := prev[pid]
		if !exists {
			if pid == rootPID {
				events = append(events, newProcessEvent("process.exec", snapshot, now, nil))
			} else {
				events = append(events, newProcessEvent("process.fork", snapshot, now, nil), newProcessEvent("process.exec", snapshot, now, nil))
			}
			events = append(events, diffFileEvents(nil, snapshot.Files, snapshot, now)...)
			events = append(events, diffConnectionEvents(nil, snapshot.Connections, snapshot, now)...)
			continue
		}
		events = append(events, diffFileEvents(previous.Files, snapshot.Files, snapshot, now)...)
		events = append(events, diffConnectionEvents(previous.Connections, snapshot.Connections, snapshot, now)...)
	}

	prevPIDs := sortedSnapshotPIDs(prev)
	for _, pid := range prevPIDs {
		if pid == rootPID {
			continue
		}
		if _, exists := current[pid]; exists {
			continue
		}
		exitCode := -1
		events = append(events, newProcessEvent("process.exit", prev[pid], now, &exitCode))
	}
	return events
}

func diffFileEvents(prev map[string]struct{}, current map[string]struct{}, snapshot runtimeProcSnapshot, now time.Time) []runtimeSensorEvent {
	if len(current) == 0 {
		return nil
	}
	paths := make([]string, 0, len(current))
	for path := range current {
		if _, seen := prev[path]; seen {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	events := make([]runtimeSensorEvent, 0, len(paths))
	for _, path := range paths {
		events = append(events, runtimeSensorEvent{TsUnixNano: now.UnixNano(), Type: "file.open", PID: snapshot.PID, PPID: snapshot.PPID, Comm: snapshot.Comm, Exe: snapshot.Exe, Path: path, Metadata: map[string]string{}})
	}
	return events
}

func diffConnectionEvents(prev map[string]runtimeConnection, current map[string]runtimeConnection, snapshot runtimeProcSnapshot, now time.Time) []runtimeSensorEvent {
	if len(current) == 0 {
		return nil
	}
	keys := make([]string, 0, len(current))
	for key := range current {
		if _, seen := prev[key]; seen {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	events := make([]runtimeSensorEvent, 0, len(keys))
	for _, key := range keys {
		conn := current[key]
		events = append(events, runtimeSensorEvent{TsUnixNano: now.UnixNano(), Type: "net.connect", PID: snapshot.PID, PPID: snapshot.PPID, Comm: snapshot.Comm, Exe: snapshot.Exe, DstIP: conn.DstIP, DstPort: conn.DstPort, Metadata: map[string]string{"state": conn.State}})
	}
	return events
}

func newProcessEvent(kind string, snapshot runtimeProcSnapshot, now time.Time, exitCode *int) runtimeSensorEvent {
	event := runtimeSensorEvent{TsUnixNano: now.UnixNano(), Type: kind, PID: snapshot.PID, PPID: snapshot.PPID, Comm: snapshot.Comm, Exe: snapshot.Exe, Metadata: map[string]string{}}
	if exitCode != nil {
		event.ExitCode = exitCode
	}
	return event
}

func sortedSnapshotPIDs(snapshots map[int]runtimeProcSnapshot) []int {
	pids := make([]int, 0, len(snapshots))
	for pid := range snapshots {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}

func snapshotRuntimeProcessTree(rootPID int) (map[int]runtimeProcSnapshot, error) {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", rootPID)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[int]runtimeProcSnapshot{}, nil
		}
		return nil, err
	}

	ppids, children, err := readRuntimeProcessTable()
	if err != nil {
		return nil, err
	}
	connections, err := parseProcNetTCPFile("/proc/net/tcp")
	if err != nil {
		connections = map[string]runtimeConnection{}
	}

	snapshots := make(map[int]runtimeProcSnapshot)
	queue := []int{rootPID}
	seen := map[int]struct{}{}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}

		ppid, ok := ppids[pid]
		if !ok {
			continue
		}
		snapshot, err := readRuntimeProcSnapshot(pid, ppid, connections)
		if err == nil {
			snapshots[pid] = snapshot
		}
		queue = append(queue, children[pid]...)
	}
	return snapshots, nil
}

func readRuntimeProcessTable() (map[int]int, map[int][]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, err
	}
	ppids := make(map[int]int)
	children := make(map[int][]int)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
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
				ppid, _ = strconv.Atoi(fields[1])
			}
			break
		}
		if ppid < 0 {
			continue
		}
		ppids[pid] = ppid
		children[ppid] = append(children[ppid], pid)
	}
	for pid := range children {
		sort.Ints(children[pid])
	}
	return ppids, children, nil
}

func readRuntimeProcSnapshot(pid int, ppid int, connections map[string]runtimeConnection) (runtimeProcSnapshot, error) {
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return runtimeProcSnapshot{}, err
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return runtimeProcSnapshot{}, err
	}
	files, conns := scanProcessDescriptors(pid, connections)
	return runtimeProcSnapshot{PID: pid, PPID: ppid, Comm: strings.TrimSpace(string(commBytes)), Exe: exePath, Files: files, Connections: conns}, nil
}

func scanProcessDescriptors(pid int, connections map[string]runtimeConnection) (map[string]struct{}, map[string]runtimeConnection) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return map[string]struct{}{}, map[string]runtimeConnection{}
	}
	files := make(map[string]struct{})
	conns := make(map[string]runtimeConnection)
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := parseSocketInode(target); ok {
			if conn, exists := connections[inode]; exists {
				conns[inode] = conn
			}
			continue
		}
		if !strings.HasPrefix(target, "/") {
			continue
		}
		if strings.HasPrefix(target, "/proc/") || strings.HasPrefix(target, "/sys/") || strings.HasPrefix(target, "/dev/") {
			continue
		}
		files[target] = struct{}{}
	}
	return files, conns
}

func parseSocketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), true
}

func parseProcNetTCPFile(path string) (map[string]runtimeConnection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	connections := make(map[string]runtimeConnection)
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		if state == "0A" {
			continue
		}
		host, port, err := decodeIPv4Address(fields[2])
		if err != nil || host == "0.0.0.0" || port == 0 {
			continue
		}
		inode := fields[9]
		connections[inode] = runtimeConnection{DstIP: host, DstPort: port, State: state, Inode: inode}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return connections, nil
}

func decodeIPv4Address(value string) (string, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", value)
	}
	addrBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(addrBytes) != 4 {
		return "", 0, fmt.Errorf("invalid IPv4 address: %s", parts[0])
	}
	portValue, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", parts[1])
	}
	ip := net.IPv4(addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]).String()
	return ip, uint16(portValue), nil
}

func intPtr(v int) *int { return &v }

func truncateStatusDetail(s string) string {
	if len(s) <= 160 {
		return s
	}
	return s[:160]
}

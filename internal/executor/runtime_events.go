package executor

import (
	"fmt"
	"sort"
	"time"

	"aegis/internal/models"
	"aegis/internal/observability"
	"aegis/internal/telemetry"
)

const (
	guestRuntimeEventBatchKind   = "guest.runtime.event.batch.v1"
	guestRuntimeSensorStatusKind = "guest.runtime.sensor.status.v1"
)

type guestRuntimeEvent struct {
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

type guestRuntimeEventBatch struct {
	Events        []guestRuntimeEvent `json:"events"`
	Dropped       uint32              `json:"dropped"`
	FloodDetected bool                `json:"flood_detected,omitempty"`
	QueueCapacity int                 `json:"queue_capacity,omitempty"`
}

type guestRuntimeSensorStatus struct {
	DroppedEvents uint64 `json:"dropped_events"`
	FloodDetected bool   `json:"flood_detected"`
	QueueCapacity int    `json:"queue_capacity,omitempty"`
	BatchEvents   int    `json:"batch_events,omitempty"`
	Source        string `json:"source,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type runtimeEventNormalizer struct {
	executionID string
	seq         uint64
}

func newRuntimeEventNormalizer(executionID string) *runtimeEventNormalizer {
	return &runtimeEventNormalizer{executionID: executionID}
}

func (n *runtimeEventNormalizer) emitBatch(batch guestRuntimeEventBatch, bus *telemetry.Bus) error {
	observability.Info("runtime_batch_received", observability.Fields{
		"execution_id":   n.executionID,
		"events":         len(batch.Events),
		"dropped":        batch.Dropped,
		"flood_detected": batch.FloodDetected,
	})

	if len(batch.Events) == 0 {
		if batch.Dropped > 0 || batch.FloodDetected {
			emitIfBus(bus, telemetry.KindRuntimeSensorStatus, telemetry.RuntimeSensorStatusData{
				DroppedEvents: uint64(batch.Dropped),
				FloodDetected: batch.FloodDetected,
				QueueCapacity: batch.QueueCapacity,
				Source:        "guest-runtime-sensor",
				Detail:        "empty-batch",
			})
		}
		return nil
	}

	dropped := batch.Dropped
	for _, raw := range batch.Events {
		event, err := n.normalize(raw, dropped)
		if err != nil {
			observability.Warn("runtime_normalize_failed", observability.Fields{
				"execution_id": n.executionID,
				"type":         raw.Type,
				"error":        err.Error(),
			})
			return err
		}
		dropped = 0
		emitIfBus(bus, telemetry.KindRuntimeEvent, event)
		observability.Info("runtime_event", observability.Fields{
			"execution_id":       event.ExecutionID,
			"backend":            event.Backend,
			"seq":                event.Seq,
			"type":               event.Type,
			"pid":                event.PID,
			"path":               event.Path,
			"dst_ip":             event.DstIP,
			"dst_port":           event.DstPort,
			"dropped_since_last": event.DroppedSinceLast,
		})
	}

	if batch.Dropped > 0 || batch.FloodDetected {
		emitIfBus(bus, telemetry.KindRuntimeSensorStatus, telemetry.RuntimeSensorStatusData{
			DroppedEvents: uint64(batch.Dropped),
			FloodDetected: batch.FloodDetected,
			QueueCapacity: batch.QueueCapacity,
			BatchEvents:   len(batch.Events),
			Source:        "guest-runtime-sensor",
			Detail:        "batch-drop-accounting",
		})
	}

	return nil
}

func (n *runtimeEventNormalizer) emitStatus(status guestRuntimeSensorStatus, bus *telemetry.Bus) {
	observability.Info("runtime_sensor_status", observability.Fields{
		"execution_id":   n.executionID,
		"source":         status.Source,
		"detail":         status.Detail,
		"dropped":        status.DroppedEvents,
		"flood_detected": status.FloodDetected,
		"batch_events":   status.BatchEvents,
	})
	emitIfBus(bus, telemetry.KindRuntimeSensorStatus, telemetry.RuntimeSensorStatusData{
		DroppedEvents: status.DroppedEvents,
		FloodDetected: status.FloodDetected,
		QueueCapacity: status.QueueCapacity,
		BatchEvents:   status.BatchEvents,
		Source:        status.Source,
		Detail:        status.Detail,
	})
}

func (n *runtimeEventNormalizer) normalize(raw guestRuntimeEvent, dropped uint32) (models.RuntimeEvent, error) {
	eventType, err := normalizeRuntimeEventType(raw.Type)
	if err != nil {
		return models.RuntimeEvent{}, err
	}

	ts := raw.TsUnixNano
	if ts == 0 {
		ts = time.Now().UnixNano()
	}

	event := models.RuntimeEvent{
		ExecutionID:      n.executionID,
		Backend:          models.BackendFirecracker,
		Seq:              n.nextSeq(),
		TsUnixNano:       ts,
		DroppedSinceLast: dropped,
		Type:             eventType,
		PID:              raw.PID,
		PPID:             raw.PPID,
		Comm:             raw.Comm,
		Exe:              raw.Exe,
		Path:             raw.Path,
		Flags:            raw.Flags,
		DstIP:            raw.DstIP,
		DstPort:          raw.DstPort,
		Domain:           "",
		ExitCode:         -1,
		Metadata:         cloneStringMap(raw.Metadata),
	}
	if raw.ExitCode != nil {
		event.ExitCode = *raw.ExitCode
	}
	return event, nil
}

func (n *runtimeEventNormalizer) nextSeq() uint64 {
	n.seq++
	return n.seq
}

func normalizeRuntimeEventType(value string) (models.EventType, error) {
	switch models.EventType(value) {
	case models.EventProcessExec,
		models.EventProcessFork,
		models.EventProcessExit,
		models.EventFileOpen,
		models.EventNetConnect:
		return models.EventType(value), nil
	default:
		return "", fmt.Errorf("unknown runtime event type: %s", value)
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	keys := make([]string, 0, len(src))
	for key := range src {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	dst := make(map[string]string, len(src))
	for _, key := range keys {
		dst[key] = src[key]
	}
	return dst
}

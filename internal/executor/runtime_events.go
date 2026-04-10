package executor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"aegis/internal/models"
	"aegis/internal/observability"
	policydivergence "aegis/internal/policy/divergence"
	policyevaluator "aegis/internal/policy/evaluator"
	"aegis/internal/telemetry"
)

const (
	guestRuntimeEventBatchKind   = "guest.runtime.event.batch.v1"
	guestRuntimeSensorStatusKind = "guest.runtime.sensor.status.v1"
	runtimeSecurityDeniedSymlink = "security_denied_symlink_open"
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
	executionID         string
	seq                 uint64
	pointEvaluator      *policyevaluator.Evaluator
	divergenceEvaluator *policydivergence.Evaluator
	enforce             func(models.PolicyDivergenceResult) error
	enforced            bool
	enforcementExitCode int
	enforcementReason   string
}

func newRuntimeEventNormalizer(executionID string, pointEvaluator *policyevaluator.Evaluator, divergenceEvaluator *policydivergence.Evaluator, enforce func(models.PolicyDivergenceResult) error) *runtimeEventNormalizer {
	return &runtimeEventNormalizer{executionID: executionID, pointEvaluator: pointEvaluator, divergenceEvaluator: divergenceEvaluator, enforce: enforce}
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
			"flags":              event.Flags,
			"dst_ip":             event.DstIP,
			"dst_port":           event.DstPort,
			"dropped_since_last": event.DroppedSinceLast,
		})
		var decision *models.PolicyPointDecision
		if n.pointEvaluator != nil {
			point := n.pointEvaluator.Evaluate(event)
			decision = &point
			emitIfBus(bus, telemetry.KindPolicyPointDecision, point)
			observability.Info("policy_point_decision", observability.Fields{
				"execution_id": point.ExecutionID,
				"seq":          point.EventSeq,
				"event_type":   point.EventType,
				"action":       point.CedarAction,
				"decision":     point.Decision,
				"reason":       point.Reason,
			})
		}
		if n.divergenceEvaluator != nil {
			outcome := n.divergenceEvaluator.Observe(event, decision)
			emitIfBus(bus, telemetry.KindPolicyDivergence, outcome.Result)
			observability.Info("policy_divergence_update", observability.Fields{
				"execution_id": outcome.Result.ExecutionID,
				"seq":          outcome.Result.LastSeq,
				"verdict":      outcome.Result.CurrentVerdict,
				"rule_count":   len(outcome.Result.TriggeredRules),
			})
			for _, hit := range outcome.NewRuleHits {
				observability.Info("policy_divergence_rule_hit", observability.Fields{
					"execution_id": outcome.Result.ExecutionID,
					"seq":          hit.EventSeq,
					"rule_id":      hit.RuleID,
					"reason":       hit.Message,
					"severity":     hit.Severity,
				})
			}
			if outcome.VerdictChanged {
				observability.Info("policy_divergence_verdict", observability.Fields{
					"execution_id": outcome.Result.ExecutionID,
					"seq":          outcome.Result.LastSeq,
					"verdict":      outcome.Result.CurrentVerdict,
				})
			}
			if outcome.Result.CurrentVerdict == models.DivergenceKillCandidate && !n.enforced && n.enforce != nil {
				ruleID := ""
				reason := "kill_candidate reached"
				if len(outcome.NewRuleHits) > 0 {
					ruleID = outcome.NewRuleHits[0].RuleID
					reason = outcome.NewRuleHits[0].Message
				} else if len(outcome.Result.TriggeredRules) > 0 {
					last := outcome.Result.TriggeredRules[len(outcome.Result.TriggeredRules)-1]
					ruleID = last.RuleID
					reason = last.Message
				}
				observability.Warn("policy_enforcement_triggered", observability.Fields{
					"execution_id": outcome.Result.ExecutionID,
					"seq":          outcome.Result.LastSeq,
					"verdict":      outcome.Result.CurrentVerdict,
					"rule_id":      ruleID,
					"reason":       reason,
					"action":       "kill_firecracker_vm",
				})
				emitIfBus(bus, telemetry.KindPolicyEnforcement, telemetry.PolicyEnforcementData{
					ExecutionID: outcome.Result.ExecutionID,
					Seq:         outcome.Result.LastSeq,
					Verdict:     string(outcome.Result.CurrentVerdict),
					Action:      "kill_firecracker_vm",
					RuleID:      ruleID,
					Reason:      reason,
				})
				if err := n.enforce(outcome.Result); err != nil {
					return fmt.Errorf("enforce divergence kill candidate: %w", err)
				}
				n.enforced = true
				n.enforcementExitCode = 137
				n.enforcementReason = "divergence_terminated"
			}
		}
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
	if !n.enforced && status.Source == "guest-runtime-trace" && strings.HasPrefix(status.Detail, "blocked-symlink-open ") {
		n.enforced = true
		n.enforcementExitCode = 137
		n.enforcementReason = runtimeSecurityDeniedSymlink
		observability.Warn("runtime_security_denial", observability.Fields{
			"execution_id": n.executionID,
			"reason":       n.enforcementReason,
			"detail":       status.Detail,
		})
		emitIfBus(bus, telemetry.KindPolicyEnforcement, telemetry.PolicyEnforcementData{
			ExecutionID: n.executionID,
			Verdict:     "security_denied",
			Action:      "kill_guest_process",
			RuleID:      "file.symlink_race_denied",
			Reason:      status.Detail,
		})
	}
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

func (n *runtimeEventNormalizer) enforcedResult() (models.Result, bool) {
	if !n.enforced {
		return models.Result{}, false
	}
	return models.Result{ExitCode: n.enforcementExitCode, ExitReason: n.enforcementReason}, true
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

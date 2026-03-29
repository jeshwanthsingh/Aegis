package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

func newHistogram(b []float64) histogram {
	return histogram{buckets: append([]float64(nil), b...), counts: make([]uint64, len(b))}
}

func (h *histogram) observe(v float64) {
	h.count++
	h.sum += v
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

type registry struct {
	mu                  sync.Mutex
	executionsTotal     map[string]uint64
	executionDuration   histogram
	bootDuration        histogram
	teardownDuration    histogram
	workerSlotsProvider func() int
}

var metrics = &registry{
	executionsTotal:   map[string]uint64{},
	executionDuration: newHistogram([]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 60}),
	bootDuration:      newHistogram([]float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 60}),
	teardownDuration:  newHistogram([]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}),
}

func SetWorkerSlotsFunc(fn func() int) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.workerSlotsProvider = fn
}

func RecordExecution(status string, d time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.executionsTotal[status]++
	metrics.executionDuration.observe(d.Seconds())
}

func ObserveBootDuration(d time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.bootDuration.observe(d.Seconds())
}

func ObserveTeardownDuration(d time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.teardownDuration.observe(d.Seconds())
}

func HandleMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(renderMetrics()))
	}
}

func renderMetrics() string {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	var b strings.Builder
	b.WriteString("# HELP aegis_executions_total Total executions by terminal status\n")
	b.WriteString("# TYPE aegis_executions_total counter\n")
	statuses := make([]string, 0, len(metrics.executionsTotal))
	for status := range metrics.executionsTotal {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	for _, status := range statuses {
		fmt.Fprintf(&b, "aegis_executions_total{status=%q} %d\n", status, metrics.executionsTotal[status])
	}

	writeHistogram(&b, "aegis_execution_duration_seconds", "Execution duration in seconds", metrics.executionDuration)
	writeHistogram(&b, "aegis_boot_duration_seconds", "Boot-to-vsock duration in seconds", metrics.bootDuration)
	writeHistogram(&b, "aegis_teardown_duration_seconds", "Teardown duration in seconds", metrics.teardownDuration)

	b.WriteString("# HELP aegis_worker_slots_available Available worker slots\n")
	b.WriteString("# TYPE aegis_worker_slots_available gauge\n")
	workerSlots := 0
	if metrics.workerSlotsProvider != nil {
		workerSlots = metrics.workerSlotsProvider()
	}
	fmt.Fprintf(&b, "aegis_worker_slots_available %d\n", workerSlots)
	return b.String()
}

func writeHistogram(b *strings.Builder, name, help string, h histogram) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s histogram\n", name)
	for i, bucket := range h.buckets {
		fmt.Fprintf(b, "%s_bucket{le=%q} %d\n", name, formatBucket(bucket), h.counts[i])
	}
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", name, h.count)
	fmt.Fprintf(b, "%s_sum %.6f\n", name, h.sum)
	fmt.Fprintf(b, "%s_count %d\n", name, h.count)
}

func formatBucket(v float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", v), "0"), ".")
}

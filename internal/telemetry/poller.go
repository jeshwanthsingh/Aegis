package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultCgroupBasePath = "/sys/fs/cgroup"

// StartCgroupPoller starts sampling cgroup pseudo-files for a specific execution.
func StartCgroupPoller(ctx context.Context, bus *Bus, execID string, interval time.Duration) func() {
	return startCgroupPoller(ctx, bus, execID, interval, defaultCgroupBasePath)
}

func startCgroupPoller(ctx context.Context, bus *Bus, execID string, interval time.Duration, basePath string) func() {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}

	stopCh := make(chan struct{})
	var stopOnce sync.Once

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				sample, ok := readCgroupSample(basePath, execID)
				if !ok {
					return
				}
				bus.Emit(KindCgroupSample, sample)
			}
		}
	}()

	return func() {
		stopOnce.Do(func() {
			close(stopCh)
		})
	}
}

func readCgroupSample(basePath, execID string) (CgroupSampleData, bool) {
	cgroupPath := filepath.Join(basePath, "aegis", execID)

	memoryCurrent, ok := readCgroupInt(filepath.Join(cgroupPath, "memory.current"))
	if !ok {
		return CgroupSampleData{}, false
	}

	memoryMax, ok := readCgroupInt(filepath.Join(cgroupPath, "memory.max"))
	if !ok {
		return CgroupSampleData{}, false
	}

	pidsCurrent, ok := readCgroupInt(filepath.Join(cgroupPath, "pids.current"))
	if !ok {
		return CgroupSampleData{}, false
	}

	pidsMax, ok := readCgroupInt(filepath.Join(cgroupPath, "pids.max"))
	if !ok {
		return CgroupSampleData{}, false
	}

	return CgroupSampleData{
		MemoryCurrent: memoryCurrent,
		MemoryMax:     memoryMax,
		PidsCurrent:   pidsCurrent,
		PidsMax:       pidsMax,
		MemoryPct:     percentage(memoryCurrent, memoryMax),
		PidsPct:       percentage(pidsCurrent, pidsMax),
	}, true
}

func readCgroupInt(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}

	value := strings.TrimSpace(string(raw))
	if value == "max" {
		return 0, true
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}

	return parsed, true
}

func percentage(current, max int64) float64 {
	if max <= 0 {
		return 0
	}

	return (float64(current) / float64(max)) * 100
}

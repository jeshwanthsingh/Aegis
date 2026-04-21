package observability

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Fields map[string]any

var (
	logMu        sync.Mutex
	stdoutWriter io.Writer = os.Stdout
	stderrWriter io.Writer = os.Stderr
)

func Info(event string, fields Fields)  { write("info", event, fields) }
func Warn(event string, fields Fields)  { write("warn", event, fields) }
func Error(event string, fields Fields) { write("error", event, fields) }
func Fatal(event string, fields Fields) { write("fatal", event, fields); os.Exit(1) }

func SetWriters(stdout io.Writer, stderr io.Writer) func() {
	logMu.Lock()
	prevStdout := stdoutWriter
	prevStderr := stderrWriter
	if stdout != nil {
		stdoutWriter = stdout
	}
	if stderr != nil {
		stderrWriter = stderr
	}
	logMu.Unlock()
	return func() {
		logMu.Lock()
		stdoutWriter = prevStdout
		stderrWriter = prevStderr
		logMu.Unlock()
	}
}

func write(level, event string, fields Fields) {
	rec := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "level": level, "event": event}
	for k, v := range fields {
		rec[k] = v
	}
	line, err := json.Marshal(rec)
	if err != nil {
		line = []byte(fmt.Sprintf(`{"ts":%q,"level":%q,"event":"log_encode_failed","error":%q}`, time.Now().UTC().Format(time.RFC3339Nano), "error", err.Error()))
	}
	logMu.Lock()
	defer logMu.Unlock()
	out := stdoutWriter
	if level == "error" || level == "fatal" {
		out = stderrWriter
	}
	_, _ = out.Write(append(line, '\n'))
}

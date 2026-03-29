package observability

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Fields map[string]any

var logMu sync.Mutex

func Info(event string, fields Fields)  { write("info", event, fields) }
func Warn(event string, fields Fields)  { write("warn", event, fields) }
func Error(event string, fields Fields) { write("error", event, fields) }
func Fatal(event string, fields Fields) { write("fatal", event, fields); os.Exit(1) }

func write(level, event string, fields Fields) {
	rec := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "level": level, "event": event}
	for k, v := range fields {
		rec[k] = v
	}
	line, err := json.Marshal(rec)
	if err != nil {
		line = []byte(fmt.Sprintf(`{"ts":%q,"level":%q,"event":"log_encode_failed","error":%q}`, time.Now().UTC().Format(time.RFC3339Nano), "error", err.Error()))
	}
	out := os.Stdout
	if level == "error" || level == "fatal" {
		out = os.Stderr
	}
	logMu.Lock()
	defer logMu.Unlock()
	_, _ = out.Write(append(line, '\n'))
}

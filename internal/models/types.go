package models

type Payload struct {
	Lang string `json:"lang"`
	Code string `json:"code"`
}

type GuestChunk struct {
	Type       string `json:"type"`
	Chunk      string `json:"chunk,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	StdoutBytes     int    `json:"stdout_bytes"`
	StderrBytes     int    `json:"stderr_bytes"`
}
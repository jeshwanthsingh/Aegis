package models

type Payload struct {
	Lang string `json:"lang"`
	Code string `json:"code"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	StdoutBytes     int    `json:"stdout_bytes"`
	StderrBytes     int    `json:"stderr_bytes"`
}

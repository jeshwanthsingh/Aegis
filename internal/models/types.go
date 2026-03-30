package models

type Payload struct {
	Lang               string `json:"lang"`
	Code               string `json:"code"`
	TimeoutMs          int    `json:"timeout_ms"`
	WorkspaceRequested bool   `json:"workspace_requested,omitempty"`
	NetworkRequested   bool   `json:"network_requested,omitempty"`
	GuestIP            string `json:"guest_ip,omitempty"`
	GatewayIP          string `json:"gateway_ip,omitempty"`
	DNSServer          string `json:"dns_server,omitempty"`
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

package models

import "encoding/json"

type Payload struct {
	Lang               string `json:"lang"`
	Code               string `json:"code"`
	TimeoutMs          int    `json:"timeout_ms"`
	PidsLimit          int    `json:"pids_limit,omitempty"`
	WorkspaceRequested bool   `json:"workspace_requested,omitempty"`
	NetworkRequested   bool   `json:"network_requested,omitempty"`
	GuestIP            string `json:"guest_ip,omitempty"`
	GatewayIP          string `json:"gateway_ip,omitempty"`
	DNSServer          string `json:"dns_server,omitempty"`
}

type GuestChunk struct {
	Type                 string          `json:"type"`
	Name                 string          `json:"name,omitempty"`
	Data                 json.RawMessage `json:"data,omitempty"`
	Chunk                string          `json:"chunk,omitempty"`
	ExitCode             int             `json:"exit_code,omitempty"`
	Reason               string          `json:"reason,omitempty"`
	DurationMs           int64           `json:"duration_ms,omitempty"`
	Error                string          `json:"error,omitempty"`
	ExecutionID          string          `json:"execution_id,omitempty"`
	ProofDir             string          `json:"proof_dir,omitempty"`
	ReceiptPath          string          `json:"receipt_path,omitempty"`
	ReceiptPublicKeyPath string          `json:"receipt_public_key_path,omitempty"`
	ReceiptSummaryPath   string          `json:"receipt_summary_path,omitempty"`
	ArtifactCount        int             `json:"artifact_count,omitempty"`
	DivergenceVerdict    string          `json:"divergence_verdict,omitempty"`
}

type Result struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	ExitReason      string `json:"exit_reason,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	StdoutBytes     int    `json:"stdout_bytes"`
	StderrBytes     int    `json:"stderr_bytes"`
}

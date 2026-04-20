export type DemoKey = "clean" | "exfil" | "broker";

export interface ExecuteRequest {
  execution_id: string;
  lang: string;
  code: string;
  timeout_ms: number;
  profile?: string;
  intent?: unknown;
}

export interface GuestChunk {
  type: string;
  chunk?: string;
  exit_code?: number;
  reason?: string;
  duration_ms?: number;
  error?: string;
  execution_id?: string;
  proof_dir?: string;
  receipt_path?: string;
  receipt_public_key_path?: string;
  receipt_summary_path?: string;
  artifact_count?: number;
  divergence_verdict?: string;
}

export interface TelemetryEvent {
  exec_id: string;
  ts: number;
  kind: string;
  data: unknown;
}

export interface SignedReceipt {
  statement: {
    predicate: ReceiptPredicate;
  };
}

export interface ReceiptPredicate {
  version: string;
  execution_id: string;
  execution_status?: string;
  policy_digest?: string;
  evidence_digest: string;
  result_class: string;
  started_at: string;
  finished_at: string;
  backend: string;
  divergence: {
    verdict: string;
    triggered_rule_ids?: string[];
    rule_hit_count: number;
  };
  outcome: {
    exit_code?: number;
    reason?: string;
    containment_verdict?: string;
    output_truncated?: boolean;
    ExitCode?: number;
    Reason?: string;
    ContainmentVerdict?: string;
    OutputTruncated?: boolean;
  };
  trust: {
    signing_mode: string;
    key_source: string;
    attestation: string;
    verification_material: string;
    limitations?: string[];
  };
  policy?: {
    baseline: {
      language: string;
      code_size_bytes: number;
      max_code_bytes: number;
      timeout_ms: number;
      max_timeout_ms: number;
      profile?: string;
      network?: {
        mode: string;
        presets?: string[];
      };
    };
    intent?: {
      digest: string;
      source?: string;
    };
  };
  runtime?: {
    profile?: string;
    vcpu_count?: number;
    memory_mb?: number;
    cgroup?: {
      memory_max_mb?: number;
      memory_high_mb?: number;
      pids_max?: number;
      cpu_max?: string;
      swap_max?: string;
    };
    network?: {
      enabled: boolean;
      mode: string;
      presets?: string[];
    };
    broker?: {
      enabled: boolean;
    };
    applied_overrides?: string[];
  };
  broker_summary?: {
    request_count: number;
    allowed_count: number;
    denied_count: number;
    domains_allowed?: string[];
    domains_denied?: string[];
    bindings_used?: string[];
  };
  governed_actions?: {
    count: number;
    normalized?: GovernedAction[];
    actions?: GovernedAction[];
  };
}

export interface GovernedAction {
  count?: number;
  action_type: string;
  target: string;
  resource?: string;
  method?: string;
  capability_path?: string;
  decision: string;
  outcome?: string;
  used: boolean;
  reason?: string;
  rule_id?: string;
  policy_digest?: string;
  brokered: boolean;
  brokered_credentials: boolean;
  binding_name?: string;
  denial_marker?: string;
  error?: string;
}

export interface ExecutionViewModel {
  executionId: string;
  status: "idle" | "submitting" | "running" | "completed" | "failed";
  stdout: string;
  stderr: string;
  exitCode?: number;
  durationMs?: number;
  streamError?: string;
  proofDir?: string;
  receiptPath?: string;
  receiptSummaryPath?: string;
  divergenceVerdict?: string;
  receipt?: SignedReceipt;
  governedEvents: GovernedAction[];
}

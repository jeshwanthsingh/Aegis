import { ProofBundle } from "./types.js";

export class StreamEvent {
  readonly type: string;
  readonly raw: Record<string, unknown>;

  constructor(type: string, raw: Record<string, unknown>) {
    this.type = type;
    this.raw = raw;
  }
}

export class StdoutEvent extends StreamEvent {
  readonly chunk: string;

  constructor(raw: Record<string, unknown>) {
    super("stdout", raw);
    this.chunk = typeof raw.chunk === "string" ? raw.chunk : "";
  }
}

export class StderrEvent extends StreamEvent {
  readonly chunk: string;

  constructor(raw: Record<string, unknown>) {
    super("stderr", raw);
    this.chunk = typeof raw.chunk === "string" ? raw.chunk : "";
  }
}

export class ProofEvent extends StreamEvent {
  readonly executionId?: string;
  readonly proofBundle: ProofBundle;
  readonly artifactCount: number;
  readonly divergenceVerdict?: string;

  constructor(raw: Record<string, unknown>) {
    super("proof", raw);
    this.executionId = typeof raw.execution_id === "string" ? raw.execution_id : undefined;
    this.proofBundle = new ProofBundle({
      proofDir: typeof raw.proof_dir === "string" ? raw.proof_dir : undefined,
      receiptPath: typeof raw.receipt_path === "string" ? raw.receipt_path : undefined,
      receiptPublicKeyPath: typeof raw.receipt_public_key_path === "string" ? raw.receipt_public_key_path : undefined,
      receiptSummaryPath: typeof raw.receipt_summary_path === "string" ? raw.receipt_summary_path : undefined,
    });
    this.artifactCount = typeof raw.artifact_count === "number" ? raw.artifact_count : 0;
    this.divergenceVerdict = typeof raw.divergence_verdict === "string" ? raw.divergence_verdict : undefined;
  }
}

export class ErrorEvent extends StreamEvent {
  readonly error: string;

  constructor(raw: Record<string, unknown>) {
    super("error", raw);
    this.error = typeof raw.error === "string" ? raw.error : "";
  }
}

export class DoneEvent extends StreamEvent {
  readonly exitCode: number;
  readonly reason?: string;
  readonly durationMs: number;

  constructor(raw: Record<string, unknown>) {
    super("done", raw);
    this.exitCode = typeof raw.exit_code === "number" ? raw.exit_code : 0;
    this.reason = typeof raw.reason === "string" ? raw.reason : undefined;
    this.durationMs = typeof raw.duration_ms === "number" ? raw.duration_ms : 0;
  }

  get ok(): boolean {
    return this.exitCode === 0 && [undefined, "", "completed"].includes(this.reason);
  }
}

export type ParsedStreamEvent = StreamEvent | StdoutEvent | StderrEvent | ProofEvent | ErrorEvent | DoneEvent;

export function parseStreamEvent(raw: Record<string, unknown>): ParsedStreamEvent {
  const eventType = typeof raw.type === "string" ? raw.type : "unknown";
  if (eventType === "stdout") return new StdoutEvent(raw);
  if (eventType === "stderr") return new StderrEvent(raw);
  if (eventType === "proof") return new ProofEvent(raw);
  if (eventType === "error") return new ErrorEvent(raw);
  if (eventType === "done") return new DoneEvent(raw);
  return new StreamEvent(eventType, raw);
}

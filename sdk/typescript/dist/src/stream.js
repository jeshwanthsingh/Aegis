import { ProofBundle } from "./types.js";
export class StreamEvent {
    type;
    raw;
    constructor(type, raw) {
        this.type = type;
        this.raw = raw;
    }
}
export class StdoutEvent extends StreamEvent {
    chunk;
    constructor(raw) {
        super("stdout", raw);
        this.chunk = typeof raw.chunk === "string" ? raw.chunk : "";
    }
}
export class StderrEvent extends StreamEvent {
    chunk;
    constructor(raw) {
        super("stderr", raw);
        this.chunk = typeof raw.chunk === "string" ? raw.chunk : "";
    }
}
export class ProofEvent extends StreamEvent {
    executionId;
    proofBundle;
    artifactCount;
    divergenceVerdict;
    constructor(raw) {
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
    error;
    constructor(raw) {
        super("error", raw);
        this.error = typeof raw.error === "string" ? raw.error : "";
    }
}
export class DoneEvent extends StreamEvent {
    exitCode;
    reason;
    durationMs;
    constructor(raw) {
        super("done", raw);
        this.exitCode = typeof raw.exit_code === "number" ? raw.exit_code : 0;
        this.reason = typeof raw.reason === "string" ? raw.reason : undefined;
        this.durationMs = typeof raw.duration_ms === "number" ? raw.duration_ms : 0;
    }
    get ok() {
        return this.exitCode === 0 && [undefined, "", "completed"].includes(this.reason);
    }
}
export function parseStreamEvent(raw) {
    const eventType = typeof raw.type === "string" ? raw.type : "unknown";
    if (eventType === "stdout")
        return new StdoutEvent(raw);
    if (eventType === "stderr")
        return new StderrEvent(raw);
    if (eventType === "proof")
        return new ProofEvent(raw);
    if (eventType === "error")
        return new ErrorEvent(raw);
    if (eventType === "done")
        return new DoneEvent(raw);
    return new StreamEvent(eventType, raw);
}

import { AegisExecutionError, AegisVerificationError } from "./errors.js";
import { Receipt } from "./receipt.js";
import { ProofBundle } from "./types.js";
import { ReceiptVerification, ReceiptVerifier } from "./verifier.js";

export interface ExecutionResponse {
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  execution_id?: string;
  duration_ms?: number;
  exit_reason?: string;
  error?: string;
  output_truncated?: boolean;
  proof_dir?: string;
  receipt_path?: string;
  receipt_public_key_path?: string;
  receipt_summary_path?: string;
  [key: string]: unknown;
}

export class ExecutionResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
  readonly executionId: string;
  readonly durationMs: number;
  readonly exitReason?: string;
  readonly executionError?: string;
  readonly outputTruncated: boolean;
  readonly proofDir?: string;
  readonly receiptPath?: string;
  readonly receiptPublicKeyPath?: string;
  readonly receiptSummaryPath?: string;
  readonly rawResponse: Record<string, unknown>;
  private readonly verifier?: ReceiptVerifier;
  private receiptCache?: Receipt | null;

  constructor(input: {
    stdout: string;
    stderr: string;
    exitCode: number;
    executionId: string;
    durationMs: number;
    exitReason?: string;
    executionError?: string;
    outputTruncated: boolean;
    proofDir?: string;
    receiptPath?: string;
    receiptPublicKeyPath?: string;
    receiptSummaryPath?: string;
    rawResponse: Record<string, unknown>;
    verifier?: ReceiptVerifier;
  }) {
    this.stdout = input.stdout;
    this.stderr = input.stderr;
    this.exitCode = input.exitCode;
    this.executionId = input.executionId;
    this.durationMs = input.durationMs;
    this.exitReason = input.exitReason;
    this.executionError = input.executionError;
    this.outputTruncated = input.outputTruncated;
    this.proofDir = input.proofDir;
    this.receiptPath = input.receiptPath;
    this.receiptPublicKeyPath = input.receiptPublicKeyPath;
    this.receiptSummaryPath = input.receiptSummaryPath;
    this.rawResponse = input.rawResponse;
    this.verifier = input.verifier;
  }

  static fromPayload(payload: ExecutionResponse, verifier?: ReceiptVerifier): ExecutionResult {
    return new ExecutionResult({
      stdout: typeof payload.stdout === "string" ? payload.stdout : "",
      stderr: typeof payload.stderr === "string" ? payload.stderr : "",
      exitCode: typeof payload.exit_code === "number" ? payload.exit_code : 0,
      executionId: typeof payload.execution_id === "string" ? payload.execution_id : "",
      durationMs: typeof payload.duration_ms === "number" ? payload.duration_ms : 0,
      exitReason: typeof payload.exit_reason === "string" ? payload.exit_reason : undefined,
      executionError: typeof payload.error === "string" ? payload.error : undefined,
      outputTruncated: Boolean(payload.output_truncated),
      proofDir: typeof payload.proof_dir === "string" ? payload.proof_dir : undefined,
      receiptPath: typeof payload.receipt_path === "string" ? payload.receipt_path : undefined,
      receiptPublicKeyPath: typeof payload.receipt_public_key_path === "string" ? payload.receipt_public_key_path : undefined,
      receiptSummaryPath: typeof payload.receipt_summary_path === "string" ? payload.receipt_summary_path : undefined,
      rawResponse: { ...payload },
      verifier,
    });
  }

  get proofBundle(): ProofBundle {
    return new ProofBundle({
      proofDir: this.proofDir,
      receiptPath: this.receiptPath,
      receiptPublicKeyPath: this.receiptPublicKeyPath,
      receiptSummaryPath: this.receiptSummaryPath,
    });
  }

  get executionFailed(): boolean {
    if (this.executionError) return true;
    if (this.exitCode !== 0) return true;
    return ![undefined, "", "completed"].includes(this.exitReason);
  }

  get ok(): boolean {
    return !this.executionFailed;
  }

  get error(): string | undefined {
    if (this.executionError) return this.executionError;
    if (this.exitCode !== 0) return `process exited with code ${this.exitCode}`;
    if (this.exitReason && this.exitReason !== "completed") return this.exitReason;
    return undefined;
  }

  get receipt(): Receipt | undefined {
    if (this.receiptCache !== undefined) return this.receiptCache ?? undefined;
    if (!this.receiptPath) {
      this.receiptCache = null;
      return undefined;
    }
    try {
      this.receiptCache = Receipt.load(this.receiptPath, {
        publicKeyPath: this.receiptPublicKeyPath,
        summaryPath: this.receiptSummaryPath,
        verifier: this.verifier,
      });
    } catch {
      this.receiptCache = null;
    }
    return this.receiptCache ?? undefined;
  }

  requireReceipt(): Receipt {
    const receipt = this.receipt;
    if (!receipt) throw new AegisVerificationError("execution result does not include a readable receipt");
    return receipt;
  }

  async verifyReceipt(): Promise<ReceiptVerification> {
    return this.requireReceipt().verify();
  }

  throwIfExecutionFailed(): void {
    if (!this.executionFailed) return;
    throw new AegisExecutionError(this.error ?? "execution failed", {
      executionId: this.executionId,
      exitCode: this.exitCode,
      exitReason: this.exitReason,
      rawResponse: this.rawResponse,
    });
  }
}

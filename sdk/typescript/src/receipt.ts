import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { ReceiptVerification, ReceiptVerifier } from "./verifier.js";

export class Receipt {
  readonly path: string;
  readonly raw: Record<string, unknown>;
  readonly publicKeyPath?: string;
  readonly summaryPath?: string;
  private readonly verifier?: ReceiptVerifier;

  constructor(input: { path: string; raw: Record<string, unknown>; publicKeyPath?: string; summaryPath?: string; verifier?: ReceiptVerifier }) {
    this.path = input.path;
    this.raw = input.raw;
    this.publicKeyPath = input.publicKeyPath;
    this.summaryPath = input.summaryPath;
    this.verifier = input.verifier;
  }

  static load(path: string, options: { publicKeyPath?: string; summaryPath?: string; verifier?: ReceiptVerifier } = {}): Receipt {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    let publicKeyPath = options.publicKeyPath;
    let summaryPath = options.summaryPath;
    if (!publicKeyPath) {
      const inferred = join(dirname(path), "receipt.pub");
      if (existsSync(inferred)) publicKeyPath = inferred;
    }
    if (!summaryPath) {
      const inferred = join(dirname(path), "receipt.summary.txt");
      if (existsSync(inferred)) summaryPath = inferred;
    }
    return new Receipt({ path, raw, publicKeyPath, summaryPath, verifier: options.verifier });
  }

  get proofDir(): string {
    return dirname(this.path);
  }

  get statement(): Record<string, unknown> {
    const statement = this.raw.statement;
    return statement && typeof statement === "object" ? { ...(statement as Record<string, unknown>) } : {};
  }

  get predicate(): Record<string, unknown> {
    const predicate = this.statement.predicate;
    return predicate && typeof predicate === "object" ? { ...(predicate as Record<string, unknown>) } : {};
  }

  get executionId(): string | undefined {
    return typeof this.predicate.execution_id === "string" ? this.predicate.execution_id : undefined;
  }

  get resultClass(): string | undefined {
    return typeof this.predicate.result_class === "string" ? this.predicate.result_class : undefined;
  }

  get divergenceVerdict(): string | undefined {
    const divergence = this.predicate.divergence;
    if (divergence && typeof divergence === "object" && typeof (divergence as Record<string, unknown>).verdict === "string") {
      return (divergence as Record<string, unknown>).verdict as string;
    }
    return undefined;
  }

  get signingMode(): string | undefined {
    const trust = this.predicate.trust;
    if (trust && typeof trust === "object" && typeof (trust as Record<string, unknown>).signing_mode === "string") {
      return (trust as Record<string, unknown>).signing_mode as string;
    }
    return undefined;
  }

  get keySource(): string | undefined {
    const trust = this.predicate.trust;
    if (trust && typeof trust === "object" && typeof (trust as Record<string, unknown>).key_source === "string") {
      return (trust as Record<string, unknown>).key_source as string;
    }
    return undefined;
  }

  get summaryText(): string | undefined {
    if (!this.summaryPath || !existsSync(this.summaryPath)) return undefined;
    return readFileSync(this.summaryPath, "utf8");
  }

  async verify(): Promise<ReceiptVerification> {
    const verifier = this.verifier ?? new ReceiptVerifier();
    return verifier.verifyReceipt({ receiptPath: this.path, publicKeyPath: this.publicKeyPath });
  }
}

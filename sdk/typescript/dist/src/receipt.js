import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ReceiptVerifier } from "./verifier.js";
export class Receipt {
    path;
    raw;
    publicKeyPath;
    summaryPath;
    verifier;
    constructor(input) {
        this.path = input.path;
        this.raw = input.raw;
        this.publicKeyPath = input.publicKeyPath;
        this.summaryPath = input.summaryPath;
        this.verifier = input.verifier;
    }
    static load(path, options = {}) {
        const raw = JSON.parse(readFileSync(path, "utf8"));
        let publicKeyPath = options.publicKeyPath;
        let summaryPath = options.summaryPath;
        if (!publicKeyPath) {
            const inferred = join(dirname(path), "receipt.pub");
            if (existsSync(inferred))
                publicKeyPath = inferred;
        }
        if (!summaryPath) {
            const inferred = join(dirname(path), "receipt.summary.txt");
            if (existsSync(inferred))
                summaryPath = inferred;
        }
        return new Receipt({ path, raw, publicKeyPath, summaryPath, verifier: options.verifier });
    }
    get proofDir() {
        return dirname(this.path);
    }
    get statement() {
        const statement = this.raw.statement;
        return statement && typeof statement === "object" ? { ...statement } : {};
    }
    get predicate() {
        const predicate = this.statement.predicate;
        return predicate && typeof predicate === "object" ? { ...predicate } : {};
    }
    get executionId() {
        return typeof this.predicate.execution_id === "string" ? this.predicate.execution_id : undefined;
    }
    get resultClass() {
        return typeof this.predicate.result_class === "string" ? this.predicate.result_class : undefined;
    }
    get divergenceVerdict() {
        const divergence = this.predicate.divergence;
        if (divergence && typeof divergence === "object" && typeof divergence.verdict === "string") {
            return divergence.verdict;
        }
        return undefined;
    }
    get signingMode() {
        const trust = this.predicate.trust;
        if (trust && typeof trust === "object" && typeof trust.signing_mode === "string") {
            return trust.signing_mode;
        }
        return undefined;
    }
    get keySource() {
        const trust = this.predicate.trust;
        if (trust && typeof trust === "object" && typeof trust.key_source === "string") {
            return trust.key_source;
        }
        return undefined;
    }
    get summaryText() {
        if (!this.summaryPath || !existsSync(this.summaryPath))
            return undefined;
        return readFileSync(this.summaryPath, "utf8");
    }
    async verify() {
        const verifier = this.verifier ?? new ReceiptVerifier();
        return verifier.verifyReceipt({ receiptPath: this.path, publicKeyPath: this.publicKeyPath });
    }
}

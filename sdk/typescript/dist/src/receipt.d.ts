import { ReceiptVerification, ReceiptVerifier } from "./verifier.js";
export declare class Receipt {
    readonly path: string;
    readonly raw: Record<string, unknown>;
    readonly publicKeyPath?: string;
    readonly summaryPath?: string;
    private readonly verifier?;
    constructor(input: {
        path: string;
        raw: Record<string, unknown>;
        publicKeyPath?: string;
        summaryPath?: string;
        verifier?: ReceiptVerifier;
    });
    static load(path: string, options?: {
        publicKeyPath?: string;
        summaryPath?: string;
        verifier?: ReceiptVerifier;
    }): Receipt;
    get proofDir(): string;
    get statement(): Record<string, unknown>;
    get predicate(): Record<string, unknown>;
    get executionId(): string | undefined;
    get verdict(): string | undefined;
    get signingMode(): string | undefined;
    get keySource(): string | undefined;
    get summaryText(): string | undefined;
    verify(): Promise<ReceiptVerification>;
}

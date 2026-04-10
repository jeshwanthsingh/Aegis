export declare class ReceiptVerification {
    readonly verified: boolean;
    readonly summaryText: string;
    readonly fields: Record<string, string>;
    constructor(input: {
        verified: boolean;
        summaryText: string;
        fields: Record<string, string>;
    });
    get executionId(): string | undefined;
    get divergenceVerdict(): string | undefined;
    get signingMode(): string | undefined;
}
export interface VerifyReceiptOptions {
    receiptPath?: string;
    publicKeyPath?: string;
    proofDir?: string;
    executionId?: string;
}
export declare class ReceiptVerifier {
    private readonly cliPath?;
    constructor(options?: {
        cliPath?: string;
    });
    resolveCliPath(): string;
    verifyReceipt(options: VerifyReceiptOptions): Promise<ReceiptVerification>;
}
export declare function parseSummary(summaryText: string): Record<string, string>;

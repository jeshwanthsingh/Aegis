export declare class ConnectionPosture {
    readonly baseUrl: string;
    readonly baseUrlSource: string;
    readonly apiKeySource: string;
    readonly apiKeyConfigured: boolean;
    constructor(input: {
        baseUrl: string;
        baseUrlSource: string;
        apiKeySource: string;
        apiKeyConfigured: boolean;
    });
    get authenticated(): boolean;
}
export declare class HealthStatus {
    readonly status: string;
    readonly workerSlotsAvailable: number;
    readonly workerSlotsTotal: number;
    constructor(input: {
        status: string;
        workerSlotsAvailable: number;
        workerSlotsTotal: number;
    });
    get ok(): boolean;
}
export declare class ProofBundle {
    readonly proofDir?: string;
    readonly receiptPath?: string;
    readonly receiptPublicKeyPath?: string;
    readonly receiptSummaryPath?: string;
    constructor(input: {
        proofDir?: string;
        receiptPath?: string;
        receiptPublicKeyPath?: string;
        receiptSummaryPath?: string;
    });
}

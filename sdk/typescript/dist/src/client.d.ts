import { ConnectionPosture, HealthStatus } from "./types.js";
import { ExecutionRequest, type ExecutionRequestInit } from "./request.js";
import { ExecutionResult } from "./result.js";
import { type ParsedStreamEvent } from "./stream.js";
import { type VerifyReceiptOptions, type ReceiptVerification } from "./verifier.js";
export interface AegisClientOptions {
    baseUrl?: string;
    apiKey?: string;
    timeoutMs?: number;
    cliPath?: string;
}
export declare class AegisClient {
    readonly baseUrl: string;
    readonly apiKey?: string;
    readonly timeoutMs: number;
    readonly posture: ConnectionPosture;
    private readonly transport;
    private readonly verifier;
    constructor(options?: AegisClientOptions);
    health(): Promise<HealthStatus>;
    run(request: ExecutionRequest | ExecutionRequestInit): Promise<ExecutionResult>;
    runCode(request: ExecutionRequest | ExecutionRequestInit): Promise<ExecutionResult>;
    stream(request: ExecutionRequest | ExecutionRequestInit): AsyncIterable<ParsedStreamEvent>;
    runStream(request: ExecutionRequest | ExecutionRequestInit): AsyncIterable<ParsedStreamEvent>;
    verifyReceipt(options: VerifyReceiptOptions): Promise<ReceiptVerification>;
}

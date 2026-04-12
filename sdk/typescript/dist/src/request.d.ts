import { CapabilitiesRequest } from "./capabilities.js";
import { IntentContract } from "./intent.js";
export interface ExecutionRequestInit {
    language: string;
    code: string;
    timeoutMs?: number;
    intent?: IntentContract | Record<string, unknown>;
    capabilities?: CapabilitiesRequest | Record<string, unknown>;
    profile?: string;
    workspaceId?: string;
    executionId?: string;
}
export declare class ExecutionRequest {
    readonly language: string;
    readonly code: string;
    readonly timeoutMs?: number;
    readonly intent?: IntentContract | Record<string, unknown>;
    readonly capabilities?: CapabilitiesRequest | Record<string, unknown>;
    readonly profile?: string;
    readonly workspaceId?: string;
    readonly executionId?: string;
    constructor(init: ExecutionRequestInit);
    toPayload(): Record<string, unknown>;
}

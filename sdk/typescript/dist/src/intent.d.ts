export type RuntimeBackend = "firecracker" | "gvisor";
export type WireObject = Record<string, unknown>;
export declare class ResourceScope {
    readonly workspaceRoot: string;
    readonly readPaths: string[];
    readonly writePaths: string[];
    readonly denyPaths: string[];
    readonly maxDistinctFiles: number;
    constructor(workspaceRoot: string, readPaths?: string[], writePaths?: string[], denyPaths?: string[], maxDistinctFiles?: number);
    toWire(): WireObject;
}
export declare class NetworkScope {
    readonly allowNetwork: boolean;
    readonly allowedDomains: string[];
    readonly allowedIps: string[];
    readonly maxDnsQueries: number;
    readonly maxOutboundConns: number;
    constructor(allowNetwork: boolean, allowedDomains?: string[], allowedIps?: string[], maxDnsQueries?: number, maxOutboundConns?: number);
    toWire(): WireObject;
}
export declare class ProcessScope {
    readonly allowedBinaries: string[];
    readonly allowShell: boolean;
    readonly allowPackageInstall: boolean;
    readonly maxChildProcesses: number;
    constructor(allowedBinaries?: string[], allowShell?: boolean, allowPackageInstall?: boolean, maxChildProcesses?: number);
    toWire(): WireObject;
}
export declare class BrokerScope {
    readonly allowedDelegations: string[];
    readonly allowedDomains: string[];
    readonly allowedActionTypes: string[];
    readonly requireHostConsent: boolean;
    constructor(allowedDelegations?: string[], allowedDomains?: string[], allowedActionTypes?: string[], requireHostConsent?: boolean);
    toWire(): WireObject;
}
export declare class Budgets {
    readonly timeoutSec: number;
    readonly memoryMb: number;
    readonly cpuQuota: number;
    readonly stdoutBytes: number;
    constructor(timeoutSec: number, memoryMb: number, cpuQuota: number, stdoutBytes: number);
    toWire(): WireObject;
}
export interface IntentContractInit {
    version: string;
    executionId: string;
    workflowId: string;
    taskClass: string;
    declaredPurpose: string;
    language: string;
    resourceScope: ResourceScope;
    networkScope: NetworkScope;
    processScope: ProcessScope;
    brokerScope: BrokerScope;
    budgets: Budgets;
    backendHint?: RuntimeBackend;
    attributes?: Record<string, string>;
}
export declare class IntentContract {
    readonly version: string;
    readonly executionId: string;
    readonly workflowId: string;
    readonly taskClass: string;
    readonly declaredPurpose: string;
    readonly language: string;
    readonly resourceScope: ResourceScope;
    readonly networkScope: NetworkScope;
    readonly processScope: ProcessScope;
    readonly brokerScope: BrokerScope;
    readonly budgets: Budgets;
    readonly backendHint?: RuntimeBackend;
    readonly attributes: Record<string, string>;
    constructor(init: IntentContractInit);
    toWire(): WireObject;
}
export declare function coerceIntentPayload(intent?: IntentContract | Record<string, unknown>): Record<string, unknown> | undefined;

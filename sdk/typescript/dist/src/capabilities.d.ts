export type WireObject = Record<string, unknown>;
export interface BrokerDelegationInit {
    name: string;
    resource?: string;
    method?: string;
}
export declare class BrokerDelegation {
    readonly name: string;
    readonly resource?: string;
    readonly method?: string;
    constructor(init: BrokerDelegationInit);
    toWire(): WireObject;
}
export interface BrokerCapabilitiesInit {
    delegations?: Array<BrokerDelegation | BrokerDelegationInit>;
    httpRequests?: boolean;
    dependencyFetch?: boolean;
}
export declare class BrokerCapabilities {
    readonly delegations: BrokerDelegation[];
    readonly httpRequests: boolean;
    readonly dependencyFetch: boolean;
    constructor(init?: BrokerCapabilitiesInit);
    toWire(): WireObject;
}
export interface CapabilitiesRequestInit {
    networkDomains?: string[];
    writePaths?: string[];
    broker?: BrokerCapabilities | BrokerCapabilitiesInit;
}
export declare class CapabilitiesRequest {
    readonly networkDomains: string[];
    readonly writePaths: string[];
    readonly broker?: BrokerCapabilities;
    constructor(init?: CapabilitiesRequestInit);
    toWire(): WireObject;
}
export declare function coerceCapabilitiesPayload(capabilities?: CapabilitiesRequest | Record<string, unknown>): Record<string, unknown> | undefined;

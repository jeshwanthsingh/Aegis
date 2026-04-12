export class BrokerDelegation {
    name;
    resource;
    method;
    constructor(init) {
        this.name = init.name;
        this.resource = init.resource;
        this.method = init.method;
    }
    toWire() {
        const wire = { name: this.name };
        if (this.resource)
            wire.resource = this.resource;
        if (this.method)
            wire.method = this.method;
        return wire;
    }
}
export class BrokerCapabilities {
    delegations;
    httpRequests;
    dependencyFetch;
    constructor(init = {}) {
        this.delegations = (init.delegations ?? []).map((delegation) => delegation instanceof BrokerDelegation ? delegation : new BrokerDelegation(delegation));
        this.httpRequests = init.httpRequests ?? false;
        this.dependencyFetch = init.dependencyFetch ?? false;
    }
    toWire() {
        const wire = {};
        if (this.delegations.length > 0)
            wire.delegations = this.delegations.map((delegation) => delegation.toWire());
        if (this.httpRequests)
            wire.http_requests = true;
        if (this.dependencyFetch)
            wire.dependency_fetch = true;
        return wire;
    }
}
export class CapabilitiesRequest {
    networkDomains;
    writePaths;
    broker;
    constructor(init = {}) {
        this.networkDomains = [...(init.networkDomains ?? [])];
        this.writePaths = [...(init.writePaths ?? [])];
        this.broker = init.broker instanceof BrokerCapabilities ? init.broker : init.broker ? new BrokerCapabilities(init.broker) : undefined;
    }
    toWire() {
        const wire = {};
        if (this.networkDomains.length > 0)
            wire.network_domains = [...this.networkDomains];
        if (this.writePaths.length > 0)
            wire.write_paths = [...this.writePaths];
        if (this.broker) {
            const brokerWire = this.broker.toWire();
            if (Object.keys(brokerWire).length > 0)
                wire.broker = brokerWire;
        }
        return wire;
    }
}
export function coerceCapabilitiesPayload(capabilities) {
    if (!capabilities)
        return undefined;
    if (capabilities instanceof CapabilitiesRequest)
        return capabilities.toWire();
    return { ...capabilities };
}

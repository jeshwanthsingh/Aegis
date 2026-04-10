export class ResourceScope {
    workspaceRoot;
    readPaths;
    writePaths;
    denyPaths;
    maxDistinctFiles;
    constructor(workspaceRoot, readPaths = [], writePaths = [], denyPaths = [], maxDistinctFiles = 1) {
        this.workspaceRoot = workspaceRoot;
        this.readPaths = readPaths;
        this.writePaths = writePaths;
        this.denyPaths = denyPaths;
        this.maxDistinctFiles = maxDistinctFiles;
    }
    toWire() {
        return {
            workspace_root: this.workspaceRoot,
            read_paths: [...this.readPaths],
            write_paths: [...this.writePaths],
            deny_paths: [...this.denyPaths],
            max_distinct_files: this.maxDistinctFiles,
        };
    }
}
export class NetworkScope {
    allowNetwork;
    allowedDomains;
    allowedIps;
    maxDnsQueries;
    maxOutboundConns;
    constructor(allowNetwork, allowedDomains = [], allowedIps = [], maxDnsQueries = 0, maxOutboundConns = 0) {
        this.allowNetwork = allowNetwork;
        this.allowedDomains = allowedDomains;
        this.allowedIps = allowedIps;
        this.maxDnsQueries = maxDnsQueries;
        this.maxOutboundConns = maxOutboundConns;
    }
    toWire() {
        return {
            allow_network: this.allowNetwork,
            allowed_domains: [...this.allowedDomains],
            allowed_ips: [...this.allowedIps],
            max_dns_queries: this.maxDnsQueries,
            max_outbound_conns: this.maxOutboundConns,
        };
    }
}
export class ProcessScope {
    allowedBinaries;
    allowShell;
    allowPackageInstall;
    maxChildProcesses;
    constructor(allowedBinaries = [], allowShell = false, allowPackageInstall = false, maxChildProcesses = 0) {
        this.allowedBinaries = allowedBinaries;
        this.allowShell = allowShell;
        this.allowPackageInstall = allowPackageInstall;
        this.maxChildProcesses = maxChildProcesses;
    }
    toWire() {
        return {
            allowed_binaries: [...this.allowedBinaries],
            allow_shell: this.allowShell,
            allow_package_install: this.allowPackageInstall,
            max_child_processes: this.maxChildProcesses,
        };
    }
}
export class BrokerScope {
    allowedDelegations;
    allowedDomains;
    allowedActionTypes;
    requireHostConsent;
    constructor(allowedDelegations = [], allowedDomains = [], allowedActionTypes = [], requireHostConsent = false) {
        this.allowedDelegations = allowedDelegations;
        this.allowedDomains = allowedDomains;
        this.allowedActionTypes = allowedActionTypes;
        this.requireHostConsent = requireHostConsent;
    }
    toWire() {
        const wire = {
            allowed_delegations: [...this.allowedDelegations],
            require_host_consent: this.requireHostConsent,
        };
        if (this.allowedDomains.length > 0)
            wire.allowed_domains = [...this.allowedDomains];
        if (this.allowedActionTypes.length > 0)
            wire.allowed_action_types = [...this.allowedActionTypes];
        return wire;
    }
}
export class Budgets {
    timeoutSec;
    memoryMb;
    cpuQuota;
    stdoutBytes;
    constructor(timeoutSec, memoryMb, cpuQuota, stdoutBytes) {
        this.timeoutSec = timeoutSec;
        this.memoryMb = memoryMb;
        this.cpuQuota = cpuQuota;
        this.stdoutBytes = stdoutBytes;
    }
    toWire() {
        return {
            timeout_sec: this.timeoutSec,
            memory_mb: this.memoryMb,
            cpu_quota: this.cpuQuota,
            stdout_bytes: this.stdoutBytes,
        };
    }
}
export class IntentContract {
    version;
    executionId;
    workflowId;
    taskClass;
    declaredPurpose;
    language;
    resourceScope;
    networkScope;
    processScope;
    brokerScope;
    budgets;
    backendHint;
    attributes;
    constructor(init) {
        this.version = init.version;
        this.executionId = init.executionId;
        this.workflowId = init.workflowId;
        this.taskClass = init.taskClass;
        this.declaredPurpose = init.declaredPurpose;
        this.language = init.language;
        this.resourceScope = init.resourceScope;
        this.networkScope = init.networkScope;
        this.processScope = init.processScope;
        this.brokerScope = init.brokerScope;
        this.budgets = init.budgets;
        this.backendHint = init.backendHint;
        this.attributes = init.attributes ?? {};
    }
    toWire() {
        const wire = {
            version: this.version,
            execution_id: this.executionId,
            workflow_id: this.workflowId,
            task_class: this.taskClass,
            declared_purpose: this.declaredPurpose,
            language: this.language,
            resource_scope: this.resourceScope.toWire(),
            network_scope: this.networkScope.toWire(),
            process_scope: this.processScope.toWire(),
            broker_scope: this.brokerScope.toWire(),
            budgets: this.budgets.toWire(),
        };
        if (this.backendHint)
            wire.backend_hint = this.backendHint;
        if (Object.keys(this.attributes).length > 0)
            wire.attributes = { ...this.attributes };
        return wire;
    }
}
export function coerceIntentPayload(intent) {
    if (!intent)
        return undefined;
    if (intent instanceof IntentContract) {
        return intent.toWire();
    }
    return { ...intent };
}

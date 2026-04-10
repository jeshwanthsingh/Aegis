export type RuntimeBackend = "firecracker" | "gvisor";

export type WireObject = Record<string, unknown>;

export class ResourceScope {
  constructor(
    public readonly workspaceRoot: string,
    public readonly readPaths: string[] = [],
    public readonly writePaths: string[] = [],
    public readonly denyPaths: string[] = [],
    public readonly maxDistinctFiles = 1,
  ) {}

  toWire(): WireObject {
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
  constructor(
    public readonly allowNetwork: boolean,
    public readonly allowedDomains: string[] = [],
    public readonly allowedIps: string[] = [],
    public readonly maxDnsQueries = 0,
    public readonly maxOutboundConns = 0,
  ) {}

  toWire(): WireObject {
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
  constructor(
    public readonly allowedBinaries: string[] = [],
    public readonly allowShell = false,
    public readonly allowPackageInstall = false,
    public readonly maxChildProcesses = 0,
  ) {}

  toWire(): WireObject {
    return {
      allowed_binaries: [...this.allowedBinaries],
      allow_shell: this.allowShell,
      allow_package_install: this.allowPackageInstall,
      max_child_processes: this.maxChildProcesses,
    };
  }
}

export class BrokerScope {
  constructor(
    public readonly allowedDelegations: string[] = [],
    public readonly allowedDomains: string[] = [],
    public readonly allowedActionTypes: string[] = [],
    public readonly requireHostConsent = false,
  ) {}

  toWire(): WireObject {
    const wire: WireObject = {
      allowed_delegations: [...this.allowedDelegations],
      require_host_consent: this.requireHostConsent,
    };
    if (this.allowedDomains.length > 0) wire.allowed_domains = [...this.allowedDomains];
    if (this.allowedActionTypes.length > 0) wire.allowed_action_types = [...this.allowedActionTypes];
    return wire;
  }
}

export class Budgets {
  constructor(
    public readonly timeoutSec: number,
    public readonly memoryMb: number,
    public readonly cpuQuota: number,
    public readonly stdoutBytes: number,
  ) {}

  toWire(): WireObject {
    return {
      timeout_sec: this.timeoutSec,
      memory_mb: this.memoryMb,
      cpu_quota: this.cpuQuota,
      stdout_bytes: this.stdoutBytes,
    };
  }
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

export class IntentContract {
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

  constructor(init: IntentContractInit) {
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

  toWire(): WireObject {
    const wire: WireObject = {
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
    if (this.backendHint) wire.backend_hint = this.backendHint;
    if (Object.keys(this.attributes).length > 0) wire.attributes = { ...this.attributes };
    return wire;
  }
}

export function coerceIntentPayload(intent?: IntentContract | Record<string, unknown>): Record<string, unknown> | undefined {
  if (!intent) return undefined;
  if (intent instanceof IntentContract) {
    return intent.toWire() as Record<string, unknown>;
  }
  return { ...intent };
}

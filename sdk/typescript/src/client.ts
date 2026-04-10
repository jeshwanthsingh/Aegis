import { HTTPTransport } from "./http.js";
import { ConnectionPosture, HealthStatus } from "./types.js";
import { AegisConfigurationError } from "./errors.js";
import { ExecutionRequest, type ExecutionRequestInit } from "./request.js";
import { ExecutionResult } from "./result.js";
import { parseStreamEvent, type ParsedStreamEvent } from "./stream.js";
import { ReceiptVerifier, type VerifyReceiptOptions, type ReceiptVerification } from "./verifier.js";

export interface AegisClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  cliPath?: string;
}

export class AegisClient {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly timeoutMs: number;
  readonly posture: ConnectionPosture;

  private readonly transport: HTTPTransport;
  private readonly verifier: ReceiptVerifier;

  constructor(options: AegisClientOptions = {}) {
    const timeoutMs = options.timeoutMs ?? 30000;
    if (timeoutMs <= 0) throw new AegisConfigurationError("timeoutMs must be greater than zero");
    const [baseUrl, baseUrlSource] = resolveBaseUrl(options.baseUrl);
    const [apiKey, apiKeySource] = resolveApiKey(options.apiKey);
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    this.posture = new ConnectionPosture({
      baseUrl,
      baseUrlSource,
      apiKeySource,
      apiKeyConfigured: Boolean(apiKey),
    });
    this.transport = new HTTPTransport({ baseUrl, apiKey, timeoutMs });
    this.verifier = new ReceiptVerifier({ cliPath: options.cliPath });
  }

  async health(): Promise<HealthStatus> {
    const payload = await this.transport.requestJson("GET", "/v1/health", { authenticated: false });
    return new HealthStatus({
      status: typeof payload.status === "string" ? payload.status : "unknown",
      workerSlotsAvailable: typeof payload.worker_slots_available === "number" ? payload.worker_slots_available : 0,
      workerSlotsTotal: typeof payload.worker_slots_total === "number" ? payload.worker_slots_total : 0,
    });
  }

  async run(request: ExecutionRequest | ExecutionRequestInit): Promise<ExecutionResult> {
    const executionRequest = coerceExecutionRequest(request);
    const payload = await this.transport.requestJson("POST", "/v1/execute", { payload: executionRequest.toPayload() });
    return ExecutionResult.fromPayload(payload, this.verifier);
  }

  async runCode(request: ExecutionRequest | ExecutionRequestInit): Promise<ExecutionResult> {
    return this.run(request);
  }

  async *stream(request: ExecutionRequest | ExecutionRequestInit): AsyncIterable<ParsedStreamEvent> {
    const executionRequest = coerceExecutionRequest(request);
    for await (const rawEvent of this.transport.streamSse("/v1/execute/stream", { payload: executionRequest.toPayload() })) {
      yield parseStreamEvent(rawEvent);
    }
  }

  async *runStream(request: ExecutionRequest | ExecutionRequestInit): AsyncIterable<ParsedStreamEvent> {
    for await (const event of this.stream(request)) {
      yield event;
    }
  }

  async verifyReceipt(options: VerifyReceiptOptions): Promise<ReceiptVerification> {
    return this.verifier.verifyReceipt(options);
  }
}

function coerceExecutionRequest(request: ExecutionRequest | ExecutionRequestInit): ExecutionRequest {
  if (request instanceof ExecutionRequest) return request;
  if (!request.language) throw new AegisConfigurationError("language is required");
  if (request.code === undefined) throw new AegisConfigurationError("code is required");
  return new ExecutionRequest(request);
}

function resolveBaseUrl(explicit?: string): [string, string] {
  if (explicit) return [explicit.replace(/\/$/, ""), "explicit"];
  for (const envName of ["AEGIS_BASE_URL", "AEGIS_URL"] as const) {
    const value = process.env[envName];
    if (value) return [value.replace(/\/$/, ""), envName];
  }
  return ["http://localhost:8080", "default"];
}

function resolveApiKey(explicit?: string): [string | undefined, string] {
  if (explicit) return [explicit, "explicit"];
  const envValue = process.env.AEGIS_API_KEY;
  if (envValue) return [envValue, "AEGIS_API_KEY"];
  return [undefined, "none"];
}

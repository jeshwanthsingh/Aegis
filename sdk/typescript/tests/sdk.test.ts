import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import {
  AegisAuthError,
  AegisClient,
  AegisConfigurationError,
  AegisExecutionError,
  AegisValidationError,
  BrokerScope,
  Budgets,
  DoneEvent,
  ExecutionRequest,
  IntentContract,
  NetworkScope,
  ProcessScope,
  ProofEvent,
  Receipt,
  ReceiptVerification,
  ReceiptVerifier,
  ResourceScope,
  StdoutEvent,
} from "@aegis/sdk";

class TestServer {
  readonly requests: Array<{ method: string; path: string; headers: Record<string, string>; body?: string }> = [];
  private readonly server;
  port = 0;

  constructor(private readonly routes: Map<string, { status: number; headers: Record<string, string>; body: string }>) {
    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const key = `${req.method} ${req.url}`;
      const route = this.routes.get(key);
      if (!route) {
        res.writeHead(404).end("missing route");
        return;
      }
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        this.requests.push({
          method: req.method ?? "GET",
          path: req.url ?? "/",
          headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(",") : String(v ?? "")])),
          body: body || undefined,
        });
        res.writeHead(route.status, route.headers);
        res.end(route.body);
      });
    });
  }

  async start(): Promise<string> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", () => resolve()));
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("server failed to bind");
    this.port = address.port;
    return `http://127.0.0.1:${this.port}`;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => this.server.close((error) => (error ? reject(error) : resolve())));
  }
}

test("client env precedence", async () => {
  process.env.AEGIS_BASE_URL = "http://env-base:8080";
  process.env.AEGIS_URL = "http://legacy:8080";
  process.env.AEGIS_API_KEY = "env-key";
  const client = new AegisClient();
  assert.equal(client.baseUrl, "http://env-base:8080");
  assert.equal(client.apiKey, "env-key");
  assert.equal(client.posture.baseUrlSource, "AEGIS_BASE_URL");
  assert.equal(client.posture.apiKeySource, "AEGIS_API_KEY");
  delete process.env.AEGIS_BASE_URL;
  delete process.env.AEGIS_URL;
  delete process.env.AEGIS_API_KEY;
});

test("invalid client configuration raises", () => {
  assert.throws(() => new AegisClient({ timeoutMs: 0 }), AegisConfigurationError);
});

test("health request is unauthenticated", async () => {
  const server = new TestServer(new Map([
    ["GET /v1/health", { status: 200, headers: { "Content-Type": "application/json" }, body: "{\"status\":\"ok\",\"worker_slots_available\":5,\"worker_slots_total\":5}" }],
  ]));
  const baseUrl = await server.start();
  try {
    const client = new AegisClient({ baseUrl, apiKey: "token" });
    const health = await client.health();
    assert.equal(health.ok, true);
    assert.equal(server.requests[0]?.headers.authorization, undefined);
  } finally {
    await server.stop();
  }
});

test("run serializes request and auth", async () => {
  const server = new TestServer(new Map([
    ["POST /v1/execute", { status: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      stdout: "ok\n", stderr: "", exit_code: 0, exit_reason: "completed", duration_ms: 12, execution_id: "exec-1",
      proof_dir: "/tmp/aegis/proofs/exec-1", receipt_path: "/tmp/aegis/proofs/exec-1/receipt.dsse.json",
      receipt_public_key_path: "/tmp/aegis/proofs/exec-1/receipt.pub", receipt_summary_path: "/tmp/aegis/proofs/exec-1/receipt.summary.txt",
    }) }],
  ]));
  const baseUrl = await server.start();
  try {
    const intent = new IntentContract({
      version: "v1",
      executionId: "11111111-1111-4111-8111-111111111111",
      workflowId: "wf_1",
      taskClass: "demo",
      declaredPurpose: "test",
      language: "bash",
      resourceScope: new ResourceScope("/workspace", ["/workspace"], ["/workspace/out"], [], 3),
      networkScope: new NetworkScope(false, [], [], 0, 0),
      processScope: new ProcessScope(["bash"], true, false, 1),
      brokerScope: new BrokerScope([], [], [], false),
      budgets: new Budgets(10, 128, 100, 4096),
    });
    const client = new AegisClient({ baseUrl, apiKey: "token" });
    const request = new ExecutionRequest({ language: "bash", code: "echo hi", timeoutMs: 1000, intent, profile: "default" });
    const result = await client.run(request);
    assert.equal(result.ok, true);
    assert.equal(result.stdout, "ok\n");
    assert.equal(server.requests[0]?.headers.authorization, "Bearer token");
    const payload = JSON.parse(server.requests[0]?.body ?? "{}");
    assert.equal(payload.lang, "bash");
    assert.equal(payload.profile, "default");
    assert.equal(payload.intent.resource_scope.workspace_root, "/workspace");
  } finally {
    await server.stop();
  }
});

test("validation and auth errors map cleanly", async () => {
  const server = new TestServer(new Map([
    ["POST /v1/execute", { status: 401, headers: { "Content-Type": "application/json" }, body: "{\"error\":{\"code\":\"auth_required\",\"message\":\"Authorization header missing\",\"details\":{}}}" }],
  ]));
  const baseUrl = await server.start();
  try {
    const client = new AegisClient({ baseUrl });
    await assert.rejects(() => client.run({ language: "bash", code: "echo hi" }), AegisAuthError);
  } finally {
    await server.stop();
  }

  const validationServer = new TestServer(new Map([
    ["POST /v1/execute", { status: 400, headers: { "Content-Type": "application/json" }, body: "{\"error\":{\"code\":\"invalid_request\",\"message\":\"invalid request body\",\"details\":{}}}" }],
  ]));
  const validationBaseUrl = await validationServer.start();
  try {
    const client = new AegisClient({ baseUrl: validationBaseUrl });
    await assert.rejects(() => client.run({ language: "bash", code: "echo hi" }), AegisValidationError);
  } finally {
    await validationServer.stop();
  }
});

test("execution failure inside 200 stays in result", async () => {
  const server = new TestServer(new Map([
    ["POST /v1/execute", { status: 200, headers: { "Content-Type": "application/json" }, body: "{\"stdout\":\"\",\"stderr\":\"\",\"exit_code\":0,\"exit_reason\":\"sandbox_error\",\"duration_ms\":10,\"execution_id\":\"exec-2\",\"error\":\"timeout\"}" }],
  ]));
  const baseUrl = await server.start();
  try {
    const client = new AegisClient({ baseUrl });
    const result = await client.run({ language: "bash", code: "sleep 1" });
    assert.equal(result.ok, false);
    assert.equal(result.error, "timeout");
    assert.throws(() => result.throwIfExecutionFailed(), AegisExecutionError);
  } finally {
    await server.stop();
  }
});

test("stream parsing yields typed events", async () => {
  const body = [
    "data: {\"type\":\"stdout\",\"chunk\":\"hello\\\\n\"}",
    "",
    "data: {\"type\":\"proof\",\"execution_id\":\"exec-stream\",\"proof_dir\":\"/tmp/aegis/proofs/exec-stream\",\"receipt_path\":\"/tmp/aegis/proofs/exec-stream/receipt.dsse.json\",\"receipt_public_key_path\":\"/tmp/aegis/proofs/exec-stream/receipt.pub\",\"receipt_summary_path\":\"/tmp/aegis/proofs/exec-stream/receipt.summary.txt\",\"artifact_count\":2,\"divergence_verdict\":\"allow\"}",
    "",
    "data: {\"type\":\"done\",\"exit_code\":0,\"reason\":\"completed\",\"duration_ms\":12}",
    "",
  ].join("\n");
  const server = new TestServer(new Map([
    ["POST /v1/execute/stream", { status: 200, headers: { "Content-Type": "text/event-stream" }, body }],
  ]));
  const baseUrl = await server.start();
  try {
    const client = new AegisClient({ baseUrl });
    const events = [];
    for await (const event of client.stream({ language: "bash", code: "echo hi" })) {
      events.push(event);
    }
    assert.equal(events[0] instanceof StdoutEvent, true);
    assert.equal(events[1] instanceof ProofEvent, true);
    assert.equal(events[2] instanceof DoneEvent, true);
  } finally {
    await server.stop();
  }
});

test("receipt wrapper and verifier helpers work", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aegis-ts-sdk-"));
  const receiptPath = join(dir, "receipt.dsse.json");
  writeFileSync(receiptPath, JSON.stringify({ statement: { predicate: { execution_id: "exec-r", divergence: { verdict: "allow" }, trust: { signing_mode: "strict", key_source: "configured_seed" } } } }));

  class StubVerifier {
    async verifyReceipt(): Promise<ReceiptVerification> {
      return new ReceiptVerification({ verified: true, summaryText: "verification=verified\nexecution_id=exec-r\n", fields: { verification: "verified", execution_id: "exec-r" } });
    }
  }

  const receipt = Receipt.load(receiptPath, { verifier: new StubVerifier() as unknown as ReceiptVerifier });
  assert.equal(receipt.executionId, "exec-r");
  assert.equal(receipt.verdict, "allow");
  const verification = await receipt.verify();
  assert.equal(verification.verified, true);
});

test("missing cli path is configuration error", () => {
  const verifier = new ReceiptVerifier({ cliPath: "/tmp/definitely-missing-aegis" });
  const originalPath = process.env.PATH;
  const originalCwd = process.cwd();
  const isolatedDir = mkdtempSync(join(tmpdir(), "aegis-ts-sdk-no-cli-"));
  process.env.PATH = "";
  process.chdir(isolatedDir);
  try {
    assert.throws(() => verifier.resolveCliPath(), AegisConfigurationError);
  } finally {
    process.chdir(originalCwd);
    process.env.PATH = originalPath;
  }
});

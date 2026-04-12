# Aegis TypeScript SDK

TypeScript SDK v1 for the local Aegis execution evidence runtime.

Package name:

- npm package: `@aegis/sdk`
- import: `@aegis/sdk`

Runtime target:

- Node.js 20+

This SDK is the Node-first client for the current `aegis serve` HTTP API.

## Install

### Source checkout mode

This is the primary mode for this repo.

```bash
cd sdk/typescript
npm install
npm run build
```

The repo-local examples run from built output:

```bash
node dist/examples/run_code.js
```

The package exports from `dist/src/index.js` after build.

### Installed-package mode

Separate concern.

Once the package is built or published for your environment, consume `@aegis/sdk` in your own project and point it at a running `aegis serve` instance. That is not the primary onboarding path for this repo.

## Client initialization

```ts
import { AegisClient } from "@aegis/sdk";

const client = new AegisClient({
  baseUrl: "http://localhost:8080",
  apiKey: undefined,
  timeoutMs: 30_000,
  cliPath: undefined,
});
```

Configuration precedence:

- `baseUrl` constructor option
- `AEGIS_BASE_URL`
- `AEGIS_URL`
- default `http://localhost:8080`

API key precedence:

- `apiKey` constructor option
- `AEGIS_API_KEY`
- no API key configured

`GET /v1/health` remains unauthenticated. Execute endpoints require `Authorization: Bearer <token>` only when the server is started with `AEGIS_API_KEY`.

## Execute

### Inline request

```ts
import { AegisClient } from "@aegis/sdk";

const client = new AegisClient();
const result = await client.run({
  language: "bash",
  code: "echo hello from typescript sdk",
  timeoutMs: 10_000,
});

console.log(result.stdout.trim());
console.log(result.ok, result.exitCode, result.executionId);
```

For the canonical source-checkout onboarding path, prefer:

```bash
node dist/examples/run_code.js
```

### Reusable request object

```ts
import { AegisClient, ExecutionRequest } from "@aegis/sdk";

const client = new AegisClient();
const request = new ExecutionRequest({
  language: "bash",
  code: "echo reusable request",
  timeoutMs: 10_000,
});

const result = await client.run(request);
console.log(result.executionId);
```

## Streaming

```ts
import { AegisClient, DoneEvent, ProofEvent, StdoutEvent } from "@aegis/sdk";

const client = new AegisClient();

for await (const event of client.stream({ language: "bash", code: "echo stream path" })) {
  if (event instanceof StdoutEvent) {
    process.stdout.write(event.chunk);
  } else if (event instanceof ProofEvent) {
    console.log("\nproof:", event.proofBundle.receiptPath);
  } else if (event instanceof DoneEvent) {
    console.log("\ndone:", event.exitCode, event.durationMs);
  }
}
```

Streaming is the advanced path. For most integrations, `client.run(...)` is the primary surface.

## Receipts and verification

Receipt verification reuses the Aegis CLI verifier rather than re-implementing receipt-signing logic in TypeScript.

Lookup order:

- `cliPath` passed to `AegisClient`
- `AEGIS_CLI_BIN`
- repo-local `.aegis/bin/aegis`
- `aegis` on `PATH`

```ts
const result = await client.run({ language: "bash", code: "echo verify me" });

const verification = await result.verifyReceipt();
console.log(verification.verified, verification.executionId);

const receipt = result.requireReceipt();
console.log(receipt.verdict, receipt.signingMode, receipt.keySource);
```

Direct verification is also available:

```ts
const verification = await client.verifyReceipt({ proofDir: result.proofDir });
```

Windows + WSL note:

- when the repo lives on WSL and the repo-local `aegis` binary also lives there, the SDK bridges that path through `wsl.exe` automatically

## Broker examples

Reference examples:

- `examples/broker_allowed.ts`
- `examples/broker_denied.ts`

These are local examples against a running orchestrator. They require the host broker credential environment to be present when `aegis serve` starts.

The stronger product proof path after first success is:

```bash
python3 ../../scripts/run_canonical_demo.py --serve
```

That is not the first-run onboarding path.

## Error model

Transport and API failures throw:

- `AegisConnectionError`
- `AegisConfigurationError`
- `AegisAuthError`
- `AegisValidationError`
- `AegisVerificationError`
- `AegisStreamError`

Runtime execution failure is distinct:

- `POST /v1/execute` may return `200 OK` for an accepted execution whose runtime outcome is unsuccessful
- those cases come back as `ExecutionResult` with `result.ok === false`

```ts
const result = await client.run({ language: "bash", code: "exit 2" });
console.log(result.ok);
console.log(result.error);
result.throwIfExecutionFailed();
```

## Caveats

- this SDK targets a running local or self-hosted Aegis server
- it does not imply hosted-service guarantees, host attestation, or HSM/KMS-backed signing custody
- broker examples are real, but they still depend on host-side broker credential configuration
- receipt verification depends on the Aegis CLI being available

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { AegisClient, BrokerCapabilities, BrokerDelegation, CapabilitiesRequest } from "@aegis/sdk";
const DEFAULT_LOG_PATH = "/tmp/aegis-local-orchestrator.log";
const ALLOWED_MARKER = "PASS_auth_present_true_no_raw_token";
const DENIED_MARKER = "PASS_denied_no_raw_token";
const WSL_DISTRO = process.env.AEGIS_WSL_DISTRO ?? "Ubuntu";
class ProbeServer {
    localObservations = [];
    logPath = `/tmp/aegis-ts-broker-probe-${randomUUID()}.jsonl`;
    wslProbe;
    server = createServer((req, res) => {
        const authHeader = req.headers.authorization ?? "";
        const authPresent = authHeader.startsWith("Bearer ");
        this.localObservations.push({
            path: req.url ?? "/",
            authPresent,
            authScheme: authPresent ? "Bearer" : "",
        });
        const body = `auth_present=${authPresent ? "true" : "false"}\n`;
        res.writeHead(200, {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": Buffer.byteLength(body).toString(),
            Connection: "close",
        });
        res.end(body);
    });
    get observations() {
        if (this.wslProbe)
            return readWslProbeObservations(this.logPath);
        return [...this.localObservations];
    }
    async start() {
        if (process.platform === "win32")
            return this.startViaWsl();
        await new Promise((resolve) => this.server.listen(0, "127.0.0.1", () => resolve()));
        const address = this.server.address();
        if (!address || typeof address === "string")
            throw new Error("probe server failed to bind");
        return address.port;
    }
    async stop() {
        if (this.wslProbe) {
            this.wslProbe.kill();
            await new Promise((resolve) => this.wslProbe?.once("exit", () => resolve()));
            this.wslProbe = undefined;
            return;
        }
        await new Promise((resolve, reject) => this.server.close((error) => (error ? reject(error) : resolve())));
    }
    async startViaWsl() {
        const child = spawn("wsl.exe", ["-d", WSL_DISTRO, "bash", "-lc", buildWslProbeCommand(this.logPath)], {
            stdio: ["ignore", "pipe", "pipe"],
            cwd: process.env.USERPROFILE ?? "C:\\",
        });
        this.wslProbe = child;
        const stderrChunks = [];
        child.stderr.on("data", (chunk) => stderrChunks.push(chunk.toString("utf8")));
        return await new Promise((resolve, reject) => {
            let resolved = false;
            let stdout = "";
            child.stdout.on("data", (chunk) => {
                stdout += chunk.toString("utf8");
                const match = stdout.match(/(\d+)/);
                if (!resolved && match?.[1]) {
                    resolved = true;
                    resolve(Number(match[1]));
                }
            });
            child.once("error", reject);
            child.once("exit", (code) => {
                if (!resolved) {
                    reject(new Error(`WSL probe server exited early with code ${String(code)}: ${stderrChunks.join("").trim()}`));
                }
            });
        });
    }
}
export async function runAllowedCase() {
    requireSecret();
    const client = new AegisClient();
    await assertHealth(client);
    const probe = new ProbeServer();
    const port = await probe.start();
    try {
        const executionId = randomUUID();
        const result = await client.run({
            language: "bash",
            code: allowedGuestCode(port),
            timeoutMs: 10_000,
            capabilities: brokerCapabilities({ resource: `http://127.0.0.1:${port}/probe`, allowHttpRequests: true }),
        });
        assertStdoutMarker(result.stdout, ALLOWED_MARKER);
        await assertResultArtifacts(result);
        await assertNoSecretLeak(result);
        assertProbeRequests(probe.observations, { expected: 1, requireAuth: true });
        const telemetry = brokerEvidenceStatus({ executionId: result.executionId, receiptSummaryPath: result.receiptSummaryPath, expected: "allowed" });
        const verification = result.receipt ? await result.receipt.verify() : undefined;
        console.log("brokerCase=allowed");
        console.log(`executionId=${result.executionId}`);
        console.log(`resultOk=${String(result.ok)}`);
        console.log(`exitCode=${result.exitCode}`);
        console.log(`proofDir=${result.proofDir ?? ""}`);
        console.log(`receiptPath=${result.receiptPath ?? ""}`);
        console.log(`receiptVerified=${String(Boolean(verification?.verified))}`);
        console.log(`upstreamRequests=${probe.observations.length}`);
        console.log(`telemetry=${telemetry}`);
        console.log("status=passed");
    }
    finally {
        await probe.stop();
    }
}
export async function runDeniedCase() {
    requireSecret();
    const client = new AegisClient();
    await assertHealth(client);
    const probe = new ProbeServer();
    const port = await probe.start();
    try {
        const executionId = randomUUID();
        const result = await client.run({
            language: "bash",
            code: deniedGuestCode(port),
            timeoutMs: 10_000,
            capabilities: brokerCapabilities({ resource: "https://example.invalid/probe", allowHttpRequests: true }),
        });
        assertStdoutMarker(result.stdout, DENIED_MARKER);
        await assertResultArtifacts(result);
        await assertNoSecretLeak(result);
        assertProbeRequests(probe.observations, { expected: 0, requireAuth: false });
        const telemetry = brokerEvidenceStatus({ executionId: result.executionId, receiptSummaryPath: result.receiptSummaryPath, expected: "denied" });
        const verification = result.receipt ? await result.receipt.verify() : undefined;
        console.log("brokerCase=denied");
        console.log(`executionId=${result.executionId}`);
        console.log(`resultOk=${String(result.ok)}`);
        console.log(`exitCode=${result.exitCode}`);
        console.log(`proofDir=${result.proofDir ?? ""}`);
        console.log(`receiptPath=${result.receiptPath ?? ""}`);
        console.log(`receiptVerified=${String(Boolean(verification?.verified))}`);
        console.log(`upstreamRequests=${probe.observations.length}`);
        console.log(`telemetry=${telemetry}`);
        console.log("status=passed");
    }
    finally {
        await probe.stop();
    }
}
async function assertHealth(client) {
    const health = await client.health();
    if (!health.ok)
        throw new Error(`Aegis health check failed: status=${health.status}`);
}
function requireSecret() {
    const direct = (process.env.AEGIS_CRED_GITHUB_TOKEN ?? "").trim();
    if (direct)
        return direct;
    const fallback = secretFromOrchestratorEnv();
    if (fallback)
        return fallback;
    throw new Error("AEGIS_CRED_GITHUB_TOKEN must be exported in the host environment or present in the running orchestrator for broker smoke validation");
}
function secretFromOrchestratorEnv() {
    const procRoot = process.platform === "win32" ? toWslUncPath("/proc") : "/proc";
    for (const entry of readdirSync(procRoot)) {
        if (!/^\d+$/.test(entry))
            continue;
        try {
            const cmdline = readFileSync(join(procRoot, entry, "cmdline"), "utf8").replace(/\0/g, " ");
            if (!cmdline.includes(".aegis/bin/orchestrator") && !cmdline.includes("/tmp/aegis-bin"))
                continue;
            const environ = readFileSync(join(procRoot, entry, "environ"));
            for (const part of environ.toString("utf8").split("\0")) {
                if (part.startsWith("AEGIS_CRED_GITHUB_TOKEN=")) {
                    return part.split("=", 2)[1]?.trim() ?? "";
                }
            }
        }
        catch {
            continue;
        }
    }
    return "";
}
function assertStdoutMarker(stdout, marker) {
    if (!stdout.includes(marker))
        throw new Error(`expected stdout marker ${marker}, got: ${stdout}`);
}
async function assertResultArtifacts(result) {
    if (!result.ok)
        result.throwIfExecutionFailed();
    if (!result.proofDir || !existsSync(result.proofDir))
        throw new Error("missing proofDir on disk");
    if (!result.receiptPath || !existsSync(result.receiptPath))
        throw new Error("missing receiptPath on disk");
    if (!result.receipt)
        throw new Error("result.receipt could not be loaded");
    const verification = await result.receipt.verify();
    if (!verification.verified)
        throw new Error("receipt verification did not return verified");
}
function assertProbeRequests(observations, options) {
    if (observations.length !== options.expected)
        throw new Error(`expected ${options.expected} upstream requests, got ${observations.length}`);
    if (options.requireAuth && (!observations[0] || !observations[0].authPresent)) {
        throw new Error("expected upstream probe to receive Bearer auth");
    }
}
async function assertNoSecretLeak(result) {
    const secret = requireSecret();
    const leaks = [];
    if (result.stdout.includes(secret))
        leaks.push("stdout");
    if (result.stderr.includes(secret))
        leaks.push("stderr");
    if (result.proofDir) {
        for (const path of await scanDirectoryForSecret(result.proofDir, secret))
            leaks.push(path);
    }
    if (leaks.length > 0)
        throw new Error(`raw credential leak detected in: ${leaks.join(", ")}`);
}
async function scanDirectoryForSecret(root, secret) {
    const findings = [];
    async function walk(current) {
        for (const entry of readdirSync(current, { withFileTypes: true })) {
            const path = join(current, entry.name);
            if (entry.isDirectory()) {
                await walk(path);
            }
            else if (entry.isFile()) {
                const data = await readFile(path);
                if (data.includes(Buffer.from(secret, "utf8")))
                    findings.push(path);
            }
        }
    }
    if (existsSync(root))
        await walk(root);
    return findings;
}
function brokerEvidenceStatus(input) {
    if (telemetryEventsPresent(input.executionId, ["credential.request", `credential.${input.expected}`])) {
        return `credential.request,credential.${input.expected}`;
    }
    if (input.expected === "denied" && input.receiptSummaryPath && existsSync(input.receiptSummaryPath)) {
        const summary = readFileSync(input.receiptSummaryPath, "utf8");
        if (summary.includes("broker.request_denied"))
            return "receipt:broker.request_denied";
    }
    return input.expected === "allowed" ? "upstream_probe_auth_present" : "receipt:broker.request_denied";
}
function telemetryEventsPresent(executionId, expectedKinds) {
    const logPath = process.env.AEGIS_ORCHESTRATOR_LOG ?? DEFAULT_LOG_PATH;
    if (!existsSync(logPath))
        return false;
    const lines = readFileSync(logPath, "utf8").split(/\r?\n/);
    return expectedKinds.every((kind) => lines.some((line) => line.includes(executionId) && line.includes(kind)));
}
function brokerCapabilities(input) {
    return new CapabilitiesRequest({
        broker: new BrokerCapabilities({
            delegations: [new BrokerDelegation({ name: "github", resource: input.resource })],
            httpRequests: input.allowHttpRequests,
        }),
    });
}
function allowedGuestCode(port) {
    return `#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:${port}/probe HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 200'*auth_present=true*|*'HTTP/1.0 200'*auth_present=true*)
    echo '${ALLOWED_MARKER}'
    exit 0
    ;;
esac
echo 'FAIL_broker_allowed'
printf '%s\\n' "$response"
exit 1
`;
}
function deniedGuestCode(port) {
    return `#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET http://127.0.0.1:${port}/probe HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
case "$response" in
  *'HTTP/1.1 403'*'broker denied:'*|*'HTTP/1.0 403'*'broker denied:'*)
    echo '${DENIED_MARKER}'
    exit 0
    ;;
esac
echo 'FAIL_broker_denied'
printf '%s\\n' "$response"
exit 1
`;
}
function buildWslProbeCommand(logPath) {
    const pythonCode = [
        "import http.server, json, socketserver, sys",
        "log_path = sys.argv[1]",
        "class Handler(http.server.BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        "        auth = self.headers.get('Authorization', '')",
        "        auth_present = auth.startswith('Bearer ')",
        "        with open(log_path, 'a', encoding='utf-8') as handle:",
        "            handle.write(json.dumps({'path': self.path, 'authPresent': auth_present, 'authScheme': 'Bearer' if auth_present else ''}) + '\\n')",
        "        body = f\"auth_present={'true' if auth_present else 'false'}\\n\".encode('utf-8')",
        "        self.send_response(200)",
        "        self.send_header('Content-Type', 'text/plain; charset=utf-8')",
        "        self.send_header('Content-Length', str(len(body)))",
        "        self.send_header('Connection', 'close')",
        "        self.end_headers()",
        "        self.wfile.write(body)",
        "    def log_message(self, *_args):",
        "        return",
        "with socketserver.TCPServer(('127.0.0.1', 0), Handler) as server:",
        "    print(server.server_address[1], flush=True)",
        "    server.serve_forever()",
    ].join("\n");
    return `rm -f ${shellQuote(logPath)} && python3 -u -c ${shellQuote(pythonCode)} ${shellQuote(logPath)}`;
}
function readWslProbeObservations(logPath) {
    const uncPath = toWslUncPath(logPath);
    if (!existsSync(uncPath))
        return [];
    return readFileSync(uncPath, "utf8")
        .split(/\r?\n/)
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line));
}
function toWslUncPath(path) {
    return `\\\\wsl.localhost\\${WSL_DISTRO}${path.replace(/\//g, "\\")}`;
}
function shellQuote(value) {
    return `'${value.replace(/'/g, `'"'"'`)}'`;
}

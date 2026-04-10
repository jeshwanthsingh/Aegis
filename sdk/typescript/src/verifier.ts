import { accessSync, constants, existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { delimiter, dirname, join } from "node:path";

import { AegisConfigurationError, AegisVerificationError } from "./errors.js";

const execFileAsync = promisify(execFile);

export class ReceiptVerification {
  readonly verified: boolean;
  readonly summaryText: string;
  readonly fields: Record<string, string>;

  constructor(input: { verified: boolean; summaryText: string; fields: Record<string, string> }) {
    this.verified = input.verified;
    this.summaryText = input.summaryText;
    this.fields = input.fields;
  }

  get executionId(): string | undefined {
    return this.fields.execution_id;
  }

  get divergenceVerdict(): string | undefined {
    return this.fields.divergence_verdict;
  }

  get signingMode(): string | undefined {
    return this.fields.signing_mode;
  }
}

export interface VerifyReceiptOptions {
  receiptPath?: string;
  publicKeyPath?: string;
  proofDir?: string;
  executionId?: string;
}

export class ReceiptVerifier {
  private readonly cliPath?: string;

  constructor(options: { cliPath?: string } = {}) {
    this.cliPath = options.cliPath;
  }

  resolveCliPath(): string {
    const candidates: string[] = [];
    if (this.cliPath) candidates.push(this.cliPath);
    if (process.env.AEGIS_CLI_BIN) candidates.push(process.env.AEGIS_CLI_BIN);

    let current = process.cwd();
    while (true) {
      candidates.push(join(current, ".aegis", "bin", "aegis"));
      const parent = dirname(current);
      if (parent === current || current === "/") break;
      current = parent;
    }

    for (const candidate of candidates) {
      if (!candidate) continue;
      if (!existsSync(candidate)) continue;
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // keep scanning
      }
    }

    for (const entry of (process.env.PATH ?? "").split(delimiter)) {
      if (!entry) continue;
      const candidate = join(entry, process.platform === "win32" ? "aegis.exe" : "aegis");
      if (!existsSync(candidate)) continue;
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // keep scanning
      }
    }

    throw new AegisConfigurationError("could not locate the Aegis CLI for receipt verification; set AEGIS_CLI_BIN or install the aegis CLI");
  }

  async verifyReceipt(options: VerifyReceiptOptions): Promise<ReceiptVerification> {
    const cli = this.resolveCliPath();
    const command = ["receipt", "verify"];
    if (options.receiptPath) {
      command.push("--file", options.receiptPath);
      if (options.publicKeyPath) command.push("--public-key", options.publicKeyPath);
    } else if (options.proofDir) {
      command.push("--proof-dir", options.proofDir);
    } else if (options.executionId) {
      command.push("--execution-id", options.executionId);
    } else {
      throw new AegisConfigurationError("receipt verification requires receiptPath, proofDir, or executionId");
    }

    const invocation = buildInvocation(cli, command);
    try {
      const completed = await execFileAsync(invocation.file, invocation.args, { encoding: "utf8" });
      const fields = parseSummary(completed.stdout);
      return new ReceiptVerification({
        verified: fields.verification === "verified",
        summaryText: completed.stdout,
        fields,
      });
    } catch (error) {
      if (error instanceof Error && "stdout" in error) {
        const withOutput = error as Error & { stdout?: string; stderr?: string };
        const message = withOutput.stderr?.trim() || withOutput.stdout?.trim() || error.message;
        throw new AegisVerificationError(message);
      }
      throw new AegisVerificationError(String(error));
    }
  }
}

function buildInvocation(cli: string, args: string[]): { file: string; args: string[] } {
  if (process.platform === "win32" && shouldInvokeViaWsl(cli)) {
    const shellCommand = [shellQuote(toWslPath(cli)), ...args.map(shellQuote)].join(" ");
    return {
      file: "wsl.exe",
      args: ["bash", "-lc", shellCommand],
    };
  }
  return { file: cli, args };
}

function shouldInvokeViaWsl(cli: string): boolean {
  return cli.startsWith("/") || cli.startsWith("\\wsl.localhost\\") || cli.startsWith("\\wsl$\\") || isMappedWslDrivePath(cli);
}

function toWslPath(path: string): string {
  if (path.startsWith("/")) return path;
  const localhostMatch = /^\\\\wsl(?:\.localhost)?\\[^\\]+\\(.*)$/.exec(path);
  if (localhostMatch?.[1]) {
    return `/${localhostMatch[1].replace(/\\/g, "/")}`;
  }
  const mappedDriveMatch = /^[A-Za-z]:(\\.*)$/.exec(path);
  if (mappedDriveMatch?.[1] && isMappedWslDrivePath(path)) {
    return mappedDriveMatch[1].replace(/\\/g, "/");
  }
  return path;
}

function isMappedWslDrivePath(path: string): boolean {
  return /^[A-Za-z]:(\\home\\|\\tmp\\|\\usr\\|\\opt\\|\\var\\)/.test(path);
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

export function parseSummary(summaryText: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const rawLine of summaryText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("outcome=")) {
      for (const token of line.split(/\s+/)) {
        const [key, value] = token.split("=", 2);
        if (key && value) fields[key] = value;
      }
      continue;
    }
    const [key, value] = line.split("=", 2);
    if (key && value) fields[key] = value;
  }
  return fields;
}


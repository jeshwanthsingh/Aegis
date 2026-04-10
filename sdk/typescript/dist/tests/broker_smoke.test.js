import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
test("broker smoke examples", { skip: process.env.AEGIS_RUN_BROKER_SMOKE !== "1" || !process.env.AEGIS_CRED_GITHUB_TOKEN }, async () => {
    const root = join(process.cwd(), "dist", "examples");
    for (const script of ["broker_allowed.js", "broker_denied.js"]) {
        const completed = await new Promise((resolve) => {
            const child = spawn(process.execPath, [join(root, script)], { stdio: ["ignore", "pipe", "pipe"], env: process.env });
            let stdout = "";
            let stderr = "";
            child.stdout.on("data", (chunk) => { stdout += String(chunk); });
            child.stderr.on("data", (chunk) => { stderr += String(chunk); });
            child.on("close", (code) => resolve({ code, stdout, stderr }));
        });
        assert.equal(completed.code, 0, `${script} failed\nstdout:\n${completed.stdout}\nstderr:\n${completed.stderr}`);
    }
});

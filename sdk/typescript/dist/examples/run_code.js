import { AegisClient } from "@aegis/sdk";
const client = new AegisClient();
const result = await client.run({ language: "bash", code: "echo hello from typescript sdk" });
process.stdout.write(result.stdout);
console.log(`ok=${String(result.ok)}`);
console.log(`exitCode=${result.exitCode}`);
console.log(`executionId=${result.executionId}`);
console.log(`proofDir=${result.proofDir ?? ""}`);

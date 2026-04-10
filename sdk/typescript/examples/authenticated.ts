import { AegisClient } from "@aegis/sdk";

const client = new AegisClient({ baseUrl: "http://localhost:8080", apiKey: "phase14-token" });
console.log(`authenticated=${String(client.posture.authenticated)}`);
const result = await client.run({ language: "bash", code: "echo authenticated typescript sdk" });
process.stdout.write(result.stdout);

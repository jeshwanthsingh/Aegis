import { AegisClient } from "@aegis/sdk";

const client = new AegisClient();
const result = await client.run({ language: "bash", code: "echo verify me" });
const verification = await result.verifyReceipt();
console.log(`verified=${String(verification.verified)}`);
console.log(`executionId=${verification.executionId}`);

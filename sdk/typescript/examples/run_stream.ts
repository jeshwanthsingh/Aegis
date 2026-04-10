import { AegisClient, DoneEvent, ErrorEvent, ProofEvent, StdoutEvent } from "@aegis/sdk";

const client = new AegisClient();
for await (const event of client.stream({ language: "bash", code: "echo streamed" })) {
  if (event instanceof StdoutEvent) {
    process.stdout.write(event.chunk);
  } else if (event instanceof ProofEvent) {
    console.log(`receiptPath=${event.proofBundle.receiptPath}`);
  } else if (event instanceof DoneEvent) {
    console.log(`done exit=${event.exitCode} durationMs=${event.durationMs}`);
  } else if (event instanceof ErrorEvent) {
    console.log(`stream error: ${event.error}`);
  }
}

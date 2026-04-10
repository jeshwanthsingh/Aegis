import { AegisClient } from "@aegis/sdk";

const client = new AegisClient();
const health = await client.health();
console.log(`status=${health.status}`);
console.log(`workerSlots=${health.workerSlotsAvailable}/${health.workerSlotsTotal}`);

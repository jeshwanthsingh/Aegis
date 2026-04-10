from aegis import AegisClient

client = AegisClient()
health = client.health()
print(f"status={health.status}")
print(f"worker_slots={health.worker_slots_available}/{health.worker_slots_total}")

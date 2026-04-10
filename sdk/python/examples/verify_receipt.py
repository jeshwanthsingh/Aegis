from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo verify me")
verification = result.verify_receipt()
print(f"verified={str(verification.verified).lower()}")
print(f"execution_id={verification.execution_id}")

from aegis import AegisClient

client = AegisClient(base_url="http://localhost:8080", api_key="phase14-token")
print(f"authenticated={str(client.posture.authenticated).lower()}")
result = client.run(language="bash", code="echo authenticated sdk")
print(result.stdout, end="")

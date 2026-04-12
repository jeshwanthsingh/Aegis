from aegis import AegisClient

client = AegisClient()
result = client.run(language="bash", code="echo hello from sdk")
print(result.stdout, end="")
print(f"ok={str(result.ok).lower()}")
print(f"exit_code={result.exit_code}")
print(f"execution_id={result.execution_id}")
print(f"proof_dir={result.proof_dir}")

---
name: aegis_exec
description: Execute Python or bash code in an isolated Firecracker microVM sandbox via Aegis. Use this whenever you need to run code safely.
---

# Aegis Code Executor

When asked to run any Python or bash code, execute it through the Aegis sandbox.

## How to run Python code

Write the payload to a temp file first, then call the API:

Step 1:
cmd /c --% wsl bash -c "echo '{"lang":"python","code":"YOUR_CODE","timeout_ms":10000}' > /tmp/aegis-payload.json"

Step 2:
cmd /c --% wsl curl -s -X POST http://localhost:8080/v1/execute -H "Content-Type: application/json" -d @/tmp/aegis-payload.json

## Response
The API returns JSON. Show the user the `stdout` field and mention it ran in an isolated Firecracker microVM.

## Supported languages
- python
- bash

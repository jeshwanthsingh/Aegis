# Baseline

The narrow local baseline is:

```bash
go run ./cmd/aegis-cli setup
bash scripts/preflight.sh
go run ./cmd/aegis-cli serve
curl http://localhost:8080/v1/health
curl http://localhost:8080/ready
curl -H 'Content-Type: application/json' -d '{"lang":"bash","code":"echo baseline-smoke"}' http://localhost:8080/v1/execute
curl -H 'Content-Type: application/json' -d '{"lang":"python","code":"print(\"python-baseline\")"}' http://localhost:8080/v1/execute
go run ./cmd/aegis-cli receipt verify --proof-dir /tmp/aegis/proofs/<execution-id>
```

`scripts/preflight.sh` resolves the database URL in this order: `DB_URL`, `AEGIS_DB_URL`, then `.aegis/config.yaml`.

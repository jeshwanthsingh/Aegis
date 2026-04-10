# Phase 18 - TypeScript SDK v1

## Status
COMPLETE.

## Goal
Build a Node-first TypeScript SDK that mirrors the finalized Python SDK v1 closely enough that the two SDKs feel like sibling products: same mental model, same result/receipt ergonomics, same structured errors, same broker smoke story, and no invented backend/session abstractions.

## What This Phase Shipped
- `sdk/typescript/` package scaffold with `package.json`, `tsconfig.json`, `src/`, `examples/`, `tests/`, and package README
- public SDK surface aligned to Python v1 around `AegisClient`, `ExecutionRequest`, `ExecutionResult`, `Receipt`, intent helpers, and a small structured error hierarchy
- primary Node-first execution flow through `client.run(...)`, `client.stream(...)`, `client.health()`, and receipt verification helpers
- CLI-backed receipt verification wrapper that works from the repo-local WSL-backed CLI path even when the TypeScript examples run through Windows Node
- broker smoke examples kept on the public SDK surface and fixed for the Windows Node + WSL runtime split by running the upstream auth probe inside WSL while preserving the canonical localhost-only broker semantics
- TypeScript tests and docs aligned to the real package layout and real validation path

## Validation Completed
- package build emits `sdk/typescript/dist/`
- built unit tests pass
- built top-level package imports work through the examples using `@aegis/sdk`
- live built examples pass against a running local `aegis serve`:
  - health
  - sync execute
  - receipt verification
  - stream
  - broker allowed
  - broker denied

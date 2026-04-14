# Self-Hosted Pilot Offer

Aegis lets internal coding agents run code without giving them your machine, and proves what they tried to do.

This offer is for a narrow self-hosted pilot, not a broad platform rollout.

## Pilot shape

- duration: 6-8 weeks
- deployment: self-hosted in the design partner's environment
- workflow scope: one internal coding-agent workflow on one codebase
- support: install help, integration help, and direct operator support included

## What is in scope

One workflow only. Example:

- an internal coding agent runs build, test, and repo-local automation against a selected repository without direct host access

One or two policy paths only, chosen up front:

- required path: direct egress denied by default
- optional second path: one governed action path already supported by the current runtime, such as one brokered credential-backed outbound dependency

## What the design partner gets

- help bringing up `~/aegis` in a self-hosted environment
- help wiring one coding-agent execution path to the local Aegis runtime
- the canonical exfil demo running locally as a trust check before workflow rollout
- direct support during pilot setup and during the evaluation window

## What success looks like

The pilot is successful if, by the end of the window, the design partner can:

- run one real internal coding-agent workflow through Aegis in its own environment
- show that direct egress is denied by default for that workflow
- verify signed receipts and proof bundles for pilot executions
- tell a reviewer what the receipt proves and what it does not prove

## What this pilot is not

- not hosted
- not multi-tenant
- not a broad policy program
- not a dashboard rollout
- not a promise of host attestation or trust independent of the host

## Entry criteria

- a Linux environment where Firecracker and the current Aegis runtime can run
- one named owner from platform or security
- one named owner from the coding-agent workflow team
- agreement to keep the pilot to one workflow and one or two policy paths

For the exact first-run path, use [quickstart.md](quickstart.md). For the canonical proof, use [demo-exfiltration.md](demo-exfiltration.md).

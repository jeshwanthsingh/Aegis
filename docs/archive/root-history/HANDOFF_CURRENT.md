# Aegis Current-State Handoff

## 1. Who I am and what I'm doing

This document is a current-state engineering handoff written against the repo as it exists now, not against older project plans.

It is meant for the next engineer or advisor session that needs to continue Aegis without inheriting stale assumptions.

It is written to be durable first. Workstation-specific notes from the authoring session are contained in the final section instead of being mixed into the main product story.

## 2. What Aegis is today

Aegis today is a local, single-host, Linux-only secure execution runtime built around Firecracker/KVM plus host-side receipt verification.

Current product identity:

- Runs untrusted agent-generated code inside disposable Firecracker microVMs instead of directly on the host.
- Keeps the host as the policy, brokerage, divergence, and receipt-signing control plane.
- Emits host-signed DSSE receipts and host-side proof bundles that can be verified offline.
- Supports a truthful network posture:
  - `none` by default
  - `egress_allowlist` when a policy explicitly declares outbound FQDNs or CIDRs
  - governed brokered outbound actions for the narrow approved path
- Ships packaged local demos as the canonical proof surface.
- Includes a minimal operator UI shell, but the runtime and receipt flow are the real product boundary today.

The honest way to describe the current product is:

- Runtime + Verify today
- local / single-host / Linux / KVM
- host-signed receipts
- governed outbound actions
- packaged demos for proof and recording
- local or internal-pilot use, not an Internet trust platform

## 3. What Aegis is not

Aegis is not:

- Authority
- trustless execution
- hardware attestation
- HSM/KMS-backed key custody
- a hosted multi-tenant execution platform
- a general agent governance cloud
- enterprise IAM
- a company-wide control plane
- a public proof system that removes trust in the host

It is also not a broad “safe internet access” sandbox. The current network story is explicit posture and governed paths, not arbitrary browser-like egress.

## 4. What has been accomplished so far

The meaningful completed work is real and should be treated as landed, not aspirational.

Receipt and proof surface:

- `6574a34` made signed DSSE receipts the only canonical receipt surface.
- `b77681b` bound the runtime envelope into the signed predicate schema.
- `6c0af24` bound universal baseline policy evidence into signed receipts.
- Receipt verification is now the canonical way to judge a run; `receipt.summary.txt` is convenience output, not the source of truth.

Network and policy honesty cleanup:

- `cce2666` renamed the misleading old `isolated` mode to `direct_web_egress`.
- `002c611` completed Pass A by making `egress_allowlist` the canonical networked mode and relegating legacy labels to compatibility/verification paths.
- Current docs and receipt semantics are aligned on `none` and `egress_allowlist` as the real current modes.

Signer hardening:

- `bce67ae` removed deterministic dev-signing fallback from signer creation.
- Older receipts may still verify with legacy provenance markers, but current runtime behavior no longer silently falls back to deterministic signing.

Exposure and trust-posture hardening:

- `18451d0` hardened default bind, auth, and CORS exposure posture.
- `cd1cd7e` closed remaining metrics and health exposure gaps.
- Non-loopback serving now requires `AEGIS_API_KEY`; wildcard CORS is blocked for non-local bind addresses.

Docs and repo cleanup:

- `175adeb` hardened setup, verification, and deprecation guidance.
- `9811ee9` cleaned public-push blockers and aligned demo tracking.
- `README.md`, `docs/setup-local.md`, `docs/trust-model.md`, `docs/receipt-model.md`, `SECURITY.md`, and `THREAT_MODEL.md` now describe a much more honest product boundary than the older handoff did.

Demo surface and truthful operator shell:

- `a3a2a50`, `715b8bd`, and `8183f92` replaced the earlier proving-ground framing with a more truthful minimal demo/operator surface.
- The packaged demo harness is the canonical product narrative, not ad hoc scripts outside the repo story.

Pass B blocked-egress work:

- `1fd89ab` completed Pass B by splitting the old overloaded egress demo into two executions under one top-level entrypoint.
- Phase A is adversarial and is expected to terminate on `network.denied_repeated` while still producing a verified receipt with `blocked_egress` evidence for `ip`, `fqdn`, and `rfc1918`.
- Phase B is benign/brokered and is expected to complete normally with governed allow evidence and `broker_allowed_count=1`.
- This fixed the demo narrative without weakening divergence defaults, receipt schema, or the allowlist model.

Graphify-assisted repo review:

- Local Graphify outputs exist and were used as hotspot maps for repo/code review.
- They are useful for identifying concentration points, but they are local analysis artifacts, not shipped product state and not canonical repo truth.

## 5. Current product/demos/docs/repo state

Current repo truth:

- The current repo history contains Pass A, signer hardening, docs hardening, repo hygiene, and Pass B finalization.
- `HANDOFF_CURRENT.md` is the current engineering handoff.
- `HANDOFF.md` is stale and should not be treated as the current project truth.

Current canonical demos:

- `scripts/demo_up.sh`: bootstrap/local environment bring-up
- `scripts/demo_egress_allowlist.sh`: current canonical egress allowlist story
- `scripts/demo_clean.sh`: clean happy-path demo
- `scripts/demo_exfil_denied.sh`: denied exfil/containment demo
- `scripts/demo_broker_success.sh`: governed broker success demo

Current egress allowlist truth:

- The public-facing entrypoint remains one demo: `scripts/demo_egress_allowlist.sh`.
- Under the hood, `scripts/run_egress_allowlist_demo.py` now runs two executions.
- The current truth is not “Pass B is blocked.”
- The current truth is not “the two-execution split is still pending.”
- The current truth is that the two-execution model is already the landed fix.

Current docs truth:

- `README.md` is broadly aligned with the sober current product identity.
- `docs/setup-local.md` is detailed and materially current, including Linux/KVM assumptions, capability requirements, and current network semantics.
- `docs/demo-guide.md` now leads with `scripts/demo_egress_allowlist.sh` as the flagship demo and keeps the smaller scripts as supporting demos.
- `docs/trust-model.md` and `docs/receipt-model.md` are current enough to serve as the trust/product baseline.
- `PASS_A_SUMMARY.md` is still useful for the network/posture cleanup history.
- `PASS_B_FINALIZATION.md` and `PASS_B_DEMO_RUN.md` are the current Pass B truth.
- `PASS_B_SUMMARY.md` is now historical context, not the final Pass B state.
- `HANDOFF.md` is stale.

Current verification truth:

- Receipts verify offline from the proof bundle using `receipt.dsse.json`, the verification key, and bound artifacts.
- Verification proves receipt integrity and semantic consistency under the bundle key.
- Verification does not prove host honesty, host attestation, or trustless execution.

## 6. Current limitations and trust boundaries

This section is the most important thing not to blur.

Host trust remains central:

- The host control plane still decides policy enforcement, divergence, brokerage, proof generation, and signing.
- Receipts are host-signed execution records, not proof independent of the host.
- The operator, host filesystem, runtime assets, local Postgres, and signing key custody remain in the trust base.

The deployment boundary is still local and narrow:

- Linux only
- single host
- Firecracker/KVM required
- self-hosted / local or internal-pilot posture
- no hostile multi-tenant claim

Current network posture is more honest, not magically trustless:

- `egress_allowlist` is the truthful current networked mode.
- The old `direct_web_egress`/`isolated` story was an honesty cleanup, not a hardening breakthrough.
- Loopback remains allowed inside the guest for the governed broker path and is reflected in the receipt allowlist.

Current control-plane exposure still has caveats:

- `GET /v1/health` remains unauthenticated.
- Execute endpoints are wrapped in auth, but if `AEGIS_API_KEY` is unset the orchestrator allows unauthenticated local-dev execution on loopback.
- This is constrained compared with earlier posture, but it is still a real trust and operator-footgun boundary that should be described honestly.

Proof bundles are useful but not yet locked down:

- Proof directories are created with `0755`.
- Receipt, public-key, summary, and artifact files are written with `0644`.
- That is workable for local development, but not a strong final permissions posture.

The demo is strong for some things and weak for others:

- Good for proving containment behavior, governed outbound behavior, and offline receipt verification.
- Good for recording a truthful local demo.
- Not good enough to imply hostile-host trust, public trustless proof, or production multi-tenant readiness.

The UI is not the main product:

- There is a minimal operator shell and demo/session surface.
- It should be treated as a thin operator aid around the runtime and receipts, not as a mature platform UX.

## 7. Major technical debt / architecture hotspots

These are the real hotspots another engineer should assume are still live.

Orchestration concentration:

- The host orchestrator is still a large concentration point for request validation, policy decisions, divergence handling, brokerage, proof assembly, and serving API endpoints.
- This concentration is functional today, but it is an architecture chokepoint and a review hotspot.

Guest-runner concentration:

- The guest-side runner is still a critical chokepoint for executing code, collecting telemetry, and shaping what the host receives back from inside the VM.
- It is intentionally smaller than the host control plane, but it is still a critical trust boundary component.

Executor shell-out debt:

- `internal/executor/lifecycle.go` still shells out to `ip` and `iptables`.
- That keeps the network path more brittle and less self-contained than it should be.

Capability surface and DNS path:

- The orchestrator still binds UDP/53 in-process, which currently requires `cap_net_bind_service`.
- `TECH_DEBT.md` already calls out the cleaner future shape: bind DNS on a high port and redirect guest DNS queries to it.

Boot-order debt:

- `cmd/orchestrator/main.go` still connects to Postgres before calling `policy.Load`.
- That is a smaller issue than the trust boundary work, but it is still tracked debt and a sign that bootstrapping can be cleaner.

Proof-bundle permissions:

- Current proof bundle directory and file modes are permissive.
- This should remain on the hardening list until tightened.

Docs/repo state drift:

- `HANDOFF.md` is stale.
- Local Graphify outputs and diagnostics are useful, but they are not canonical docs and should not quietly drive product truth.

## 8. What is left to do next

### A. Before public push / public artifact

- Resolve branch and merge state cleanly before any public push.
- Keep local-only artifacts such as Graphify outputs, scratch diagnostics, `.codex/`, and demo output directories out of public history unless they are intentionally curated.
- Replace or clearly deprecate the stale `HANDOFF.md` so future sessions do not pick up the wrong project state.
- Keep `README.md`, `docs/demo-guide.md`, and the handoff aligned if the packaged demo surface changes again.
- Re-run the packaged demos you want to show publicly and capture the exact proof dirs/output lines you intend to point people at.
- Sanity-check the public story for repo/history cleanliness before publishing a recording or blog update.

### B. Before a serious design-partner demo

- Tighten proof-bundle permissions so local artifacts are not world-readable by default.
- Decide whether unauthenticated loopback execution remains acceptable as-is or whether it needs an explicit opt-in switch beyond “`AEGIS_API_KEY` unset on loopback.”
- Do a fresh-host or fresh-VM validation pass of `demo_up.sh` and the packaged demos so the setup story is reproducible outside the current dev machine.
- Align the remaining docs so trust, setup, demo flow, and receipt semantics tell one consistent story.
- Record one truthful canonical demo sequence instead of improvising around older scripts or stale docs.

### C. Later engineering hardening

- Reduce orchestration concentration by separating responsibilities more cleanly on the host side.
- Revisit guest-runner concentration and minimize the amount of guest-side logic that has to be trusted for evidence quality.
- Replace shell-outs to `ip` and `iptables` with a tighter internal implementation where practical.
- Rework the DNS interception path so `cap_net_bind_service` is no longer required.
- Improve key custody and signing posture beyond local host-managed strict mode.
- Continue trimming stale compatibility paths once old proof bundles and older docs no longer need them.

### D. Explicitly not now

- Do not start Authority work.
- Do not present Aegis as trustless or attested before those properties actually exist.
- Do not turn this into a hosted multi-tenant platform project right now.
- Do not broaden the product into a company-wide agent governance system.
- Do not make the UI the center of gravity before the runtime/trust/hardening work is ready.
- Do not invent new public demo concepts when the current packaged demos already prove the core story.

## 9. What not to build next

The easiest way to waste momentum here is to build the wrong next layer.

Do not build next:

- Authority
- a hosted SaaS wrapper around the current codebase
- multi-tenant scheduling/control-plane features
- broad policy-productization beyond the current truthful runtime boundary
- heavy UI polish disconnected from runtime hardening and demo truth
- new demo theater that hides host trust, receipt limits, or the actual local-only posture

The right next work is still cleanup, alignment, hardening, and a truthful public artifact for the product that already exists.

## 10. Operating pattern with Codex

The operating pattern that has worked should remain explicit:

- Codex is the execution hands.
- The advisor is the brain.
- One Pass equals one commit.
- For non-trivial work, do recon first and verify current state before editing.
- Keep a summary/finalization doc per pass when the pass materially changes the product or demo truth.
- Push back on scope creep aggressively.
- Prefer the smallest truthful fix over a broader redesign.
- Name exact verification commands before claiming success.
- Treat the repo as source of truth over memory, earlier chat context, or stale handoff docs.

Graphify can help as a local hotspot map during recon, but it should stay in its place:

- useful for finding concentration points
- not a substitute for reading the actual code/docs
- not canonical repo state unless intentionally promoted into committed docs

## 11. Handoff notes / how to continue

If you are picking this up next, start here:

- Inspect `git status --short`, `git branch --show-current`, and `git log --oneline -n 15` before changing anything.
- Read `README.md`, `docs/setup-local.md`, `docs/trust-model.md`, `docs/receipt-model.md`, `SECURITY.md`, `THREAT_MODEL.md`, `PASS_A_SUMMARY.md`, `PASS_B_FINALIZATION.md`, and `PASS_B_DEMO_RUN.md`.
- Treat `HANDOFF.md` as historical only unless it is explicitly refreshed.
- Treat `PASS_B_SUMMARY.md` as historical context, not the final Pass B truth.
- If you need current demo truth, trust the packaged scripts and `scripts/run_egress_allowlist_demo.py` over older narrative docs.
- If you need architecture review, use `graphify-out/GRAPH_REPORT.md` only as a local map, then confirm against code.

Practical continuation order:

- First clean up branch/docs/repo-state drift.
- Then make the public/demo artifact story coherent.
- Then spend hardening effort on proof permissions and loopback/auth posture.
- Only after that should larger architectural refactors compete for attention.

Snapshot at time of writing:

- The handoff was authored from branch `pass-b/blocked-egress` at tip `1fd89ab` (`pass b: finalize blocked egress receipts and split egress demo`).
- Local `main` in that worktree was still at `cce2666` (`network: rename isolated mode to direct_web_egress`).
- The worktree was dirty, with tracked edits in core docs/runtime files and local-only artifacts including `graphify-out/`, `.graphify_*`, `scripts/demo_output/`, diagnostics notes, and `.codex/`.

The key thing not to lose is honesty. Aegis is strongest when it says exactly what it proves today and refuses to imply the rest.

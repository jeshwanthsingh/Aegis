# Receipt Model

Aegis writes one proof bundle per execution. The bundle is a host-side record of what the runtime observed, enforced, and signed for that execution ID.

## Bundle Contents

A typical proof directory contains:

- `receipt.dsse.json`
- `receipt.pub`
- `receipt.summary.txt`
- `output-manifest.json`
- one or both of `stdout.txt` and `stderr.txt`
- one or both of `stdout.truncated.txt` and `stderr.truncated.txt` when capture was truncated

`receipt.dsse.json` is the signed record.

`receipt.pub` is the Ed25519 public key used to verify that record.

`receipt.summary.txt` is a convenience text projection for operators. It is not itself signed and it is not the source of truth for verification.

The bundle matters because the signed statement binds the output artifacts by name and `sha256`.

## What Is Signed

The DSSE signature covers an in-toto Statement v1 with:

- `_type=https://in-toto.io/Statement/v1`
- `payloadType=application/vnd.in-toto+json`
- `predicateType=https://aegis.dev/ExecutionReceipt/v1`
- `predicate.version=v1`

The signed statement includes:

- a `subject[]` list naming each bound output artifact and its `sha256`
- an Aegis predicate describing execution identity, outcome, policy evidence, runtime envelope, trust posture, and governed-action evidence

Because the whole statement is signed, the artifact list and predicate are signed together.

In the current implementation, the bound artifacts are the execution output files named in `subject[]`, typically `output-manifest.json` plus captured stdout and stderr. The convenience files `receipt.pub` and `receipt.summary.txt` are not part of that signed artifact set.

## What The Predicate Binds

The current predicate binds these categories of evidence:

- Execution identity and timing:
  `execution_id`, `workflow_id`, `task_class`, `declared_purpose`, `workspace_id`, `started_at`, `finished_at`
- Execution result:
  `execution_status`, `result_class`, `outcome`, `denial`, `divergence`, `runtime_event_count`, `point_decisions`
- Policy evidence:
  `policy_digest`, `policy`, `intent_digest`, `intent_digest_algo`
- Runtime envelope:
  `backend`, `runtime.profile`, `runtime.vcpu_count`, `runtime.memory_mb`, `runtime.cgroup.*`, `runtime.network.*`, `runtime.broker.*`, `runtime.applied_overrides`
- Governed outbound evidence:
  `broker_summary` and `governed_actions`, including per-action `decision`, `rule_id`, `policy_digest`, `binding_name`, `response_digest`, and `denial_marker` when present
- Trust posture:
  `signer_key_id`, `trust.signing_mode`, `trust.key_source`, `trust.attestation`, `trust.verification_material`, `trust.limitations`, and top-level `limitations`

For the raw contract, use [../schemas/receipt-predicate-v1.json](../schemas/receipt-predicate-v1.json).

## Governed Actions And Denials

A denied direct outbound attempt is carried in two places:

- `denial`
- `governed_actions`

For the packaged exfil demo, current verification output shows fields such as:

- `denial_class=governed_action`
- `denial_rule_id=governance.direct_egress_disabled`
- `denial_marker=direct_egress_denied`
- `governed_action_1=kind=network_connect decision=deny ...`

A brokered outbound success shows:

- `broker_allowed_count=1`
- `broker_bindings_used=demo`
- `governed_action_1=kind=http_request decision=allow ...`

That deny path is specific to the no-network or governed-demo configuration. The receipt also records the runtime network mode directly:

- `none`: no guest NIC
- `direct_web_egress`: direct public TCP 80/443 is allowed while private ranges, metadata, and guest DNS stay blocked
- `allowlist`: DNS is intercepted and narrow outbound rules are opened only for declared allowlist destinations

Older bundles may still carry the legacy label `isolated`; current verification normalizes that to `direct_web_egress` in reporting.

## How Verification Works

`./.aegis/bin/aegis receipt show --proof-dir <proof_dir>` prints a sectioned review of the bundle:

- verification status
- bundle paths
- artifact inventory
- execution result
- governed actions and capability summaries
- broker summary
- trust and receipt limitations

`./.aegis/bin/aegis receipt verify --proof-dir <proof_dir>` prints a machine-readable key=value summary. In that mode, the CLI resolves `receipt.pub` from the same proof directory unless you explicitly supply a different key with `--file` and `--public-key`.

`receipt show` and `receipt verify` do not trust `receipt.summary.txt`. They recompute verification from `receipt.dsse.json`, the verification key, and the bound artifacts in the bundle.

Current verification checks:

1. the DSSE payload type, statement type, predicate type, and signer key ID shape
2. the Ed25519 signature on the DSSE envelope
3. receipt semantic invariants such as valid `result_class`, denial structure, runtime envelope shape, and governed-action consistency
4. the `sha256` of each bound artifact against the signed `subject[]` list
5. the `output-manifest.json` inventory when present

## What `verification=verified` Means

`verification=verified` means:

- the bundle is complete enough to verify
- the signature validated
- the receipt parsed as the expected Aegis predicate
- the artifact set on disk matched the signed artifact set
- the receipt semantics passed validation

It does not mean:

- hardware attestation
- proof that the host was honest
- proof that the public key in the bundle is trusted by itself
- proof that the host could not forge or suppress evidence

If you need explicit trust-root pinning, verify with an expected public key using `receipt verify --file ... --public-key ...`, or separately compare `signer_key_id` to the signer you trust.

## Trust Limitations In The Receipt

Current receipts surface trust limitations directly.

Trust-posture limitations include:

- `host_attestation_absent`
- `dev_signing_mode` when dev signing is used
- `fallback_dev_seed` when the dev fallback seed is used

Receipt-level limitations may also include:

- `host attestation deferred`
- `captured standard stream artifacts may be truncated`
- `file.open semantics are read-only in RuntimeEvent v1`

The packaged local demo currently runs in strict signing mode with a configured seed and still reports `attestation=absent`. That is expected. Strict signing is not hardware attestation.

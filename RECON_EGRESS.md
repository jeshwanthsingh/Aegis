# RECON_EGRESS

## 1. Network mode definitions
- `direct_web_egress` is defined in the policy constants at `internal/policy/policy.go:12-17`.
- The other defined mode strings are `none`, legacy `isolated`, and `allowlist` (`internal/policy/policy.go:12-17`).
- `NormalizeNetworkMode()` maps legacy `isolated` to `direct_web_egress` (`internal/policy/policy.go:69-80`), and receipt verification applies the same normalization to legacy receipt payloads (`internal/receipt/verify.go:323-341`).
- The process default is `none`: `policy.Default()` sets `Network.Mode` to `none` (`internal/policy/policy.go:82-115`), the checked-in default policy file also sets `network.mode: none` (`configs/default-policy.yaml:6-8`), and the orchestrator loads that policy file at startup (`cmd/orchestrator/main.go:55-58`, `cmd/orchestrator/main.go:89-93`).
- There is no per-request `network.mode` field in the execute API. `ExecuteRequest` only exposes `intent` and `capabilities` for per-execution policy input (`internal/api/handler.go:32-41`).
- Each execution still uses the process-wide `pol.Network`: `acquireExecutionVM()` passes `pol` into `executor.NewVM(...)` (`internal/api/handler.go:404-437`), and `NewVM()` calls `SetupNetwork(uuid, pol.Network, bus)` (`internal/executor/firecracker.go:141-180`).
- Per-execution input does carry network facts, but only as intent scope, not VM mode: `network_scope` is `allow_network`, `allowed_domains`, `allowed_ips`, `max_dns_queries`, and `max_outbound_conns` (`internal/policy/contract/contract.go:39-45`, `internal/capabilities/request.go:161-191`).

## 2. Current egress enforcement path
- Execution start to VM creation runs through `NewHandler()` / `NewStreamHandler()` -> `acquireExecutionVM()` -> `executor.NewVM(...)` (`internal/api/handler.go:549-620`, `internal/api/handler.go:657-659`, `internal/api/handler.go:880-958`, `internal/api/handler.go:1002-1004`, `internal/executor/firecracker.go:141-180`).
- Host-side TAP setup happens in `SetupNetwork()`: it creates `tap-<id>`, assigns the host `/30`, brings the TAP up, and enables IPv4 forwarding (`internal/executor/lifecycle.go:225-249`).
- Firecracker gets guest network access only if `networkCfg != nil`; then `NewVM()` attaches `eth0` with `guest_mac` and `host_dev_name` pointing at the TAP (`internal/executor/firecracker.go:268-275`).
- The guest only receives network parameters when `vm.Network != nil` (`internal/api/handler.go:1146-1152`, `internal/models/types.go:5-15`). Inside the guest, `setupNetwork()` brings up `eth0`, installs the guest IP, adds the default route via the host gateway, and bind-mounts a temp `/etc/resolv.conf` pointing DNS at that gateway (`guest-runner/main.go:405-472`).
- The exact host rule generation is:

```text
iptables -t nat -A POSTROUTING -s <subnet> ! -d <subnet> -j MASQUERADE
iptables -I FORWARD 1 -i <tap> -j DROP
# direct_web_egress only
iptables -I FORWARD 1 -i <tap> -p tcp --dport 80 -j ACCEPT
iptables -I FORWARD 1 -i <tap> -p tcp --dport 443 -j ACCEPT
# all networked modes
iptables -I FORWARD 1 -i <tap> -d 10.0.0.0/8 -j DROP
iptables -I FORWARD 1 -i <tap> -d 172.16.0.0/12 -j DROP
iptables -I FORWARD 1 -i <tap> -d 192.168.0.0/16 -j DROP
iptables -I FORWARD 1 -i <tap> -d 169.254.169.254 -j DROP
iptables -I FORWARD 1 -i <tap> -p udp --dport 53 -j DROP
iptables -I FORWARD 1 -i <tap> -p tcp --dport 53 -j DROP
```

  (`internal/executor/lifecycle.go:251-287`, `internal/executor/lifecycle.go:831-845`)
- Allowlist mode is partial and preset-based today. Presets are defined in `policy.NetworkPresets` (`internal/policy/policy.go:19-38`), expanded by `resolvePresetHosts()` (`internal/executor/lifecycle.go:507-523`), enforced by `startDNSInterceptor()` (`internal/executor/lifecycle.go:644-655`), and converted into per-IP TCP 80/443 accept rules by `allowResolvedIP()` (`internal/executor/lifecycle.go:607-635`).
- DNS is host-mediated only in allowlist mode. The host-side custom resolver reads `/etc/resolv.conf`, prefers non-loopback nameservers, falls back to `127.0.0.53` or `8.8.8.8` / `1.1.1.1`, and is used by the DNS interceptor (`internal/executor/lifecycle.go:563-605`, `internal/executor/lifecycle.go:637-807`). The guest-side temp resolver file is created by `createTempResolvConf()` (`guest-runner/main.go:234-257`, `guest-runner/main.go:445-452`).
- Partial allow/deny mechanisms exist today, but they are split:
  - Host firewall allowlist: preset hostnames only in `allowlist` mode (`internal/policy/policy.go:19-38`, `internal/executor/lifecycle.go:263-273`, `internal/executor/lifecycle.go:607-635`).
  - Host firewall hard-coded denylist: RFC1918, metadata IP, and guest DNS (`internal/executor/lifecycle.go:831-845`).
  - Per-execution intent allowlist: `allowed_domains` / `allowed_ips` only affect point-decision evaluation, not `iptables` (`internal/policy/evaluator/evaluator.go:163-189`).

## 3. The enforcement gap, concretely
`direct_web_egress` is still broad public-IP web egress, not default-deny named allow. When `pol.Network.Mode` normalizes to `direct_web_egress`, Aegis creates a TAP/NAT path, inserts a TAP-scoped default `DROP`, adds TAP-scoped `ACCEPT` rules only for TCP destination ports 80 and 443, then prepends explicit `DROP` rules for `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, and guest DNS on UDP/TCP 53 (`internal/executor/lifecycle.go:251-287`, `internal/executor/lifecycle.go:831-845`). The guest is still told to use the host gateway as its DNS server (`internal/api/handler.go:1147-1151`, `guest-runner/main.go:445-452`), but the DNS interceptor only starts in `allowlist` mode (`internal/executor/lifecycle.go:263-273`, `internal/executor/lifecycle.go:644-655`), so `direct_web_egress` provides no guest DNS service. Concretely: today it permits direct guest TCP connects to public IP addresses on ports 80/443 only, NATed out of the host; it does not enforce domain names, and it denies private ranges, metadata, DNS, and all non-80/443 forwarded traffic.

## 4. The brokered outbound path
- Guest entry point: the guest starts an HTTP proxy on `127.0.0.1:8888` before running user code, and the user process gets `HTTP_PROXY` / `HTTPS_PROXY` pointing there (`guest-runner/broker_proxy.go:18-23`, `guest-runner/broker_proxy.go:49-75`, `guest-runner/main.go:586-591`, `guest-runner/main.go:667-667`).
- Vsock transport: the guest proxy dials Firecracker vsock host CID `2` on port `1025` (`guest-runner/broker_proxy.go:18-23`, `guest-runner/broker_proxy.go:118-145`). On the host, `StartBrokerListener()` listens on `<vsock_uds_path>_1025` and dispatches each connection to `handleBrokerConn()` (`internal/executor/proxy.go:18-35`, `internal/executor/proxy.go:54-89`).
- Host-side handler: `handleBrokerConn()` decodes `broker.BrokerRequest`, calls `b.Handle(req)`, and returns a `broker.BrokerResponse` (`internal/executor/proxy.go:67-89`).
- Governance names three action types: `http_request`, `dependency_fetch`, and `network_connect` (`internal/governance/governance.go:17-20`).
- The broker transport itself is HTTP-only. The guest wire format is `method/url/headers/body` (`guest-runner/broker_proxy.go:25-32`), the host executes `http.NewRequest(...)` and strips/injects HTTP headers (`internal/broker/broker.go:168-223`), and `CONNECT` is explicitly denied (`guest-runner/broker_proxy.go:77-82`, `internal/broker/broker.go:66-88`).
- Practically, the brokered outbound path supports `http_request` and the HTTP-flavored `dependency_fetch`; it does not implement arbitrary raw `network_connect` brokerage (`internal/broker/broker.go:49-52`, `internal/broker/broker.go:168-223`).
- Demo wiring:
  - `scripts/demo_broker_success.sh` is a wrapper into `aegis_demo.py broker-success` (`scripts/demo_broker_success.sh:1-4`).
  - `demo_broker_success()` opens `/dev/tcp/127.0.0.1/8888`, sets `allow_network=true`, `allowed_ips=["127.0.0.1"]`, and broker domains/delegations, then expects verified `broker_allowed_count=1` (`scripts/aegis_demo.py:320-379`, `scripts/aegis_demo.py:382-420`).
  - The canonical harness uses the same brokered allow path in `run_governed_allow()` (`scripts/run_canonical_demo.py:366-382`, `scripts/run_canonical_demo.py:572-696`).
  - The denied demos are not brokered; they exercise direct-egress denial evidence (`scripts/aegis_demo.py:267-316`, `scripts/run_canonical_demo.py:614-714`).

## 5. Receipt schema — egress-relevant fields
- The receipt builder is `internal/receipt/builder.go`, called from `emitSignedReceipt()` with `TelemetryEvents: bus.Drain()`, `Policy`, and `Runtime` (`internal/api/handler.go:1239-1269`, `internal/receipt/builder.go:19-24`, `internal/receipt/builder.go:48-94`).
- Egress-relevant predicate fields today are:
  - `policy.baseline.network.mode` / `policy.baseline.network.presets`, populated from the loaded policy in `policyEvidenceForExecution()` and cloned into the predicate (`internal/api/handler.go:249-288`, `internal/receipt/types.go:141-154`, `internal/receipt/builder.go:97-129`).
  - `runtime.network.enabled` / `runtime.network.mode` / `runtime.network.presets`, populated from `vm.Network` in `runtimeEnvelopeForExecution()` and cloned into the predicate (`internal/api/handler.go:204-247`, `internal/receipt/types.go:101-127`, `internal/receipt/builder.go:131-166`).
  - `runtime_event_count`, `point_decisions`, and `divergence`, all derived from summarized telemetry (`internal/receipt/types.go:177-185`, `internal/receipt/builder.go:50-54`, `internal/receipt/builder.go:192-233`).
  - `broker_summary`, derived from `credential.allowed` / `credential.denied` telemetry, including request/allow/deny counts plus allowed/denied domains and bindings used (`internal/receipt/types.go:194-201`, `internal/receipt/builder.go:197-200`, `internal/receipt/builder.go:260-297`).
  - `governed_actions.actions` / `governed_actions.normalized`, populated from `telemetry.KindGovernedAction`; each entry records `action_type`, `target`, `resource`, `method`, `capability_path`, `decision`, `outcome`, `used`, `rule_id`, `policy_digest`, `brokered`, `binding_name`, `response_digest`, `denial_marker`, `audit_payload`, and `error` (`internal/receipt/types.go:203-252`, `internal/receipt/builder.go:234-259`, `internal/receipt/builder.go:299-307`).
  - Top-level `denial.class` / `denial.rule_id` / `denial.marker`, derived from the first denied governed action or policy-denied execution (`internal/receipt/types.go:53-64`, `internal/receipt/builder.go:310-352`).
- There is no dedicated receipt field for “blocked outbound attempts count.” The schema has no standalone blocked-egress counter; blocked attempts only appear indirectly via `point_decisions.deny_count`, denied `governed_actions`, and top-level `denial` (`internal/receipt/types.go:161-191`, `internal/receipt/types.go:203-252`).

## 6. Tests
All `internal/...` tests run in CI via `go test ./cmd/... ./internal/...`, and all `guest-runner/...` tests run in CI via `go test ./...` in `guest-runner` (`.github/workflows/ci.yml:35-40`).

- `internal/executor/lifecycle_test.go`: host-side allowlist DNS path, DNS deny telemetry, upstream resolver fallback, and legacy `isolated` normalization (`internal/executor/lifecycle_test.go:38-207`). CI: yes. Denial asserted: yes, for DNS deny; no raw packet-level `iptables` test.
- `internal/executor/vsock_test.go`: runtime `net.connect` -> point decisions, governed-action denials for direct egress, and divergence escalation (`internal/executor/vsock_test.go:207-294`, `internal/executor/vsock_test.go:296-372`, `internal/executor/vsock_test.go:374-450`, `internal/executor/vsock_test.go:452-531`). CI: yes. Denial asserted: yes.
- `internal/policy/evaluator/evaluator_test.go`: per-intent connect allow/deny logic (`internal/policy/evaluator/evaluator_test.go:27-33`, `internal/policy/evaluator/evaluator_test.go:86-98`, `internal/policy/evaluator/evaluator_test.go:138-158`). CI: yes. Denial asserted: yes.
- `internal/policy/divergence/evaluator_test.go`: repeated denied connects escalate to `kill_candidate` (`internal/policy/divergence/evaluator_test.go:54-64`, `internal/policy/divergence/evaluator_test.go:174-187`). CI: yes. Denial asserted: yes, but as divergence behavior rather than firewall behavior.
- `internal/governance/governance_test.go`: broker domain denial and direct-egress rule-id mapping (`internal/governance/governance_test.go:31-49`, `internal/governance/governance_test.go:51-77`). CI: yes. Denial asserted: yes.
- `internal/broker/broker_test.go`: broker domain denial, missing-binding denial, `CONNECT` denial, dependency-fetch grant/deny, and governed-action / credential telemetry (`internal/broker/broker_test.go:30-42`, `internal/broker/broker_test.go:64-81`, `internal/broker/broker_test.go:106-119`, `internal/broker/broker_test.go:149-179`, `internal/broker/broker_test.go:230-264`). CI: yes. Denial asserted: yes.
- `internal/api/handler_test.go`: SSE stream includes `dns.query` deny events (`internal/api/handler_test.go:671-736`). CI: yes. Denial asserted: yes.
- `internal/api/helpers_test.go`: receipt runtime envelope carries network / broker state (`internal/api/helpers_test.go:152-190`). CI: yes. Denial asserted: no; representation only.
- `guest-runner/runtime_sensor_test.go`: guest runtime sensor emits `net.connect` events from observed socket state (`guest-runner/runtime_sensor_test.go:12-39`, `guest-runner/runtime_sensor_test.go:71-101`). CI: yes. Denial asserted: no; event capture only.
- `guest-runner/main_test.go`: guest temp `resolv.conf` generation is readable and correctly written (`guest-runner/main_test.go:110-132`). CI: yes. Denial asserted: no; plumbing only.
- `internal/policy/policy_test.go`: policy validation accepts `direct_web_egress` and normalizes legacy `isolated` (`internal/policy/policy_test.go:21-46`). CI: yes. Denial asserted: no; config validation only.
- `internal/receipt/builder_test.go`, `internal/receipt/verify_test.go`, and `internal/receipt/schema_test.go`: receipt network mode normalization, governed-action denial marker preservation, and schema acceptance of `direct_web_egress` / legacy `isolated` (`internal/receipt/builder_test.go:263-333`, `internal/receipt/builder_test.go:453-559`, `internal/receipt/verify_test.go:226-281`, `internal/receipt/schema_test.go:37-58`). CI: yes. Denial asserted: yes for receipt semantics, not live enforcement.

## 7. Demos
- `scripts/demo_up.sh`, `scripts/demo_status.sh`, `scripts/demo_down.sh`: wrappers around harness control, not execution demos (`scripts/demo_up.sh:1-4`, `scripts/demo_status.sh:1-4`, `scripts/demo_down.sh:1-4`, `scripts/aegis_demo.py:155-179`, `scripts/aegis_demo.py:189-249`). Network mode: n/a. Deny behavior: n/a.
- `scripts/demo_clean.sh`: wrapper to `aegis_demo.py clean` (`scripts/demo_clean.sh:1-4`). Uses the checked-in default policy `network.mode: none` and no per-run intent override (`configs/default-policy.yaml:6-8`, `scripts/aegis_demo.py:252-264`). Demonstrates allow behavior only.
- `scripts/demo_exfil_denied.sh`: wrapper to `aegis_demo.py exfil-denied` (`scripts/demo_exfil_denied.sh:1-4`). VM-layer network mode stays `none` from the default policy, while per-run intent sets `allow_network=false` with no allowed IPs/domains (`configs/default-policy.yaml:6-8`, `scripts/aegis_demo.py:267-316`). Demonstrates deny behavior.
- `scripts/demo_broker_success.sh`: wrapper to `aegis_demo.py broker-success` (`scripts/demo_broker_success.sh:1-4`). VM-layer network mode stays `none`; the demo uses guest loopback + broker scope (`allow_network=true`, `allowed_ips=["127.0.0.1"]`, broker domains/delegations) rather than direct host egress (`configs/default-policy.yaml:6-8`, `scripts/aegis_demo.py:320-379`). Demonstrates allow behavior.
- `scripts/run_canonical_demo.py`: canonical governed-action harness. The default story is governed allow + denied direct egress + receipt verification (`scripts/run_canonical_demo.py:366-382`). Its payloads use intent `network_scope`, not `pol.Network.Mode` (`scripts/run_canonical_demo.py:529-569`, `scripts/run_canonical_demo.py:572-714`). Demonstrates both allow and deny behavior.
- `scripts/run-proof-demo.sh`: manual proof-bundle harness. All four embedded intents set `allow_network=false`; the `network_denied` case attempts a denied connect (`scripts/run-proof-demo.sh:83-180`). Demonstrates both allow and deny behavior, but not `direct_web_egress`.
- `scripts/run-demo.sh`: legacy curl demo script. It comments about `direct_web_egress` / `allowlist`, but it never sets `network.mode` and just posts raw execute requests (`scripts/run-demo.sh:15-18`, `scripts/run-demo.sh:103-140`). Under the checked-in policy it therefore inherits `network.mode: none` (`configs/default-policy.yaml:6-8`). Demonstrates mixed behavior, but the mode comments are stale.
- `scripts/demo_exfil_aegis.py`: older one-off denied exfil demo. Uses intent `allow_network=false` with no allowed IPs/domains (`scripts/demo_exfil_aegis.py:62-115`, `scripts/demo_exfil_aegis.py:145-159`). Demonstrates deny behavior.
- `scripts/demo_exfil_baseline.sh` + `scripts/demo_receiver.py`: not an Aegis-contained demo; they perform plain host-side HTTP POST exfil to a local receiver (`scripts/demo_exfil_baseline.sh:4-15`, `scripts/demo_receiver.py:8-37`). Network mode: n/a. Demonstrates allow behavior outside Aegis.

## 8. Known constraints
- The documented happy path is Linux + Firecracker + `/dev/kvm`, and the checked baseline is Ubuntu 24.04.4 LTS (`docs/setup-local.md:3-17`, `docs/setup-local.md:39-50`). The demo harness enforces `/dev/kvm` access before startup (`scripts/aegis_demo.py:674-696`).
- Networked demos additionally depend on `ip`, `iptables`, `/dev/net/tun`, and host privileges such as CAP_NET_ADMIN; setup only warns about that, it does not self-provision it (`internal/setup/setup.go:242-267`).
- I found no tracked code or setup check that mentions or validates `vhost_net`. The repo checks `/dev/kvm`, `iptables`, and `/dev/net/tun`, not `vhost_net` (`docs/setup-local.md:9-17`, `internal/setup/setup.go:242-267`, `scripts/preflight.sh:47-60`, `scripts/preflight.sh:115-120`).
- The repo does mention WSL2 only as a performance caveat in the legacy `run-demo.sh` comments, not as a supported network-isolation path or a formal `vhost_net` limitation (`scripts/run-demo.sh:3-4`, `scripts/run-demo.sh:14`, `scripts/run-demo.sh:29`). I cannot confirm the “WSL2 lacks `vhost_net` so network isolation cannot run” claim from current tracked source.

## 9. Chokepoints touched by this work
- `internal/policy/policy.go`: owns network mode names, normalization, presets, and validation; any new named-allow model starts here (`internal/policy/policy.go:12-38`, `internal/policy/policy.go:69-80`, `internal/policy/policy.go:146-159`).
- `configs/default-policy.yaml`: checked-in default policy surface for `network.mode` (`configs/default-policy.yaml:6-8`).
- `internal/executor/lifecycle.go`: actual TAP setup, DNS interception, and `iptables` rule installation/removal (`internal/executor/lifecycle.go:225-294`, `internal/executor/lifecycle.go:421-466`, `internal/executor/lifecycle.go:542-845`).
- `internal/executor/firecracker.go`: decides whether a NIC exists at all by calling `SetupNetwork()` and attaching `eth0` (`internal/executor/firecracker.go:174-180`, `internal/executor/firecracker.go:268-275`).
- `internal/api/handler.go`: today passes only global `pol.Network` into VM creation and separately builds per-execution policy/runtime envelopes; a per-execution named-allow model will almost certainly change this seam (`internal/api/handler.go:204-288`, `internal/api/handler.go:404-437`, `internal/api/handler.go:657-659`, `internal/api/handler.go:1146-1152`).
- `internal/policy/contract/contract.go`: intent contract schema for per-execution network scope (`internal/policy/contract/contract.go:39-45`, `internal/policy/contract/contract.go:92-98`, `internal/policy/contract/contract.go:246-258`).
- `internal/capabilities/request.go`: public capabilities surface that compiles into `network_scope` / broker scope (`internal/capabilities/request.go:27-31`, `internal/capabilities/request.go:97-220`).
- `internal/policy/evaluator/evaluator.go`: per-event allow/deny logic for connects against `network_scope` (`internal/policy/evaluator/evaluator.go:163-189`).
- `internal/governance/governance.go`: maps denied direct egress events into governed-action evidence and denial markers (`internal/governance/governance.go:17-28`, `internal/governance/governance.go:250-302`, `internal/governance/governance.go:393-401`).
- `internal/receipt/types.go`, `internal/receipt/builder.go`, `internal/receipt/verify.go`, `schemas/receipt-predicate-v1.json`: receipt schema and verifier currently encode network mode, presets, governed actions, and denial markers; they will need to represent any new egress model honestly (`internal/receipt/types.go:101-191`, `internal/receipt/types.go:203-252`, `internal/receipt/builder.go:48-94`, `internal/receipt/verify.go:227-341`, `schemas/receipt-predicate-v1.json:305-325`, `schemas/receipt-predicate-v1.json:398-421`).
- `scripts/aegis_demo.py` and `scripts/run_canonical_demo.py`: current packaged demos prove intent-driven allow/deny and broker behavior, not host `direct_web_egress`; demo truth will need to stay aligned (`scripts/aegis_demo.py:252-379`, `scripts/run_canonical_demo.py:366-382`, `scripts/run_canonical_demo.py:529-714`).

## 10. Drive-by observations
- The current canonical demos do not exercise host-side `direct_web_egress` at all; they run under the checked-in default `network.mode: none` and rely on intent-level `network_scope` plus broker telemetry (`configs/default-policy.yaml:6-8`, `scripts/aegis_demo.py:252-379`, `scripts/run_canonical_demo.py:529-714`).
- `scripts/run-demo.sh` still labels tests as `direct_web_egress` / `allowlist`, but it never sets those modes and will inherit whatever policy the orchestrator already loaded (`scripts/run-demo.sh:103-140`, `configs/default-policy.yaml:6-8`).
- The receipt JSON schema still accepts legacy `isolated` for both baseline and runtime network mode, even though policy and verifier normalize it to `direct_web_egress` (`schemas/receipt-predicate-v1.json:312-319`, `schemas/receipt-predicate-v1.json:409-416`, `internal/policy/policy.go:69-80`, `internal/receipt/verify.go:323-341`).

# Graph Report - /home/cellardoor72/aegis  (2026-04-19)

## Corpus Check
- 167 files · ~145,989 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2109 nodes · 6180 edges · 54 communities detected
- Extraction: 64% EXTRACTED · 36% INFERRED · 0% AMBIGUOUS · INFERRED: 2242 edges (avg confidence: 0.79)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]

## God Nodes (most connected - your core abstractions)
1. `Error()` - 114 edges
2. `Fatal()` - 104 edges
3. `Default()` - 77 edges
4. `newRequest()` - 73 edges
5. `NewHandler()` - 73 edges
6. `New()` - 68 edges
7. `NewBusRegistry()` - 65 edges
8. `NewStreamHandler()` - 65 edges
9. `main()` - 62 edges
10. `NewStatsCounter()` - 58 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `Connect()`  [INFERRED]
  /home/cellardoor72/aegis/guest-runner/main.go → /home/cellardoor72/aegis/internal/store/postgres.go
- `main()` --calls--> `SetWorkerSlotsFunc()`  [INFERRED]
  /home/cellardoor72/aegis/guest-runner/main.go → /home/cellardoor72/aegis/internal/observability/metrics.go
- `TestReconcileMarksInflightAndRemovesOrphans()` --calls--> `reconcile()`  [INFERRED]
  /home/cellardoor72/aegis/cmd/orchestrator/main_test.go → /home/cellardoor72/aegis/cmd/orchestrator/main.go
- `TestReconcileRemovesUntrackedWarmOrphansWithoutReceipt()` --calls--> `reconcile()`  [INFERRED]
  /home/cellardoor72/aegis/cmd/orchestrator/main_test.go → /home/cellardoor72/aegis/cmd/orchestrator/main.go
- `receipt()` --calls--> `Load()`  [INFERRED]
  /home/cellardoor72/aegis/sdk/python/aegis/result.py → /home/cellardoor72/aegis/internal/config/config.go

## Communities

### Community 0 - "Community 0"
Cohesion: 0.02
Nodes (277): _a(), aa(), ac(), Ad(), ae(), ai(), An(), ao() (+269 more)

### Community 1 - "Community 1"
Cohesion: 0.02
Nodes (89): BrokerCapabilities, BrokerDelegation, CapabilitiesRequest, coerce_capabilities_payload(), coerceCapabilitiesPayload(), AegisClient, _coerce_execution_request(), coerceExecutionRequest() (+81 more)

### Community 2 - "Community 2"
Cohesion: 0.04
Nodes (176): APIError, busEntry, BusRegistry, ErrorEnvelope, ExecuteRequest, ExecuteResponse, Stats, StatsCounter (+168 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (128): nonFlushingResponseWriter, stubAddr, stubConn, Broker, digestBytes(), TestBroker_AllowedDomainsAndWildcardMatching(), TestBroker_DenyErrorUsesForbiddenEnvelope(), TestBroker_HandleRejectsInvalidURLAndMalformedBody() (+120 more)

### Community 4 - "Community 4"
Cohesion: 0.04
Nodes (141): buildPredicate(), BuildSignedReceipt(), buildSubjects(), classifyResult(), clonePolicyEnvelope(), cloneRuntimeEnvelope(), cloneStringMap(), deriveGovernedDenial() (+133 more)

### Community 5 - "Community 5"
Cohesion: 0.04
Nodes (122): base_intent(), BaseHTTPRequestHandler, _allowed_guest_code(), _assert_health(), _assert_no_secret_leak(), _assert_probe_requests(), _assert_result_artifacts(), _assert_stdout_marker() (+114 more)

### Community 6 - "Community 6"
Cohesion: 0.03
Nodes (108): ApplyEnvOverrides(), Load(), EffectiveCgroupLimits, EffectiveVMSpec, guestRuntimeEvent, guestRuntimeEventBatch, guestRuntimeSensorStatus, NetworkConfig (+100 more)

### Community 7 - "Community 7"
Cohesion: 0.05
Nodes (58): runtimeConnection, runtimeFileObservation, runtimeProcSnapshot, runtimeSensor, runtimeSensorBatch, runtimeSensorEvent, runtimeSensorStatus, runtimeSockaddr (+50 more)

### Community 8 - "Community 8"
Cohesion: 0.04
Nodes (57): CallToolParams, CallToolResult, ClientInfo, ExecuteArgs, ExecuteToolResult, Handler, healthResponse, healthWarmPool (+49 more)

### Community 9 - "Community 9"
Cohesion: 0.08
Nodes (64): New(), MCPBinPath(), TestEvaluateExecBranches(), TestEvaluateReadAndConnectBranches(), TestObserveBrokerDenialEscalatesKillCandidateAndTracksRule(), TestRepeatedDeniedFileOpenEscalatesWarn(), TestShellSpawnDeniedEscalatesWarn(), TestWriteDeniedEscalatesWarnForDenyPaths() (+56 more)

### Community 10 - "Community 10"
Cohesion: 0.05
Nodes (64): apiErrorEnvelope, doctorCheck, doctorReadyResponse, doctorStatus, executeRequest, executeResponse, healthResponse, Request (+56 more)

### Community 11 - "Community 11"
Cohesion: 0.07
Nodes (36): BrokerState, DecisionState, Evaluator, FileState, NetworkState, ObserveOutcome, ProcessState, State (+28 more)

### Community 12 - "Community 12"
Cohesion: 0.1
Nodes (44): apply_schema(), check_kvm(), cleanup_from_state(), cli_env(), demo_broker_success(), demo_clean(), demo_down(), demo_exfil_denied() (+36 more)

### Community 13 - "Community 13"
Cohesion: 0.06
Nodes (41): BrokerRequest, CompiledIntent, Delegation, InvalidRequestError, TestCompile(), brokerScopeJSON, BudgetLimits, budgetsJSON (+33 more)

### Community 14 - "Community 14"
Cohesion: 0.09
Nodes (42): CapabilityPath, CapabilityRecord, CapabilityUse, cloneStringMap(), Decision, DigestBrokerScope(), DigestIntent(), digestJSON() (+34 more)

### Community 15 - "Community 15"
Cohesion: 0.09
Nodes (15): appendTimelineRecord(), applyChunk(), applyTemplate(), buildIntent(), buildTimelineEntry(), createExecutionId(), createExecutionRecord(), parseSseBlock() (+7 more)

### Community 16 - "Community 16"
Cohesion: 0.07
Nodes (29): Artifact, BaselineNetworkPolicy, BaselinePolicy, BrokerSummary, BundlePaths, DenialClass, DenialSummary, DivergenceSummary (+21 more)

### Community 17 - "Community 17"
Cohesion: 0.15
Nodes (21): allowedGuestCode(), assertHealth(), assertNoSecretLeak(), assertProbeRequests(), assertResultArtifacts(), assertStdoutMarker(), brokerCapabilities(), brokerEvidenceStatus() (+13 more)

### Community 18 - "Community 18"
Cohesion: 0.13
Nodes (25): Is(), TestCreateTempResolvConfReadableByGuestUser(), BuildPlan(), haveDelegatedScopeSupport(), Mode, mustReadSeed(), Plan, TestBuildPlanFailsOnBlockingResult() (+17 more)

### Community 19 - "Community 19"
Cohesion: 0.15
Nodes (12): CgroupConfiguredData, CgroupSampleData, CleanupDoneData, CredentialBrokerData, DNSQueryData, Event, ExecExitData, GovernedActionData (+4 more)

### Community 20 - "Community 20"
Cohesion: 0.26
Nodes (6): ProxyRequest, ProxyResponse, responseWriterHijackGuard, handleConnect(), handleProxy(), proxyStream()

### Community 21 - "Community 21"
Cohesion: 0.29
Nodes (6): ComputeProfile, Default(), Load(), NetworkPolicy, Policy, ResourcePolicy

### Community 22 - "Community 22"
Cohesion: 0.33
Nodes (3): DecodeBrokerRequestJSON(), TestDecodeBrokerRequestJSON(), FuzzDecodeBrokerRequestJSON()

### Community 23 - "Community 23"
Cohesion: 0.33
Nodes (5): DivergenceCounters, DivergenceRuleHit, DivergenceSeverity, DivergenceVerdict, PolicyDivergenceResult

### Community 24 - "Community 24"
Cohesion: 0.5
Nodes (4): CompiledContract, Principal, cloneStringMap(), Compile()

### Community 25 - "Community 25"
Cohesion: 0.5
Nodes (3): CedarAction, PointDecision, PolicyPointDecision

### Community 26 - "Community 26"
Cohesion: 0.67
Nodes (2): BrokerRequest, BrokerResponse

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (0): 

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (0): 

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (0): 

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (0): 

### Community 31 - "Community 31"
Cohesion: 1.0
Nodes (0): 

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (0): 

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (0): 

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (0): 

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (0): 

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (0): 

### Community 37 - "Community 37"
Cohesion: 1.0
Nodes (0): 

### Community 38 - "Community 38"
Cohesion: 1.0
Nodes (0): 

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (0): 

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (0): 

### Community 41 - "Community 41"
Cohesion: 1.0
Nodes (0): 

### Community 42 - "Community 42"
Cohesion: 1.0
Nodes (0): 

### Community 43 - "Community 43"
Cohesion: 1.0
Nodes (0): 

### Community 44 - "Community 44"
Cohesion: 1.0
Nodes (0): 

### Community 45 - "Community 45"
Cohesion: 1.0
Nodes (0): 

### Community 46 - "Community 46"
Cohesion: 1.0
Nodes (0): 

### Community 47 - "Community 47"
Cohesion: 1.0
Nodes (0): 

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (0): 

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (0): 

### Community 50 - "Community 50"
Cohesion: 1.0
Nodes (0): 

### Community 51 - "Community 51"
Cohesion: 1.0
Nodes (0): 

### Community 52 - "Community 52"
Cohesion: 1.0
Nodes (0): 

### Community 53 - "Community 53"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **167 isolated node(s):** `serverExposureConfig`, `executeRequest`, `executeResponse`, `healthResponse`, `apiErrorEnvelope` (+162 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 27`** (2 nodes): `index.js`, `register()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `vite.config.d.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `vite.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `tailwind.config.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (1 nodes): `tailwind.config.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (1 nodes): `tailwind.config.d.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `postcss.config.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (1 nodes): `vite.config.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (1 nodes): `demoTemplates.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (1 nodes): `main.tsx`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 37`** (1 nodes): `types.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 38`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `health.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `broker_allowed.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `verify_receipt.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `broker_denied.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `run_stream.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `authenticated.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `run_code.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `eslint.config.mjs`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `broker_smoke.test.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `index.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `verify_receipt.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 50`** (1 nodes): `run_stream.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 51`** (1 nodes): `health.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 52`** (1 nodes): `run_code.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 53`** (1 nodes): `authenticated.ts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Error()` connect `Community 0` to `Community 1`, `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 18`, `Community 20`?**
  _High betweenness centrality (0.175) - this node is a cross-community bridge._
- **Why does `Fatal()` connect `Community 3` to `Community 2`, `Community 4`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 13`, `Community 14`, `Community 18`, `Community 22`?**
  _High betweenness centrality (0.099) - this node is a cross-community bridge._
- **Why does `Run()` connect `Community 1` to `Community 0`, `Community 3`, `Community 4`, `Community 5`, `Community 8`, `Community 9`, `Community 10`, `Community 12`, `Community 14`, `Community 17`?**
  _High betweenness centrality (0.089) - this node is a cross-community bridge._
- **Are the 112 inferred relationships involving `Error()` (e.g. with `main()` and `buildMux()`) actually correct?**
  _`Error()` has 112 INFERRED edges - model-reasoned connections that need verification._
- **Are the 102 inferred relationships involving `Fatal()` (e.g. with `main()` and `TestValidateServerExposureRejectsNonLocalWithoutAuth()`) actually correct?**
  _`Fatal()` has 102 INFERRED edges - model-reasoned connections that need verification._
- **Are the 74 inferred relationships involving `Default()` (e.g. with `TestBuildMuxProtectsSensitiveRoutesWithSharedAuth()` and `TestBaseURLUsesConfigWhenEnvUnset()`) actually correct?**
  _`Default()` has 74 INFERRED edges - model-reasoned connections that need verification._
- **Are the 70 inferred relationships involving `newRequest()` (e.g. with `TestBuildMuxProtectsSensitiveRoutesWithSharedAuth()` and `doctorCmd()`) actually correct?**
  _`newRequest()` has 70 INFERRED edges - model-reasoned connections that need verification._
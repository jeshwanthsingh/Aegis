## 1. Go thread-locking at the raise site

### Command

```bash
rg -n "RaiseAmbient|LockOSThread|UnlockOSThread|ambient_capabilities_raised" /home/cellardoor72/aegis/cmd/orchestrator/main.go /home/cellardoor72/aegis/internal/capabilities/ambient.go
```

### Output

```text
/home/cellardoor72/aegis/internal/capabilities/ambient.go:18:// RaiseAmbient raises the specified Linux capabilities into the ambient
/home/cellardoor72/aegis/internal/capabilities/ambient.go:29:func RaiseAmbient(caps []string) error {
/home/cellardoor72/aegis/internal/capabilities/ambient.go:33:	runtime.LockOSThread()
/home/cellardoor72/aegis/cmd/orchestrator/main.go:97:	ambientRaiseErr := capabilities.RaiseAmbient(ambientCaps)
/home/cellardoor72/aegis/cmd/orchestrator/main.go:111:		observability.Info("ambient_capabilities_raised", fields)

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/cmd/orchestrator/main.go | sed -n '88,116p'
```

### Output

```text
    88		if err := executor.CleanupLeakedNetworks(); err != nil {
    89			observability.Warn("reconcile_leaked_networks_failed", observability.Fields{"error": err.Error()})
    90		}
    91	
    92		pol, err := policy.Load(*policyPath)
    93		if err != nil {
    94			observability.Fatal("startup_failed", observability.Fields{"step": "load_policy", "error": err.Error(), "policy_path": *policyPath})
    95		}
    96		observability.Info("policy_loaded", observability.Fields{"policy_path": *policyPath})
    97		ambientRaiseErr := capabilities.RaiseAmbient(ambientCaps)
    98		if ambientRaiseErr != nil {
    99			observability.Warn("ambient_capabilities_raise_failed", observability.Fields{
   100				"message": fmt.Sprintf("could not raise ambient capabilities (%s). Networked demos will fail. Run `make setcap` to grant capabilities to the orchestrator binary.", ambientRaiseErr.Error()),
   101				"error":   ambientRaiseErr.Error(),
   102				"caps":    ambientCaps,
   103			})
   104		} else {
   105			fields := observability.Fields{"caps": ambientCaps}
   106			if capAmbHex, err := currentCapAmbHex(); err == nil {
   107				fields["cap_amb_hex"] = capAmbHex
   108			} else {
   109				fields["cap_amb_error"] = err.Error()
   110			}
   111			observability.Info("ambient_capabilities_raised", fields)
   112		}
   113	
   114		apiKey := os.Getenv("AEGIS_API_KEY")
   115		allowedOrigins := parseAllowedOrigins(*allowedOriginsFlag)
   116		serverExposure := serverExposureConfig{

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/internal/capabilities/ambient.go | sed -n '24,60p'
```

### Output

```text
    24	// It is a no-op on non-Linux platforms and returns nil in that case.
    25	//
    26	// Requires that the calling process already has the capabilities in its
    27	// permitted and inheritable sets — typically via file capabilities set with
    28	// `setcap`.
    29	func RaiseAmbient(caps []string) error {
    30		// Linux capabilities are thread-scoped. Keep this goroutine pinned so the
    31		// thread that populates inheritable+ambient caps remains available for the
    32		// process lifetime; subsequent exec.Command calls need those thread caps.
    33		runtime.LockOSThread()
    34	
    35		hdr := unix.CapUserHeader{
    36			Version: unix.LINUX_CAPABILITY_VERSION_3,
    37			Pid:     0,
    38		}
    39		data := [2]unix.CapUserData{}
    40		if err := unix.Capget(&hdr, &data[0]); err != nil {
    41			return fmt.Errorf("capget: %w", err)
    42		}
    43	
    44		for _, capName := range caps {
    45			capNum, err := capabilityNumber(capName)
    46			if err != nil {
    47				return err
    48			}
    49			index := capNum / 32
    50			bit := uint32(1) << uint(capNum%32)
    51			if data[index].Permitted&bit == 0 {
    52				return fmt.Errorf("capability %s not in permitted set; run `make setcap` on the binary", capName)
    53			}
    54			data[index].Inheritable |= bit
    55		}
    56	
    57		if err := unix.Capset(&hdr, &data[0]); err != nil {
    58			return fmt.Errorf("capset inheritable: %w", err)
    59		}
    60	

```

## 2. The call path from HTTP handler to ip spawn

### Command

```bash
rg -n "NewHandler|NewStreamHandler|acquireExecutionVM|NewVM|SetupNetwork|runCmd\(|exec.Command\(" /home/cellardoor72/aegis/internal/api/handler.go /home/cellardoor72/aegis/internal/api /home/cellardoor72/aegis/internal/executor /home/cellardoor72/aegis/cmd/orchestrator/main.go
```

### Output

```text
/home/cellardoor72/aegis/cmd/orchestrator/main.go:278:	mux.HandleFunc("/v1/execute", api.WithAuth(apiKey, api.NewHandler(s, pool, warmPool, pol, assetsDir, rootfsPath, registry, stats, policyName, workspaceRegistry)))
/home/cellardoor72/aegis/cmd/orchestrator/main.go:279:	mux.HandleFunc("/v1/execute/stream", api.WithAuth(apiKey, api.NewStreamHandler(s, pool, warmPool, pol, assetsDir, rootfsPath, registry, stats, policyName, workspaceRegistry)))
/home/cellardoor72/aegis/internal/api/handler.go:66:	acquireExecutionVMFunc   = acquireExecutionVM
/home/cellardoor72/aegis/internal/api/handler.go:468:func acquireExecutionVM(ctx context.Context, warm *warmpool.Manager, execID string, req ExecuteRequest, pol *policy.Policy, computeProfile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler.go:495:	vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/api/handler.go:574:func NewHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
/home/cellardoor72/aegis/internal/api/handler.go:729:		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, execPolicy, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/api/handler.go:936:func NewStreamHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
/home/cellardoor72/aegis/internal/api/handler.go:1088:		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, execPolicy, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/api/handler.go:66:	acquireExecutionVMFunc   = acquireExecutionVM
/home/cellardoor72/aegis/internal/api/handler.go:468:func acquireExecutionVM(ctx context.Context, warm *warmpool.Manager, execID string, req ExecuteRequest, pol *policy.Policy, computeProfile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler.go:495:	vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/api/handler.go:574:func NewHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
/home/cellardoor72/aegis/internal/api/handler.go:729:		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, execPolicy, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/api/handler.go:936:func NewStreamHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
/home/cellardoor72/aegis/internal/api/handler.go:1088:		vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, execPolicy, computeProfile, assetsDir, rootfsPath, bus)
/home/cellardoor72/aegis/internal/executor/workspace.go:21:		cmd := exec.Command("/usr/sbin/mkfs.ext4", "-F", path)
/home/cellardoor72/aegis/internal/executor/lifecycle.go:229:func SetupNetwork(execID string, np policy.NetworkPolicy, bus *telemetry.Bus) (*NetworkConfig, error) {
/home/cellardoor72/aegis/internal/executor/lifecycle.go:405:	out, err := exec.Command("ip", "-o", "link", "show").CombinedOutput()
/home/cellardoor72/aegis/internal/executor/lifecycle.go:897:func runCmd(name string, args ...string) error {
/home/cellardoor72/aegis/internal/executor/lifecycle.go:898:	cmd := exec.Command(name, args...)
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:211:func TestSetupNetworkProgramsExpectedRules(t *testing.T) {
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:243:	cfg, err := SetupNetwork("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", policy.NetworkPolicy{
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:251:		t.Fatalf("SetupNetwork: %v", err)
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:293:func TestSetupNetworkStartsDNSOnlyWhenFQDNsPresent(t *testing.T) {
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:330:			_, err := SetupNetwork("30454c31-dfdf-4b5f-ae7c-1bddbf09ad6b", policy.NetworkPolicy{
/home/cellardoor72/aegis/internal/executor/lifecycle_test.go:335:				t.Fatalf("SetupNetwork: %v", err)
/home/cellardoor72/aegis/internal/api/handler_test.go:216:	vm, dispatch, fallbackReason, err := acquireExecutionVM(context.Background(), warm, execID, ExecuteRequest{Lang: "python", Profile: "standard"}, pol, pol.Profiles["standard"], "", "", nil)
/home/cellardoor72/aegis/internal/api/handler_test.go:218:		t.Fatalf("acquireExecutionVM returned error: %v", err)
/home/cellardoor72/aegis/internal/api/handler_test.go:296:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:340:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:363:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:377:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:397:	handler := NewHandler(nil, executor.NewPool(1), nil, pol, "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:413:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:432:	handler := NewHandler(nil, executor.NewPool(1), nil, pol, "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:821:	origAcquire := acquireExecutionVMFunc
/home/cellardoor72/aegis/internal/api/handler_test.go:833:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:858:		acquireExecutionVMFunc = origAcquire
/home/cellardoor72/aegis/internal/api/handler_test.go:875:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:897:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:914:	acquireExecutionVMFunc = func(ctx context.Context, _ *warmpool.Manager, _ string, _ ExecuteRequest, _ *policy.Policy, _ policy.ComputeProfile, _ string, _ string, _ *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:923:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:947:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:963:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:975:	handler := WithAuth("secret", NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test"))
/home/cellardoor72/aegis/internal/api/handler_test.go:992:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1009:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1026:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1044:	handler := NewHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1056:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1069:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1081:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1095:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1108:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1112:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1125:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1129:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1144:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1159:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1177:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1193:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1210:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1222:	handler := WithAuth("secret", NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test"))
/home/cellardoor72/aegis/internal/api/handler_test.go:1234:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1252:	handler := NewStreamHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1264:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1277:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1289:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1301:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1313:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1331:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1352:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1366:	handler := NewStreamHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test", workspaceRegistry)
/home/cellardoor72/aegis/internal/api/handler_test.go:1395:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1408:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1412:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1424:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1428:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1443:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1458:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1475:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1492:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1509:	handler := NewStreamHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1545:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1569:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", registry, NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1593:	acquireExecutionVMFunc = func(context.Context, *warmpool.Manager, string, ExecuteRequest, *policy.Policy, policy.ComputeProfile, string, string, *telemetry.Bus) (*executor.VMInstance, string, string, error) {
/home/cellardoor72/aegis/internal/api/handler_test.go:1607:	handler := NewHandler(nil, pool, nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test", workspaceRegistry)
/home/cellardoor72/aegis/internal/api/handler_test.go:1700:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/api/handler_test.go:1721:	handler := NewHandler(nil, executor.NewPool(1), nil, policy.Default(), "", "", NewBusRegistry(), NewStatsCounter(), "test")
/home/cellardoor72/aegis/internal/executor/firecracker.go:141:func NewVM(uuid string, workspaceID string, pol *policy.Policy, profile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*VMInstance, error) {
/home/cellardoor72/aegis/internal/executor/firecracker.go:176:		networkCfg, err = SetupNetwork(uuid, pol.Network, bus)
/home/cellardoor72/aegis/internal/executor/firecracker.go:186:	cmd := exec.Command(resolveFirecrackerBinary(), "--api-sock", socketPath)

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/internal/api/handler.go | sed -n '574,750p'
```

### Output

```text
   574	func NewHandler(s *store.Store, pool *executor.Pool, warm *warmpool.Manager, pol *policy.Policy, assetsDir string, rootfsPath string, registry *BusRegistry, stats *StatsCounter, _ string, workspaceRegistries ...*WorkspaceRegistry) http.HandlerFunc {
   575		workspaceRegistry := resolveWorkspaceRegistry(workspaceRegistries)
   576		return func(w http.ResponseWriter, r *http.Request) {
   577			start := time.Now()
   578			execStatus := "error"
   579			defer func() { observability.RecordExecution(execStatus, time.Since(start)) }()
   580	
   581			w.Header().Set("Content-Type", "application/json")
   582			r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
   583	
   584			proofRoot := receipt.ProofRoot(strings.TrimSpace(os.Getenv("AEGIS_PROOF_ROOT")))
   585			proofPaths := receipt.BundlePaths{}
   586			var (
   587				vmPath             string
   588				coldFallbackReason string
   589			)
   590			respond := func(resp ExecuteResponse, rec store.ExecutionRecord) {
   591				resp.DurationMs = time.Since(start).Milliseconds()
   592				resp.DispatchPath = vmPath
   593				if vmPath == "cold" && coldFallbackReason != "" {
   594					resp.ColdFallbackReason = coldFallbackReason
   595				}
   596				resp = withReceiptProof(resp, proofPaths)
   597				writeJSON(w, http.StatusOK, resp)
   598			}
   599	
   600			var req ExecuteRequest
   601			if err := decodeJSONBody(r.Body, &req); err != nil {
   602				execStatus = "invalid_request"
   603				var maxBytesErr *http.MaxBytesError
   604				if errors.As(err, &maxBytesErr) {
   605					execStatus = "request_too_large"
   606					writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 128 KiB limit", errorDetails("max_bytes", maxBytesErr.Limit))
   607				} else {
   608					writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid request body", errorDetails("cause", err.Error()))
   609				}
   610				return
   611			}
   612	
   613			pointEvaluator, intent, err := buildPointEvaluator(&req, pol.DefaultTimeoutMs)
   614			if err != nil {
   615				execStatus = "validation_error"
   616				errorCode := "invalid_intent_contract"
   617				var invalidReq *capabilities.InvalidRequestError
   618				if errors.As(err, &invalidReq) {
   619					errorCode = "invalid_request"
   620				}
   621				writeAPIError(w, http.StatusBadRequest, errorCode, err.Error(), nil)
   622				return
   623			}
   624			var divergenceEvaluator *policydivergence.Evaluator
   625			if intent != nil {
   626				divergenceEvaluator = policydivergence.New(*intent)
   627			}
   628	
   629			execID, err := chooseExecutionID(requestedExecutionID(req, intent))
   630			if err != nil {
   631				execStatus = "invalid_request"
   632				writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error(), errorDetails("field", "execution_id"))
   633				return
   634			}
   635			if req.WorkspaceID != "" {
   636				if err := executor.ValidateWorkspaceID(req.WorkspaceID); err != nil {
   637					execStatus = "validation_error"
   638					writeAPIError(w, http.StatusBadRequest, "invalid_workspace_id", err.Error(), errorDetails("workspace_id", req.WorkspaceID))
   639					return
   640				}
   641				if !workspaceRegistry.TryClaim(req.WorkspaceID, execID) {
   642					execStatus = "workspace_busy"
   643					writeAPIError(w, http.StatusConflict, "workspace_busy", "workspace already has an active execution", errorDetails("workspace_id", req.WorkspaceID))
   644					return
   645				}
   646				defer workspaceRegistry.Release(req.WorkspaceID, execID)
   647			}
   648			if err := pool.Acquire(); err != nil {
   649				execStatus = "too_many_requests"
   650				w.Header().Set("Retry-After", "5")
   651				writeAPIError(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent executions", errorDetails("retry_after_seconds", 5))
   652				return
   653			}
   654			defer pool.Release()
   655			bus, execID, err := claimExecutionBus(registry, execID, requestedExecutionID(req, intent) != "")
   656			if err != nil {
   657				execStatus = "conflict"
   658				writeAPIError(w, http.StatusConflict, "execution_conflict", err.Error(), errorDetails("execution_id", execID))
   659				return
   660			}
   661			defer func() {
   662				bus.Close()
   663				registry.Complete(execID)
   664			}()
   665			recordLifecycleStatus(s, execID, req.Lang, store.StatusRequested, "")
   666	
   667			timeoutMs := req.TimeoutMs
   668			if timeoutMs == 0 {
   669				timeoutMs = pol.DefaultTimeoutMs
   670			}
   671			req.TimeoutMs = timeoutMs
   672			req.Profile = resolveRequestedProfile(req, pol)
   673			computeProfile, ok := pol.Profiles[req.Profile]
   674			if !ok {
   675				execStatus = "invalid_profile"
   676				writeAPIError(w, http.StatusBadRequest, "invalid_profile", "invalid compute profile", errorDetails("profile", req.Profile))
   677				return
   678			}
   679			if err := pol.Validate(req.Lang, len(req.Code), timeoutMs); err != nil {
   680				execStatus = "validation_error"
   681				writeAPIError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
   682				return
   683			}
   684			effectiveNetwork, err := resolveEffectiveNetworkPolicy(pol.Network, intent)
   685			if err != nil {
   686				execStatus = "validation_error"
   687				writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
   688				return
   689			}
   690			execPolicy := clonePolicyWithNetwork(pol, effectiveNetwork)
   691			policyEvidence, err := policyEvidenceForExecution(req, pol, timeoutMs)
   692			if err != nil {
   693				execStatus = "validation_error"
   694				writeAPIError(w, http.StatusBadRequest, "invalid_intent_contract", err.Error(), nil)
   695				return
   696			}
   697	
   698			var (
   699				vm              *executor.VMInstance
   700				effectiveCgroup *executor.EffectiveCgroupLimits
   701				exitCode        int
   702				exitReason      = "completed"
   703				outputTruncated bool
   704				stdoutData      string
   705				stderrData      string
   706				brokerEnabled   bool
   707			)
   708			currentRuntimeEnvelope := func() *receipt.RuntimeEnvelope {
   709				return runtimeEnvelopeForExecution(req, vm, effectiveCgroup, brokerEnabled)
   710			}
   711	
   712			ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMs)*time.Millisecond+startupSlack)
   713			defer cancel()
   714			deadline, _ := ctx.Deadline()
   715			observability.Info("execution_start", observability.Fields{"execution_id": execID, "lang": req.Lang, "timeout_ms": timeoutMs, "deadline": deadline.Format(time.RFC3339Nano)})
   716			recordLifecycleStatus(s, execID, req.Lang, store.StatusBooting, "")
   717	
   718			bootStart := time.Now()
   719			bootObserved := false
   720			recordBoot := func() {
   721				if bootObserved {
   722					return
   723				}
   724				bootObserved = true
   725				observability.ObserveBootDuration(time.Since(bootStart))
   726			}
   727	
   728			claimStart := time.Now()
   729			vm, vmPath, coldFallbackReason, err = acquireExecutionVMFunc(ctx, warm, execID, req, execPolicy, computeProfile, assetsDir, rootfsPath, bus)
   730			claimElapsed := time.Since(claimStart)
   731			if err != nil {
   732				recordBoot()
   733				if errors.Is(err, executor.ErrInvalidWorkspaceID) {
   734					execStatus = "validation_error"
   735					msg := err.Error()
   736					_ = writeExecutionRecordFunc(s, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: msg})
   737					respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
   738					return
   739				}
   740				if req.WorkspaceID != "" && errors.Is(err, os.ErrNotExist) {
   741					execStatus = "validation_error"
   742					msg := "workspace_not_found: " + req.WorkspaceID
   743					_ = writeExecutionRecordFunc(s, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", Status: store.StatusSandboxError, ErrorMsg: msg})
   744					respond(ExecuteResponse{ExecutionID: execID, Error: msg}, store.ExecutionRecord{ExecutionID: execID, Lang: req.Lang, Outcome: "error", ErrorMsg: msg})
   745					return
   746				}
   747				execStatus = "sandbox_error"
   748				exitCode = -1
   749				exitReason = "sandbox_error"
   750				status := store.StatusSandboxError

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/internal/api/handler.go | sed -n '468,520p'
```

### Output

```text
   468	func acquireExecutionVM(ctx context.Context, warm *warmpool.Manager, execID string, req ExecuteRequest, pol *policy.Policy, computeProfile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*executor.VMInstance, string, string, error) {
   469		shapeKey, fallbackReason := warmShapeDecision(req, warm, pol, assetsDir, rootfsPath)
   470		if shapeKey != "" {
   471			vm, ok, claimReason, err := warm.ClaimFor(ctx, shapeKey)
   472			if ok && err == nil {
   473				if err := vm.ClaimExecutionIdentity(execID); err != nil {
   474					observability.Warn("warm_pool_claim_identity_rebind_failed", observability.Fields{"execution_id": execID, "asset_id": vm.AssetID, "error": err.Error()})
   475					if teardownErr := teardownVMFunc(vm, bus); teardownErr != nil {
   476						observability.Warn("warm_pool_claim_rebind_teardown_failed", observability.Fields{"execution_id": execID, "asset_id": vm.AssetID, "error": teardownErr.Error()})
   477					}
   478					fallbackReason = warmpool.FallbackClaimError
   479					if warm != nil {
   480						warm.RecordColdFallbackReason(fallbackReason)
   481					}
   482				} else {
   483					return vm, "warm", "", nil
   484				}
   485			}
   486			if err != nil {
   487				fallbackReason = claimReason
   488				observability.Warn("warm_pool_claim_failed", observability.Fields{"execution_id": execID, "error": err.Error(), "fallback_reason": fallbackReason})
   489			} else if !ok {
   490				fallbackReason = claimReason
   491			}
   492		} else if warm != nil {
   493			warm.RecordColdFallbackReason(fallbackReason)
   494		}
   495		vm, err := executor.NewVM(execID, req.WorkspaceID, pol, computeProfile, assetsDir, rootfsPath, bus)
   496		if vm != nil {
   497			if claimErr := vm.ClaimExecutionIdentity(execID); claimErr != nil {
   498				return nil, "cold", fallbackReason, claimErr
   499			}
   500		}
   501		return vm, "cold", fallbackReason, err
   502	}
   503	
   504	// WithAuth wraps a handler with Bearer token authentication.
   505	// If apiKey is empty the handler runs unauthenticated (dev mode).
   506	func WithAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
   507		if apiKey == "" {
   508			return next
   509		}
   510		return func(w http.ResponseWriter, r *http.Request) {
   511			authorization := strings.TrimSpace(r.Header.Get("Authorization"))
   512			if authorization == "" {
   513				writeAPIError(w, http.StatusUnauthorized, "auth_required", "Authorization header missing", errorDetails("header", "Authorization"))
   514				return
   515			}
   516			const bearerPrefix = "Bearer "
   517			if !strings.HasPrefix(authorization, bearerPrefix) {
   518				writeAPIError(w, http.StatusUnauthorized, "auth_invalid", "Authorization header must use Bearer token", errorDetails("header", "Authorization"))
   519				return
   520			}

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/internal/executor/firecracker.go | sed -n '141,190p'
```

### Output

```text
   141	func NewVM(uuid string, workspaceID string, pol *policy.Policy, profile policy.ComputeProfile, assetsDir string, rootfsPath string, bus *telemetry.Bus) (*VMInstance, error) {
   142		baseDir, err := resolveAssetsDir(assetsDir)
   143		if err != nil {
   144			return nil, err
   145		}
   146		emitIfBus(bus, telemetry.KindVMBootStart, map[string]string{})
   147	
   148		if err := os.MkdirAll(scratchDir, 0o700); err != nil {
   149			return nil, fmt.Errorf("create scratch dir: %w", err)
   150		}
   151		if err := os.Chmod(scratchDir, 0o700); err != nil {
   152			return nil, fmt.Errorf("chmod scratch dir: %w", err)
   153		}
   154	
   155		rootfsPath, err = resolveRootfsImage(baseDir, rootfsPath)
   156		if err != nil {
   157			return nil, err
   158		}
   159		isPersistent := false
   160		var scratchPath string
   161		if workspaceID != "" {
   162			scratchPath, err = GetWorkspace(workspaceID)
   163			if err != nil {
   164				return nil, fmt.Errorf("get workspace disk: %w", err)
   165			}
   166			isPersistent = true
   167		} else {
   168			scratchPath, err = CreateScratchDisk(uuid)
   169			if err != nil {
   170				return nil, fmt.Errorf("create scratch disk: %w", err)
   171			}
   172		}
   173	
   174		var networkCfg *NetworkConfig
   175		if pol != nil {
   176			networkCfg, err = SetupNetwork(uuid, pol.Network, bus)
   177			if err != nil {
   178				return nil, fmt.Errorf("setup network: %w", err)
   179			}
   180		}
   181	
   182		socketPath := firecrackerSocketPath(uuid)
   183		vsockPath := vsockSocketPath(uuid)
   184		kernelPath := filepath.Join(baseDir, "vmlinux")
   185	
   186		cmd := exec.Command(resolveFirecrackerBinary(), "--api-sock", socketPath)
   187		cmd.Env = []string{}
   188		serialLogPath := serialLogFilePath(uuid)
   189		serialLog, _ := os.OpenFile(serialLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
   190		cmd.Stdout = serialLog

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/internal/executor/lifecycle.go | sed -n '229,248p;897,905p'
```

### Output

```text
   229	func SetupNetwork(execID string, np policy.NetworkPolicy, bus *telemetry.Bus) (*NetworkConfig, error) {
   230		np = policy.NormalizeNetworkPolicy(np)
   231		mode := policy.NormalizeNetworkMode(np.Mode)
   232		if mode == policy.NetworkModeNone {
   233			return nil, nil
   234		}
   235	
   236		cfg := newNetworkConfig(execID, np)
   237		cleanup := true
   238		defer func() {
   239			if cleanup {
   240				_ = teardownNetwork(cfg)
   241			}
   242		}()
   243	
   244		if err := runNetworkCmd("ip", "tuntap", "add", "dev", cfg.TapName, "mode", "tap"); err != nil {
   245			return nil, err
   246		}
   247		if err := runNetworkCmd("ip", "addr", "add", cfg.HostIP+"/30", "dev", cfg.TapName); err != nil {
   248			return nil, err
   897	func runCmd(name string, args ...string) error {
   898		cmd := exec.Command(name, args...)
   899		output, err := cmd.CombinedOutput()
   900		if err != nil {
   901			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
   902		}
   903		return nil
   904	}
   905	

```

### Command

```bash
rg -n 'LockOSThread|UnlockOSThread' /home/cellardoor72/aegis/cmd/orchestrator/main.go /home/cellardoor72/aegis/internal/api /home/cellardoor72/aegis/internal/executor /home/cellardoor72/aegis/internal/capabilities/ambient.go
```

### Output

```text
/home/cellardoor72/aegis/internal/capabilities/ambient.go:33:	runtime.LockOSThread()

```

## 3. SysProcAttr inspection

### Command

```bash
rg -n --glob '*.go' 'SysProcAttr|AmbientCaps|syscall\.SysProcAttr' /home/cellardoor72/aegis
```

### Output

```text
/home/cellardoor72/aegis/guest-runner/main_test.go:354:	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
/home/cellardoor72/aegis/guest-runner/main.go:674:	cmd.SysProcAttr = &syscall.SysProcAttr{

```

### Command

```bash
nl -ba /home/cellardoor72/aegis/guest-runner/main.go | sed -n '668,686p'; printf '\n----\n'; nl -ba /home/cellardoor72/aegis/guest-runner/main_test.go | sed -n '348,360p'
```

### Output

```text
   668		workDir := "/tmp"
   669		if mountedWorkspace {
   670			workDir = "/workspace"
   671		}
   672		cmd.Dir = workDir
   673		cmd.Env = append(os.Environ(), "HOME="+workDir, "USER=nobody", "LOGNAME=nobody", "HTTP_PROXY=http://127.0.0.1:8888", "HTTPS_PROXY=http://127.0.0.1:8888", "PYTHONHASHSEED=0")
   674		cmd.SysProcAttr = &syscall.SysProcAttr{
   675			Credential: &syscall.Credential{Uid: guestExecUID, Gid: guestExecGID},
   676			Setpgid:    true,
   677		}
   678		stdoutPipe, err := cmd.StdoutPipe()
   679		if err != nil {
   680			if !sendChunk(GuestChunk{Type: "error", Error: diagPrefix + "stdout pipe: " + err.Error()}) {
   681				return
   682			}
   683			close(chunks)
   684			_ = <-writeErr
   685			return
   686		}

----
   348	}
   349	
   350	func TestTimeoutKillsWholeProcessGroup(t *testing.T) {
   351		t.Parallel()
   352	
   353		cmd := exec.Command("/bin/bash", "-lc", "sleep 30 & wait")
   354		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
   355		stdoutPipe, err := cmd.StdoutPipe()
   356		if err != nil {
   357			t.Fatalf("stdout pipe: %v", err)
   358		}
   359		stderrPipe, err := cmd.StderrPipe()
   360		if err != nil {

```

## 4. Live confirmation: inspect a child's caps

### Command

```bash
command -v ip
```

### Output

```text
/usr/sbin/ip

```

### Command

```bash
bash -lc 'export PATH=/tmp/wrapper-bin:$PATH; ./scripts/demo_egress_allowlist.sh'
```

### Output

```text
Aegis egress_allowlist demo
watch_for=three blocked beats (public IP, denied DNS, RFC1918) plus one brokered allow to api.github.com with offline receipt verification
summary_json=/home/cellardoor72/aegis/scripts/demo_output/egress_allowlist/run_20260420T071719Z.json
host_check=api.github.com:443 reachable
network_privileges=cap_net_admin
runtime_mode=started
api_url=http://127.0.0.1:8080
proof_root=/tmp/aegis-demo/proofs
execution_id=d7ef9c71-f2a0-47dd-a5c1-9aeb3faa5a21
FAIL: execution failed: setup network: ip tuntap add dev tap-d7ef9c71 mode tap: exit status 1: ioctl(TUNSETIFF): Operation not permitted
summary_json=/home/cellardoor72/aegis/scripts/demo_output/egress_allowlist/run_20260420T071719Z.json

```

### Command

```bash
cat /tmp/ip-wrapper.log
```

### Output

```text
=== ip-wrapper invoked with: -o link show
=== CapAmb from /proc/self/status:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
=== calling real ip
=== ip-wrapper invoked with: tuntap add dev tap-d7ef9c71 mode tap
=== CapAmb from /proc/self/status:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
=== calling real ip
=== ip-wrapper invoked with: link del tap-d7ef9c71
=== CapAmb from /proc/self/status:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
=== calling real ip

```

## 5. Process tree check

### Command

```bash
tail -80 /tmp/ambient_drop_ps.log
```

### Output

```text
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080

```

### Command

```bash
ps -eo pid,ppid,comm,args | grep -E "orchestrator|firecracker|ip"
```

### Output

```text
    152       2 kworker/R-ipv6_ [kworker/R-ipv6_addrconf]
  15765   15746 pipewire        /usr/bin/pipewire
  15766   15746 pipewire        /usr/bin/pipewire -c filter-chain.conf
  15772   15746 pipewire-pulse  /usr/bin/pipewire-pulse
  15906   15732 gdm-x-session   /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
  58119   15746 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:45257/aegisdemo?sslmode=disable --policy /tmp/aegis-demo/egress-allowlist-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
  58671   17758 bash            /bin/bash -lc ps -eo pid,ppid,comm,args | grep -E "orchestrator|firecracker|ip"
  58682   58671 grep            grep -E orchestrator|firecracker|ip

```

## Finding

Based on evidence, the ambient caps are being dropped because the ambient/inheritable state is raised only on the main goroutine’s locked OS thread, but the HTTP execution path that reaches `exec.Command("ip", ...)` runs through the request handler goroutine path with no additional `runtime.LockOSThread` and no `SysProcAttr.AmbientCaps` on the child process. The relevant evidence is section 1 and section 2 for where `RaiseAmbient` and `runtime.LockOSThread()` happen, section 3 for the absence of any orchestrator/executor `SysProcAttr` or `AmbientCaps` configuration, and section 4 where the actual wrapped `ip` child shows `CapInh=0`, `CapPrm=0`, `CapEff=0`, and `CapAmb=0`.

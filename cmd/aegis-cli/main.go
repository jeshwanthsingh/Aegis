package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/config"
	"aegis/internal/models"
	"aegis/internal/receipt"
	"aegis/internal/serve"
	"aegis/internal/setup"
)

type executeRequest struct {
	Lang      string          `json:"lang"`
	Code      string          `json:"code"`
	TimeoutMs int             `json:"timeout_ms,omitempty"`
	Intent    json.RawMessage `json:"intent,omitempty"`
}

type executeResponse struct {
	Stdout               string `json:"stdout"`
	Stderr               string `json:"stderr"`
	ExitCode             int    `json:"exit_code"`
	DurationMs           int64  `json:"duration_ms"`
	ExecutionID          string `json:"execution_id"`
	Error                string `json:"error"`
	OutputTruncated      bool   `json:"output_truncated,omitempty"`
	ProofDir             string `json:"proof_dir,omitempty"`
	ReceiptPath          string `json:"receipt_path,omitempty"`
	ReceiptPublicKeyPath string `json:"receipt_public_key_path,omitempty"`
	ReceiptSummaryPath   string `json:"receipt_summary_path,omitempty"`
}

type healthResponse struct {
	Status               string `json:"status"`
	WorkerSlotsAvailable int    `json:"worker_slots_available"`
	WorkerSlotsTotal     int    `json:"worker_slots_total"`
}

type apiErrorEnvelope struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details,omitempty"`
	} `json:"error"`
}

func main() {
	os.Exit(runMain(os.Stdout, os.Stderr, os.Args[1:]))
}

func runMain(stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "setup":
		return setupCmd(stdout, stderr, args[1:])
	case "serve":
		return serveCmd(stdout, stderr, args[1:])
	case "doctor", "self-test":
		return doctorCmd(stdout, stderr, args[1:])
	case "run":
		return run(stdout, stderr, args[1:])
	case "health":
		return health(stdout, stderr)
	case "receipt":
		return receiptCmd(stdout, stderr, args[1:])
	default:
		usage(stderr)
		return 2
	}
}

func usage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: aegis <setup|serve|doctor|self-test|run|health|receipt>")
}

func setupCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to config yaml")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	repoRoot, err := config.FindRepoRoot("")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	report, err := setup.Run(context.Background(), repoRoot, *configPath, setup.Options{Stdout: stdout, Stderr: stderr})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	fmt.Fprintf(stdout, "repo: %s\n", repoRoot)
	fmt.Fprintf(stdout, "config: %s\n", report.ConfigPath)
	printPathList(stdout, "created", report.Created)
	printPathList(stdout, "reused", report.Reused)
	fmt.Fprint(stdout, setup.RenderSummary(report.Results))
	fmt.Fprintln(stdout, "Generated binaries live under .aegis/bin; rerun `go run ./cmd/aegis-cli setup` after source changes before relying on them.")
	if report.ReadyForServe {
		fmt.Fprintln(stdout, "Next step: aegis serve")
		return 0
	}

	fmt.Fprintln(stderr, "setup found blocking prerequisites")
	return 1
}

func serveCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to config yaml")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	repoRoot, err := config.FindRepoRoot("")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cfg, resolvedConfigPath, err := loadServeConfig(repoRoot, *configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	checks := setup.Evaluate(repoRoot, cfg, setup.BootstrapArtifacts{})
	plan, err := serve.BuildPlan(cfg, checks)
	if err != nil {
		fmt.Fprintln(stdout, "serve readiness:")
		fmt.Fprint(stdout, setup.RenderSummary(checks))
		fmt.Fprintf(stderr, "%v\n", err)
		fmt.Fprintln(stderr, "Run `aegis setup` to create defaults and see the full readiness report.")
		return 1
	}

	printServeInfo(stdout, cfg, resolvedConfigPath, plan, checks)
	cmd := serve.Command(plan)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "serve failed: %v\n", err)
		return 1
	}
	return 0
}

func printServeInfo(stdout io.Writer, cfg config.Config, configPath string, plan serve.Plan, checks []setup.CheckResult) {
	fmt.Fprintln(stdout, "Serve configuration:")
	fmt.Fprintf(stdout, "- config: %s\n", configPath)
	fmt.Fprintf(stdout, "- api: %s\n", cfg.API.URL)
	fmt.Fprintf(stdout, "- mode: %s\n", plan.Mode)
	fmt.Fprintf(stdout, "- firecracker: %s\n", cfg.Runtime.FirecrackerBin)
	fmt.Fprintf(stdout, "- policy: %s\n", cfg.Runtime.PolicyPath)
	fmt.Fprintf(stdout, "- assets: %s\n", cfg.Runtime.AssetsDir)
	fmt.Fprintf(stdout, "- rootfs: %s\n", cfg.Runtime.RootfsPath)
	fmt.Fprintf(stdout, "- proofs: %s\n", cfg.Runtime.ProofRoot)
	fmt.Fprintf(stdout, "- cgroup parent: %s\n", cfg.Runtime.CgroupParent)
	fmt.Fprintf(stdout, "- warm pool: %s\n", warmPoolStatus(cfg))
	fmt.Fprintf(stdout, "- broker demos: %s\n", brokerStatus(cfg))
	fmt.Fprintf(stdout, "- api auth: %s\n", apiAuthStatus())
	fmt.Fprintf(stdout, "- receipt signing: %s\n", signingStatus(cfg))
	warnings := collectWarnings(plan, checks)
	if len(warnings) > 0 {
		fmt.Fprintln(stdout, "Warnings:")
		for _, warning := range warnings {
			fmt.Fprintf(stdout, "- %s\n", warning)
		}
	}
	fmt.Fprintln(stdout, "Starting orchestrator in the foreground. Press Ctrl+C to stop.")
}

func warmPoolStatus(cfg config.Config) string {
	if cfg.Runtime.WarmPoolSize <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("enabled size=%d max_age=%ds", cfg.Runtime.WarmPoolSize, cfg.Runtime.WarmPoolMaxAge)
}

func brokerStatus(cfg config.Config) string {
	if len(cfg.Demo.BrokerEnv) == 0 {
		return "available, no broker demo env configured"
	}
	missing := []string{}
	for _, envName := range cfg.Demo.BrokerEnv {
		if strings.TrimSpace(os.Getenv(envName)) == "" {
			missing = append(missing, envName)
		}
	}
	if len(missing) == 0 {
		return "enabled via " + strings.Join(cfg.Demo.BrokerEnv, ", ")
	}
	return "available, missing " + strings.Join(missing, ", ")
}

func apiAuthStatus() string {
	if strings.TrimSpace(os.Getenv("AEGIS_API_KEY")) == "" {
		return "disabled (unauthenticated local dev mode)"
	}
	return "enabled via AEGIS_API_KEY"
}

func signingStatus(cfg config.Config) string {
	mode := strings.TrimSpace(cfg.Receipt.SigningMode)
	if mode == "" {
		mode = "dev"
	}
	if strings.EqualFold(mode, "strict") {
		return "strict (host seed file required)"
	}
	return "dev fallback; not a production trust posture"
}

func collectWarnings(plan serve.Plan, checks []setup.CheckResult) []string {
	warnings := append([]string{}, plan.Warnings...)
	for _, result := range checks {
		if result.Status == setup.StatusWarn {
			warnings = append(warnings, fmt.Sprintf("%s: %s", result.Label, result.Detail))
		}
	}
	sort.Strings(warnings)
	if len(warnings) < 2 {
		return warnings
	}
	collapsed := warnings[:0]
	seen := map[string]struct{}{}
	for _, warning := range warnings {
		if _, ok := seen[warning]; ok {
			continue
		}
		seen[warning] = struct{}{}
		collapsed = append(collapsed, warning)
	}
	return collapsed
}

func printPathList(stdout io.Writer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	sort.Strings(values)
	fmt.Fprintf(stdout, "%s:\n", label)
	for _, value := range values {
		fmt.Fprintf(stdout, "- %s\n", value)
	}
}

func loadServeConfig(repoRoot string, explicit string) (config.Config, string, error) {
	path := config.ConfigPath(repoRoot, explicit)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return config.Config{}, path, fmt.Errorf("config not found at %s; run `aegis setup` first", path)
		}
		return config.Config{}, path, fmt.Errorf("stat config: %w", err)
	}
	cfg, err := config.Load(repoRoot, path)
	if err != nil {
		return config.Config{}, path, err
	}
	return cfg, path, nil
}

func baseURL() string {
	if v := strings.TrimSpace(os.Getenv("AEGIS_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if repoRoot, err := config.FindRepoRoot(""); err == nil {
		path := config.ConfigPath(repoRoot, "")
		if _, err := os.Stat(path); err == nil {
			if cfg, err := config.Load(repoRoot, path); err == nil && strings.TrimSpace(cfg.API.URL) != "" {
				return strings.TrimRight(cfg.API.URL, "/")
			}
		}
	}
	return "http://localhost:8080"
}

func newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if apiKey := strings.TrimSpace(os.Getenv("AEGIS_API_KEY")); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return req, nil
}

func run(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lang := fs.String("lang", "", "language to execute")
	code := fs.String("code", "", "inline code")
	filePath := fs.String("file", "", "path to code file")
	intentFile := fs.String("intent-file", "", "path to an IntentContract JSON file")
	timeoutMs := fs.Int("timeout", 0, "timeout in milliseconds")
	stream := fs.Bool("stream", false, "stream output as it arrives")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *lang == "" {
		fmt.Fprintln(stderr, "--lang is required")
		return 2
	}
	if (*code == "" && *filePath == "") || (*code != "" && *filePath != "") {
		fmt.Fprintln(stderr, "exactly one of --code or --file is required")
		return 2
	}

	source := *code
	if *filePath != "" {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		source = string(b)
	}

	var intent json.RawMessage
	if *intentFile != "" {
		b, err := os.ReadFile(*intentFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		intent = append(intent[:0], b...)
	}

	payload, err := json.Marshal(executeRequest{Lang: *lang, Code: source, TimeoutMs: *timeoutMs, Intent: intent})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	path := "/v1/execute"
	if *stream {
		path = "/v1/execute/stream"
	}
	req, err := newRequest(http.MethodPost, baseURL()+path, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer resp.Body.Close()

	if *stream {
		return consumeStream(stdout, stderr, resp)
	}
	return consumeSingle(stdout, stderr, resp)
}

func consumeSingle(stdout io.Writer, stderr io.Writer, resp *http.Response) int {
	if resp.StatusCode >= http.StatusBadRequest {
		var apiErr apiErrorEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		message := strings.TrimSpace(apiErr.Error.Message)
		if message == "" {
			message = resp.Status
		}
		fmt.Fprintln(stderr, message)
		return 1
	}

	var out executeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if out.Stdout != "" {
		fmt.Fprint(stdout, out.Stdout)
	}
	if out.Stderr != "" {
		for _, line := range strings.Split(strings.TrimRight(out.Stderr, "\n"), "\n") {
			if line == "" {
				continue
			}
			fmt.Fprintf(stdout, "[stderr] %s\n", line)
		}
	}

	printProofBundle(stdout, receipt.BundlePaths{
		ProofDir:      out.ProofDir,
		ReceiptPath:   out.ReceiptPath,
		PublicKeyPath: out.ReceiptPublicKeyPath,
		SummaryPath:   out.ReceiptSummaryPath,
	})

	if out.Error != "" {
		if out.Error == "timeout" {
			fmt.Fprintln(stderr, "execution timed out")
		} else {
			fmt.Fprintln(stderr, out.Error)
		}
		fmt.Fprintf(stdout, "[done in %dms]\n", out.DurationMs)
		return 1
	}

	if out.ExitCode != 0 {
		fmt.Fprintf(stdout, "[exit code %d]\n", out.ExitCode)
		fmt.Fprintf(stdout, "[done in %dms]\n", out.DurationMs)
		return 1
	}

	fmt.Fprintf(stdout, "[done in %dms]\n", out.DurationMs)
	return 0
}

func consumeStream(stdout io.Writer, stderr io.Writer, resp *http.Response) int {
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return consumeSingle(stdout, stderr, resp)
	}
	if execID := strings.TrimSpace(resp.Header.Get("X-Execution-ID")); execID != "" {
		fmt.Fprintf(stdout, "[execution %s]\n", execID)
	}

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var chunk models.GuestChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		switch chunk.Type {
		case "stdout":
			fmt.Fprint(stdout, chunk.Chunk)
		case "stderr":
			for _, line := range strings.Split(strings.TrimRight(chunk.Chunk, "\n"), "\n") {
				if line == "" {
					continue
				}
				fmt.Fprintf(stdout, "[stderr] %s\n", line)
			}
		case "proof":
			printProofBundle(stdout, receipt.BundlePaths{
				ProofDir:          chunk.ProofDir,
				ReceiptPath:       chunk.ReceiptPath,
				PublicKeyPath:     chunk.ReceiptPublicKeyPath,
				SummaryPath:       chunk.ReceiptSummaryPath,
				ArtifactCount:     chunk.ArtifactCount,
				DivergenceVerdict: chunk.DivergenceVerdict,
			})
		case "error":
			if chunk.Error == "timeout" {
				fmt.Fprintln(stderr, "execution timed out")
			} else {
				fmt.Fprintln(stderr, chunk.Error)
			}
			return 1
		case "done":
			if chunk.ExitCode != 0 {
				fmt.Fprintf(stdout, "[exit code %d]\n", chunk.ExitCode)
				fmt.Fprintf(stdout, "[done in %dms]\n", chunk.DurationMs)
				return 1
			}
			fmt.Fprintf(stdout, "[done in %dms]\n", chunk.DurationMs)
			return 0
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stderr, "stream ended unexpectedly")
	return 1
}

func health(stdout io.Writer, stderr io.Writer) int {
	req, err := newRequest(http.MethodGet, baseURL()+"/v1/health", nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer resp.Body.Close()

	var out healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	fmt.Fprintf(stdout, "status: %s\n", out.Status)
	fmt.Fprintf(stdout, "workers: %d/%d available\n", out.WorkerSlotsAvailable, out.WorkerSlotsTotal)
	return 0
}

func receiptCmd(stdout io.Writer, stderr io.Writer, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: aegis receipt <verify|show>")
		return 2
	}
	switch args[0] {
	case "verify":
		return receiptVerify(stdout, stderr, args[1:])
	case "show":
		return receiptShow(stdout, stderr, args[1:])
	default:
		fmt.Fprintln(stderr, "usage: aegis receipt <verify|show>")
		return 2
	}
}

func receiptVerify(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	receiptPath := fs.String("file", "", "path to a DSSE receipt JSON file")
	publicKeyPath := fs.String("public-key", "", "path to the receipt public key PEM")
	proofDir := fs.String("proof-dir", "", "path to a proof bundle directory")
	executionID := fs.String("execution-id", "", "execution id to resolve under AEGIS_PROOF_ROOT")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	paths, err := resolveReceiptSelection(*receiptPath, *publicKeyPath, *proofDir, *executionID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var statement receipt.Statement
	if strings.TrimSpace(*receiptPath) != "" {
		statement, err = receipt.VerifyReceiptFile(paths.ReceiptPath, paths.PublicKeyPath)
	} else {
		statement, err = receipt.VerifyBundlePaths(paths)
	}
	if err != nil {
		fmt.Fprintf(stderr, "receipt verification failed: %v\n", err)
		if class, ok := receipt.VerificationFailure(err); ok {
			fmt.Fprintf(stderr, "verification_failure_class=%s\n", class)
		}
		return 1
	}
	fmt.Fprint(stdout, receipt.FormatSummary(statement, true))
	return 0
}

func receiptShow(stdout io.Writer, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	proofDir := fs.String("proof-dir", "", "path to a proof bundle directory")
	executionID := fs.String("execution-id", "", "execution id to resolve under AEGIS_PROOF_ROOT")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	paths, err := receipt.ResolveBundlePaths(os.Getenv("AEGIS_PROOF_ROOT"), *executionID, *proofDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	printProofBundle(stdout, paths)
	report, err := receipt.VerifyBundleReport(paths)
	if err != nil {
		fmt.Fprint(stdout, receipt.FormatReview(paths, report))
		return 1
	}
	fmt.Fprint(stdout, receipt.FormatReview(paths, report))
	return 0
}

func resolveReceiptSelection(receiptPath string, publicKeyPath string, proofDir string, executionID string) (receipt.BundlePaths, error) {
	if strings.TrimSpace(receiptPath) != "" {
		keyPath := strings.TrimSpace(publicKeyPath)
		if keyPath == "" {
			keyPath = filepath.Join(filepath.Dir(receiptPath), "receipt.pub")
		}
		return receipt.BundlePaths{
			ProofDir:      filepath.Dir(receiptPath),
			ReceiptPath:   receiptPath,
			PublicKeyPath: keyPath,
			SummaryPath:   filepath.Join(filepath.Dir(receiptPath), "receipt.summary.txt"),
		}, nil
	}
	return receipt.ResolveBundlePaths(os.Getenv("AEGIS_PROOF_ROOT"), executionID, proofDir)
}

func printProofBundle(stdout io.Writer, paths receipt.BundlePaths) {
	if paths.ProofDir != "" {
		fmt.Fprintf(stdout, "[proof bundle %s]\n", paths.ProofDir)
	}
	if paths.ReceiptPath != "" {
		fmt.Fprintf(stdout, "[receipt %s]\n", paths.ReceiptPath)
	}
	if paths.PublicKeyPath != "" {
		fmt.Fprintf(stdout, "[receipt public key %s]\n", paths.PublicKeyPath)
	}
	if paths.SummaryPath != "" {
		fmt.Fprintf(stdout, "[receipt summary %s]\n", paths.SummaryPath)
	}
}

import { useEffect, useMemo, useRef, useState } from "react";
import { DEMOS } from "./demoTemplates";
import type {
  DemoKey,
  ExecuteRequest,
  ExecutionViewModel,
  GovernedAction,
  GuestChunk,
  ReceiptPredicate,
  SignedReceipt,
  TelemetryEvent,
} from "./types";

const API_BASE = ((import.meta as ImportMeta & { env?: { VITE_AEGIS_API_BASE?: string } }).env?.VITE_AEGIS_API_BASE ||
  window.location.origin ||
  "http://127.0.0.1:8080").replace(/\/$/, "");

const EMPTY_VIEW: ExecutionViewModel = {
  executionId: "",
  status: "idle",
  stdout: "",
  stderr: "",
  governedEvents: [],
};

function createExecutionId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID().toLowerCase();
  }
  return `exec-${Date.now()}`;
}

function parseSseBlock(block: string) {
  const payload = block
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n");
  return payload || null;
}

async function readSse<T>(response: Response, onMessage: (value: T) => void) {
  if (!response.body) {
    throw new Error("stream body unavailable");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    let boundary = buffer.indexOf("\n\n");
    while (boundary >= 0) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const payload = parseSseBlock(block);
      if (payload) {
        onMessage(JSON.parse(payload) as T);
      }
      boundary = buffer.indexOf("\n\n");
    }
    if (done) {
      const payload = parseSseBlock(buffer);
      if (payload) {
        onMessage(JSON.parse(payload) as T);
      }
      return;
    }
  }
}

function prettyDuration(ms?: number) {
  if (!ms || Number.isNaN(ms)) {
    return "pending";
  }
  return `${(ms / 1000).toFixed(2)}s`;
}

function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function policyNetworkSummary(predicate: ReceiptPredicate) {
  const network = predicate.policy?.baseline.network;
  if (!network) {
    return "none";
  }
  return network.presets && network.presets.length > 0
    ? `${network.mode} · ${network.presets.join(", ")}`
    : network.mode;
}

function runtimeNetworkSummary(predicate: ReceiptPredicate) {
  const network = predicate.runtime?.network;
  if (!network) {
    return "unavailable";
  }
  const presets = network.presets && network.presets.length > 0 ? ` · ${network.presets.join(", ")}` : "";
  return `${network.mode}${presets}`;
}

function receiptExitCode(predicate: ReceiptPredicate | null) {
  if (!predicate) {
    return undefined;
  }
  return predicate.outcome.exit_code ?? predicate.outcome.ExitCode;
}

function receiptOutcomeSummary(predicate: ReceiptPredicate | null) {
  if (!predicate) {
    return "unavailable";
  }
  return (
    predicate.outcome.reason ||
    predicate.outcome.Reason ||
    predicate.outcome.containment_verdict ||
    predicate.outcome.ContainmentVerdict ||
    predicate.execution_status ||
    "unavailable"
  );
}

function governedActionsFor(predicate?: ReceiptPredicate | null): GovernedAction[] {
  if (!predicate?.governed_actions) {
    return [];
  }
  return predicate.governed_actions.normalized?.length
    ? predicate.governed_actions.normalized
    : predicate.governed_actions.actions || [];
}

function outcomeTone(resultClass: string) {
  switch (resultClass) {
    case "completed":
      return "text-emerald-300 border-emerald-500/40 bg-emerald-500/10";
    case "denied":
      return "text-amber-200 border-amber-500/40 bg-amber-500/10";
    case "abnormal":
      return "text-rose-300 border-rose-500/40 bg-rose-500/10";
    default:
      return "text-slate-200 border-white/10 bg-white/5";
  }
}

function buildIntent(
  demo: DemoKey,
  executionId: string,
  lang: string,
  timeoutMs: number,
  apiBase: string,
) {
  const api = new URL(apiBase);
  const targetHost = api.host;
  const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
  const common = {
    version: "v1",
    execution_id: executionId,
    workflow_id: "wf_ui_demo_v1",
    task_class: `ui_${demo}`,
    declared_purpose:
      demo === "exfil"
        ? "Prove denied direct network egress in the UI demo"
        : "Prove brokered outbound execution in the UI demo",
    language: lang,
    resource_scope: {
      workspace_root: "/workspace",
      read_paths: ["/workspace", "/etc", "/usr/share/locale", "/dev"],
      write_paths: ["/workspace", "/dev/tty"],
      deny_paths: [],
      max_distinct_files: 64,
    },
    process_scope: {
      allowed_binaries: lang === "bash" ? ["bash"] : ["python3"],
      allow_shell: lang === "bash",
      allow_package_install: false,
      max_child_processes: 6,
    },
    budgets: {
      timeout_sec: timeoutSec,
      memory_mb: 128,
      cpu_quota: 100,
      stdout_bytes: 4096,
    },
  };

  if (demo === "exfil") {
    return {
      ...common,
      network_scope: {
        allow_network: false,
        allowed_domains: [],
        allowed_ips: [],
        max_dns_queries: 0,
        max_outbound_conns: 1,
      },
      broker_scope: {
        allowed_delegations: [],
        allowed_domains: [],
        allowed_action_types: [],
        require_host_consent: false,
      },
    };
  }

  return {
    ...common,
    network_scope: {
      allow_network: true,
      allowed_domains: [],
      allowed_ips: ["127.0.0.1"],
      max_dns_queries: 0,
      max_outbound_conns: 1,
    },
    broker_scope: {
      allowed_delegations: [],
      allowed_domains: ["127.0.0.1", targetHost],
      allowed_action_types: [],
      require_host_consent: false,
    },
  };
}

function templateCode(demo: DemoKey, apiBase: string) {
  const template = DEMOS.find((candidate) => candidate.id === demo);
  if (!template) {
    return "";
  }
  if (demo !== "broker") {
    return template.code;
  }
  const url = new URL(apiBase);
  const targetUrl = `http://${url.host}/health`;
  return template.code.replaceAll("__TARGET_URL__", targetUrl).replaceAll("__TARGET_HOST__", url.host);
}

export default function App() {
  const [selectedDemo, setSelectedDemo] = useState<DemoKey>("clean");
  const [language, setLanguage] = useState<"bash" | "python" | "node">("bash");
  const [profile, setProfile] = useState<"nano" | "standard" | "crunch">("nano");
  const [timeoutMs, setTimeoutMs] = useState(5000);
  const [code, setCode] = useState(templateCode("clean", API_BASE));
  const [view, setView] = useState<ExecutionViewModel>(EMPTY_VIEW);
  const [submitError, setSubmitError] = useState<string>("");
  const eventsAbortRef = useRef<AbortController | null>(null);
  const runAbortRef = useRef<AbortController | null>(null);

  const selectedTemplate = useMemo(() => DEMOS.find((demo) => demo.id === selectedDemo)!, [selectedDemo]);
  const predicate = view.receipt?.statement.predicate ?? null;
  const governedActions = predicate ? governedActionsFor(predicate) : view.governedEvents;

  function applyTemplate(demo: DemoKey) {
    const template = DEMOS.find((candidate) => candidate.id === demo);
    if (!template) {
      return null;
    }
    const nextCode = templateCode(template.id, API_BASE);
    setSelectedDemo(template.id);
    setLanguage(template.lang);
    setProfile(template.profile);
    setTimeoutMs(template.timeoutMs);
    setCode(nextCode);
    return {
      demo: template.id,
      language: template.lang,
      profile: template.profile,
      timeoutMs: template.timeoutMs,
      code: nextCode,
    };
  }

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const demo = params.get("demo");
    const autorun = params.get("autorun") === "1";
    if (demo === "clean" || demo === "exfil" || demo === "broker") {
      const next = applyTemplate(demo);
      if (autorun && next) {
        window.setTimeout(() => {
          void runExecution(next);
        }, 0);
      }
    }
  }, []);

  useEffect(() => {
    return () => {
      eventsAbortRef.current?.abort();
      runAbortRef.current?.abort();
    };
  }, []);

  async function runExecution(
    config?: {
      demo: DemoKey;
      language: "bash" | "python" | "node";
      profile: "nano" | "standard" | "crunch";
      timeoutMs: number;
      code: string;
    },
  ) {
    const activeDemo = config?.demo || selectedDemo;
    const activeLanguage = config?.language || language;
    const activeProfile = config?.profile || profile;
    const activeTimeoutMs = config?.timeoutMs || timeoutMs;
    const activeCode = config?.code || code;
    eventsAbortRef.current?.abort();
    runAbortRef.current?.abort();
    const executionId = createExecutionId();
    const payload: ExecuteRequest = {
      execution_id: executionId,
      lang: activeLanguage,
      code: activeCode,
      timeout_ms: activeTimeoutMs,
      profile: activeProfile,
    };
    if (activeDemo === "exfil" || activeDemo === "broker") {
      payload.intent = buildIntent(activeDemo, executionId, activeLanguage, activeTimeoutMs, API_BASE);
    }

    setSubmitError("");
    setView({
      executionId,
      status: "submitting",
      stdout: "",
      stderr: "",
      governedEvents: [],
    });

    const telemetryAbort = new AbortController();
    const runAbort = new AbortController();
    eventsAbortRef.current = telemetryAbort;
    runAbortRef.current = runAbort;

    void subscribeTelemetry(executionId, telemetryAbort.signal);

    try {
      const response = await fetch(`${API_BASE}/v1/execute/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
        signal: runAbort.signal,
      });

      if (!response.ok) {
        const failure = await response.text();
        throw new Error(failure || `request failed: ${response.status}`);
      }

      setView((current) => ({ ...current, status: "running" }));
      await readSse<GuestChunk>(response, (chunk) => {
        setView((current) => applyChunk(current, chunk));
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setSubmitError(message);
      setView((current) => ({ ...current, status: "failed", streamError: message }));
    } finally {
      setTimeout(() => telemetryAbort.abort(), 1500);
    }
  }

  async function subscribeTelemetry(executionId: string, signal: AbortSignal) {
    try {
      const deadline = Date.now() + 8000;
      while (!signal.aborted) {
        const response = await fetch(`${API_BASE}/v1/events/${executionId}`, {
          headers: {
            Accept: "text/event-stream",
          },
          signal,
        });
        if (response.ok) {
          await readSse<TelemetryEvent>(response, (event) => {
            if (event.kind === "containment.receipt") {
              const receipt = event.data as SignedReceipt;
              setView((current) => ({ ...current, receipt }));
              return;
            }
            if (event.kind === "governed.action.v1") {
              setView((current) => ({
                ...current,
                governedEvents: [...current.governedEvents, event.data as GovernedAction],
              }));
            }
          });
          return;
        }
        if (response.status !== 404 || Date.now() >= deadline) {
          return;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 250));
      }
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setSubmitError((error as Error).message);
      }
    }
  }

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(249,115,22,0.16),_transparent_24%),linear-gradient(180deg,_#020617_0%,_#0f172a_42%,_#111827_100%)] text-ink">
      <div className="mx-auto flex max-w-7xl flex-col gap-8 px-4 py-6 lg:px-8">
        <header className="flex flex-col gap-3 border-b border-white/10 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.32em] text-amber-300/80">Aegis Demo Surface</p>
            <h1 className="text-3xl font-semibold tracking-tight text-white">Minimal signed execution truth.</h1>
            <p className="max-w-3xl text-sm leading-6 text-slate-300">
              This UI only renders data returned by the current execution API, telemetry stream, and signed receipt.
              It does not invent metrics, legacy receipt fields, or verification claims that the browser cannot prove.
            </p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300 shadow-panel">
            <div>API base: <span className="font-mono text-xs text-slate-100">{API_BASE}</span></div>
            <div>Browser verification: <span className="text-slate-100">not exposed; use proof dir with CLI</span></div>
          </div>
        </header>

        <main className="grid gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
          <section className="space-y-6">
            <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 shadow-panel backdrop-blur">
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-white">Demo gallery</h2>
                <p className="mt-1 text-sm text-slate-400">Pick a real execution template, then adjust code or runtime inputs before running.</p>
              </div>
              <div className="space-y-3">
                {DEMOS.map((demo) => (
                  <button
                    key={demo.id}
                    type="button"
                    onClick={() => applyTemplate(demo.id)}
                    className={classNames(
                      "w-full rounded-2xl border px-4 py-4 text-left transition",
                      selectedDemo === demo.id
                        ? "border-amber-400/60 bg-amber-500/10"
                        : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/10",
                    )}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-semibold text-white">{demo.label}</span>
                      <span className="rounded-full border border-white/10 px-2 py-1 font-mono text-[11px] text-slate-300">{demo.lang}</span>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-400">{demo.description}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 shadow-panel backdrop-blur">
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-white">Run</h2>
                <p className="mt-1 text-sm text-slate-400">Submit a real execution request against the current backend.</p>
              </div>
              <div className="grid gap-4">
                <label className="grid gap-2 text-sm">
                  <span className="text-slate-300">Language</span>
                  <select
                    value={language}
                    onChange={(event) => setLanguage(event.target.value as "bash" | "python" | "node")}
                    className="rounded-2xl border border-white/10 bg-slate-900 px-3 py-2 text-white outline-none transition focus:border-amber-400/50"
                  >
                    <option value="bash">bash</option>
                    <option value="python">python</option>
                    <option value="node">node</option>
                  </select>
                </label>
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="grid gap-2 text-sm">
                    <span className="text-slate-300">Profile</span>
                    <select
                      value={profile}
                      onChange={(event) => setProfile(event.target.value as "nano" | "standard" | "crunch")}
                      className="rounded-2xl border border-white/10 bg-slate-900 px-3 py-2 text-white outline-none transition focus:border-amber-400/50"
                    >
                      <option value="nano">nano</option>
                      <option value="standard">standard</option>
                      <option value="crunch">crunch</option>
                    </select>
                  </label>
                  <label className="grid gap-2 text-sm">
                    <span className="text-slate-300">Timeout (ms)</span>
                    <input
                      type="number"
                      min={1000}
                      step={1000}
                      value={timeoutMs}
                      onChange={(event) => setTimeoutMs(Number(event.target.value) || 1000)}
                      className="rounded-2xl border border-white/10 bg-slate-900 px-3 py-2 text-white outline-none transition focus:border-amber-400/50"
                    />
                  </label>
                </div>
                <label className="grid gap-2 text-sm">
                  <span className="text-slate-300">Code</span>
                  <textarea
                    value={code}
                    onChange={(event) => setCode(event.target.value)}
                    rows={16}
                    spellCheck={false}
                    className="rounded-3xl border border-white/10 bg-slate-900 px-4 py-4 font-mono text-xs leading-6 text-slate-100 outline-none transition focus:border-amber-400/50"
                  />
                </label>
                <button
                  type="button"
                  onClick={() => void runExecution()}
                  className="rounded-2xl bg-amber-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-amber-400"
                >
                  Run {selectedTemplate.label}
                </button>
                {submitError ? <p className="rounded-2xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{submitError}</p> : null}
              </div>
            </div>
          </section>

          <section className="space-y-6">
            <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 shadow-panel backdrop-blur">
              <div className="flex flex-col gap-3 border-b border-white/10 pb-4 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-white">Live execution</h2>
                  <p className="mt-1 text-sm text-slate-400">Execution status, output, governed actions, and signed receipt state from the current run.</p>
                </div>
                <div className={classNames("inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.22em]", outcomeTone(predicate?.result_class || (view.status === "failed" ? "abnormal" : "completed")))}>
                  <span>{predicate?.result_class || view.status}</span>
                </div>
              </div>
              <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
                <div className="space-y-4">
                  <SummaryGrid view={view} predicate={predicate} />
                  <ConsolePane label="stdout" value={view.stdout} />
                  <ConsolePane label="stderr" value={view.stderr} tone="rose" />
                  <GovernedActionPane actions={governedActions} />
                </div>
                <div className="space-y-4">
                  <RuntimePane predicate={predicate} />
                  <PolicyPane predicate={predicate} />
                </div>
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 shadow-panel backdrop-blur">
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-white">Signed receipt</h2>
                <p className="mt-1 text-sm text-slate-400">Canonical DSSE receipt data from the containment receipt event. Browser verification is not exposed by the API.</p>
              </div>
              <ReceiptPane view={view} predicate={predicate} />
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

function applyChunk(current: ExecutionViewModel, chunk: GuestChunk): ExecutionViewModel {
  switch (chunk.type) {
    case "stdout":
      return { ...current, stdout: current.stdout + (chunk.chunk || ""), status: "running" };
    case "stderr":
      return { ...current, stderr: current.stderr + (chunk.chunk || ""), status: "running" };
    case "proof":
      return {
        ...current,
        proofDir: chunk.proof_dir,
        receiptPath: chunk.receipt_path,
        receiptSummaryPath: chunk.receipt_summary_path,
        divergenceVerdict: chunk.divergence_verdict,
      };
    case "done":
      return {
        ...current,
        status: chunk.reason === "completed" || chunk.exit_code === 0 ? "completed" : "failed",
        exitCode: chunk.exit_code ?? current.exitCode,
        durationMs: chunk.duration_ms,
      };
    case "error":
      return {
        ...current,
        status: "failed",
        streamError: chunk.error || "execution error",
      };
    default:
      return current;
  }
}

function SummaryGrid({ view, predicate }: { view: ExecutionViewModel; predicate: ReceiptPredicate | null }) {
  const exitCode =
    view.exitCode !== undefined
      ? String(view.exitCode)
      : receiptExitCode(predicate) !== undefined
        ? String(receiptExitCode(predicate))
        : "pending";
  const items = [
    { label: "Execution ID", value: view.executionId || "pending" },
    { label: "Proof dir", value: view.proofDir || "pending" },
    { label: "Duration", value: prettyDuration(view.durationMs) },
    { label: "Exit code", value: exitCode },
    { label: "Result class", value: predicate?.result_class || "pending" },
    { label: "Divergence", value: predicate?.divergence.verdict || view.divergenceVerdict || "pending" },
  ];
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {items.map((item) => (
        <div key={item.label} className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
          <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">{item.label}</div>
          <div className="mt-2 break-all font-mono text-xs text-slate-100">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

function ConsolePane({ label, value, tone = "slate" }: { label: string; value: string; tone?: "slate" | "rose" }) {
  const borderTone = tone === "rose" ? "border-rose-500/20" : "border-white/10";
  return (
    <div className={classNames("rounded-3xl border bg-slate-900/80", borderTone)}>
      <div className="border-b border-white/10 px-4 py-3 text-xs uppercase tracking-[0.22em] text-slate-400">{label}</div>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap px-4 py-4 font-mono text-xs leading-6 text-slate-100">{value || "No output yet."}</pre>
    </div>
  );
}

function GovernedActionPane({ actions }: { actions: GovernedAction[] }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-900/80">
      <div className="border-b border-white/10 px-4 py-3 text-xs uppercase tracking-[0.22em] text-slate-400">Governed actions</div>
      <div className="space-y-3 px-4 py-4">
        {actions.length === 0 ? (
          <p className="text-sm text-slate-400">No governed actions were emitted for this run.</p>
        ) : (
          actions.map((action, index) => (
            <div key={`${action.action_type}-${index}-${action.target}`} className="rounded-2xl border border-white/10 bg-white/5 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className={classNames("rounded-full border px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]", action.decision === "deny" ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-200")}>
                  {action.decision}
                </span>
                <span className="font-mono text-xs text-slate-200">{action.action_type}</span>
                {action.capability_path ? <span className="rounded-full border border-white/10 px-2 py-1 font-mono text-[11px] text-slate-400">{action.capability_path}</span> : null}
              </div>
              <div className="mt-3 space-y-1 text-sm text-slate-300">
                <p>target: <span className="font-mono text-xs">{action.target}</span></p>
                {action.reason ? <p>reason: {action.reason}</p> : null}
                {action.denial_marker ? <p>marker: <span className="font-mono text-xs">{action.denial_marker}</span></p> : null}
                {action.binding_name ? <p>binding: <span className="font-mono text-xs">{action.binding_name}</span></p> : null}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function RuntimePane({ predicate }: { predicate: ReceiptPredicate | null }) {
  const runtime = predicate?.runtime;
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-900/80 p-4">
      <h3 className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-400">Runtime summary</h3>
      {!runtime ? (
        <p className="mt-4 text-sm text-slate-400">Awaiting signed receipt runtime envelope.</p>
      ) : (
        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
          <Meta label="Profile" value={runtime.profile || "none"} />
          <Meta label="VM shape" value={`${runtime.vcpu_count || 0} vCPU · ${runtime.memory_mb || 0} MB`} />
          <Meta label="Cgroup" value={runtime.cgroup ? `${runtime.cgroup.memory_max_mb || 0} MB max · ${runtime.cgroup.pids_max || 0} pids` : "none"} />
          <Meta label="Network" value={runtimeNetworkSummary(predicate)} />
          <Meta label="Broker" value={runtime.broker?.enabled ? "enabled" : "disabled"} />
          <Meta label="Overrides" value={runtime.applied_overrides?.join(", ") || "none"} />
        </dl>
      )}
    </div>
  );
}

function PolicyPane({ predicate }: { predicate: ReceiptPredicate | null }) {
  const policy = predicate?.policy;
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-900/80 p-4">
      <h3 className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-400">Policy summary</h3>
      {!policy ? (
        <p className="mt-4 text-sm text-slate-400">Awaiting signed receipt policy evidence.</p>
      ) : (
        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
          <Meta label="Language" value={policy.baseline.language} />
          <Meta label="Profile" value={policy.baseline.profile || "none"} />
          <Meta label="Timeout" value={`${policy.baseline.timeout_ms} ms of ${policy.baseline.max_timeout_ms} ms`} />
          <Meta label="Code size" value={`${policy.baseline.code_size_bytes} bytes of ${policy.baseline.max_code_bytes} bytes`} />
          <Meta label="Network" value={policyNetworkSummary(predicate)} />
          <Meta label="Intent" value={policy.intent ? `${policy.intent.source || "intent"} · ${policy.intent.digest}` : "none"} />
        </dl>
      )}
    </div>
  );
}

function ReceiptPane({ view, predicate }: { view: ExecutionViewModel; predicate: ReceiptPredicate | null }) {
  if (!predicate) {
    return (
      <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4 text-sm text-slate-400">
        The browser is waiting for the containment receipt event. Proof paths will appear once the run completes.
      </div>
    );
  }

  const trustLimitations = predicate.trust.limitations?.length ? predicate.trust.limitations : ["No additional browser-visible trust limitations provided."];
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <MetaCard label="Execution ID" value={predicate.execution_id} />
          <MetaCard label="Proof dir" value={view.proofDir || "pending"} />
          <MetaCard label="Policy digest" value={predicate.policy_digest || "none"} />
          <MetaCard label="Verification" value="Not exposed by browser UI" />
          <MetaCard label="Result class" value={predicate.result_class} />
          <MetaCard label="Outcome" value={receiptOutcomeSummary(predicate)} />
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-900/80 p-4">
          <h3 className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-400">Trust limitations</h3>
          <ul className="mt-4 space-y-2 text-sm leading-6 text-slate-300">
            {trustLimitations.map((item) => (
              <li key={item} className="rounded-2xl border border-white/10 bg-white/5 px-3 py-2">{item}</li>
            ))}
          </ul>
        </div>
      </div>
      <div className="rounded-3xl border border-white/10 bg-slate-900/80 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.22em] text-slate-400">Receipt trust</h3>
        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
          <Meta label="Signing mode" value={predicate.trust.signing_mode} />
          <Meta label="Key source" value={predicate.trust.key_source} />
          <Meta label="Attestation" value={predicate.trust.attestation} />
          <Meta label="Verification material" value={predicate.trust.verification_material} />
          <Meta label="Evidence digest" value={predicate.evidence_digest || "none"} />
          <Meta label="Started" value={predicate.started_at} />
          <Meta label="Finished" value={predicate.finished_at} />
        </dl>
      </div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-[11px] uppercase tracking-[0.22em] text-slate-500">{label}</dt>
      <dd className="break-all font-mono text-xs text-slate-100">{value}</dd>
    </div>
  );
}

function MetaCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
      <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">{label}</div>
      <div className="mt-2 break-all font-mono text-xs text-slate-100">{value}</div>
    </div>
  );
}

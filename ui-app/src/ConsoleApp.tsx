import { useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { DEMOS, type DemoTemplate } from "./demoTemplates";
import type {
  DemoKey,
  ExecuteRequest,
  GovernedAction,
  GuestChunk,
  ReceiptPredicate,
  SignedReceipt,
  TelemetryEvent,
} from "./types";

const API_BASE = ((import.meta as ImportMeta & { env?: { VITE_AEGIS_API_BASE?: string } }).env?.VITE_AEGIS_API_BASE ||
  window.location.origin ||
  "http://127.0.0.1:8080").replace(/\/$/, "");

const TIME_FORMAT = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

const RECEIPT_FINISHED_FORMAT = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

type SectionId = "run" | "executions" | "receipts" | "demos";
type DensityMode = "comfortable" | "compact";
type ExecutionStatus = "idle" | "submitting" | "running" | "completed" | "failed";
type TimelineTone = "neutral" | "info" | "success" | "warning" | "danger";
type ReceiptInspectorTab = "trust" | "json" | "artifacts";

interface TimelineEntry {
  id: string;
  at: number;
  stage: string;
  message: string;
  detail?: string;
  tone: TimelineTone;
}

interface ExecutionRecord {
  executionId: string;
  demo: DemoKey;
  demoLabel: string;
  language: "bash" | "python" | "node";
  profile: "nano" | "standard" | "crunch";
  timeoutMs: number;
  code: string;
  createdAt: number;
  updatedAt: number;
  status: ExecutionStatus;
  stdout: string;
  stderr: string;
  exitCode?: number;
  durationMs?: number;
  streamError?: string;
  proofDir?: string;
  receiptPath?: string;
  receiptSummaryPath?: string;
  divergenceVerdict?: string;
  receipt?: SignedReceipt;
  governedEvents: GovernedAction[];
  timeline: TimelineEntry[];
}

function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

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

function buildTimelineEntry(stage: string, message: string, tone: TimelineTone, detail?: string): TimelineEntry {
  return {
    id: `${stage}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    at: Date.now(),
    stage,
    message,
    detail,
    tone,
  };
}

function prettyDuration(ms?: number) {
  if (!ms || Number.isNaN(ms)) {
    return "pending";
  }
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatTime(ms: number) {
  return TIME_FORMAT.format(ms);
}

function formatFinishedAt(value?: string) {
  if (!value) {
    return "pending";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return RECEIPT_FINISHED_FORMAT.format(date);
}

function truncateMiddle(value?: string, keep = 10) {
  if (!value) {
    return "none";
  }
  if (value.length <= keep * 2) {
    return value;
  }
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

function statusLabel(record: ExecutionRecord) {
  return record.receipt?.statement.predicate.result_class || record.status;
}

function statusTone(status: string) {
  switch (status) {
    case "completed":
      return "status-success";
    case "denied":
      return "status-warning";
    case "abnormal":
    case "failed":
      return "status-danger";
    case "running":
    case "submitting":
      return "status-progress";
    default:
      return "status-neutral";
  }
}

function parseActionTone(decision: string) {
  return decision === "deny" ? "status-warning" : "status-success";
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

function readSectionFromQuery(): SectionId | null {
  const value = new URLSearchParams(window.location.search).get("section");
  return value === "run" || value === "executions" || value === "receipts" || value === "demos" ? value : null;
}

function readDensityFromQuery(): DensityMode | null {
  const value = new URLSearchParams(window.location.search).get("density");
  return value === "comfortable" || value === "compact" ? value : null;
}

function policyNetworkSummary(predicate: ReceiptPredicate) {
  const network = predicate.policy?.baseline.network;
  if (!network) {
    return "none";
  }
  return network.presets?.length ? `${network.mode} · ${network.presets.join(", ")}` : network.mode;
}

function runtimeNetworkSummary(predicate: ReceiptPredicate) {
  const network = predicate.runtime?.network;
  if (!network) {
    return "unavailable";
  }
  return network.presets?.length ? `${network.mode} · ${network.presets.join(", ")}` : network.mode;
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
    workflow_id: "wf_ui_console_v1",
    task_class: `ui_${demo}`,
    declared_purpose:
      demo === "exfil"
        ? "Prove denied direct network egress in the operator console"
        : "Prove brokered outbound execution in the operator console",
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
      allowed_delegations: demo === "broker" ? ["demo"] : [],
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

function createExecutionRecord(
  executionId: string,
  demo: DemoTemplate,
  language: "bash" | "python" | "node",
  profile: "nano" | "standard" | "crunch",
  timeoutMs: number,
  code: string,
): ExecutionRecord {
  return {
    executionId,
    demo: demo.id,
    demoLabel: demo.label,
    language,
    profile,
    timeoutMs,
    code,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    status: "submitting",
    stdout: "",
    stderr: "",
    governedEvents: [],
    timeline: [
      buildTimelineEntry("request", "Execution requested", "info", `${language} • ${profile} • ${timeoutMs} ms`),
    ],
  };
}

function appendTimelineRecord(current: ExecutionRecord, entry: TimelineEntry, skip = false) {
  if (skip) {
    return current;
  }
  return {
    ...current,
    timeline: [...current.timeline, entry],
  };
}

function applyChunk(current: ExecutionRecord, chunk: GuestChunk): ExecutionRecord {
  switch (chunk.type) {
    case "stdout":
      return {
        ...current,
        status: "running",
        stdout: current.stdout + (chunk.chunk || ""),
        updatedAt: Date.now(),
      };
    case "stderr":
      return {
        ...current,
        status: "running",
        stderr: current.stderr + (chunk.chunk || ""),
        updatedAt: Date.now(),
      };
    case "proof":
      return appendTimelineRecord(
        {
          ...current,
          proofDir: chunk.proof_dir,
          receiptPath: chunk.receipt_path,
          receiptSummaryPath: chunk.receipt_summary_path,
          divergenceVerdict: chunk.divergence_verdict,
          updatedAt: Date.now(),
        },
        buildTimelineEntry("proof", "Proof bundle available", "info", chunk.proof_dir || "proof dir pending"),
        Boolean(current.proofDir),
      );
    case "done":
      return appendTimelineRecord(
        {
          ...current,
          status: chunk.reason === "completed" || chunk.exit_code === 0 ? "completed" : "failed",
          exitCode: chunk.exit_code ?? current.exitCode,
          durationMs: chunk.duration_ms,
          updatedAt: Date.now(),
        },
        buildTimelineEntry(
          "complete",
          chunk.reason === "completed" || chunk.exit_code === 0 ? "Execution completed" : "Execution ended with error",
          chunk.reason === "completed" || chunk.exit_code === 0 ? "success" : "danger",
          chunk.exit_code !== undefined ? `exit ${chunk.exit_code}` : chunk.reason,
        ),
      );
    case "error":
      return appendTimelineRecord(
        {
          ...current,
          status: "failed",
          streamError: chunk.error || "execution error",
          updatedAt: Date.now(),
        },
        buildTimelineEntry("error", "Stream error", "danger", chunk.error || "execution error"),
      );
    default:
      return current;
  }
}

export default function ConsoleApp() {
  const [activeSection, setActiveSection] = useState<SectionId>(() => readSectionFromQuery() || "run");
  const [autorunTargetSection] = useState<SectionId | null>(() => readSectionFromQuery());
  const [density, setDensity] = useState<DensityMode>(() => {
    const fromQuery = readDensityFromQuery();
    if (fromQuery) {
      return fromQuery;
    }
    try {
      return window.localStorage.getItem("aegis.console.density") === "compact" ? "compact" : "comfortable";
    } catch {
      return "comfortable";
    }
  });
  const [search, setSearch] = useState("");
  const [selectedDemo, setSelectedDemo] = useState<DemoKey>("clean");
  const [language, setLanguage] = useState<"bash" | "python" | "node">("bash");
  const [profile, setProfile] = useState<"nano" | "standard" | "crunch">("nano");
  const [timeoutMs, setTimeoutMs] = useState(5000);
  const [code, setCode] = useState(templateCode("clean", API_BASE));
  const [executions, setExecutions] = useState<ExecutionRecord[]>([]);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState("");
  const eventsAbortRef = useRef<AbortController | null>(null);
  const runAbortRef = useRef<AbortController | null>(null);
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());

  const selectedTemplate = useMemo(() => DEMOS.find((demo) => demo.id === selectedDemo)!, [selectedDemo]);
  const selectedExecution = executions.find((execution) => execution.executionId === selectedExecutionId) || executions[0] || null;
  const receiptExecutions = executions.filter((execution) => Boolean(execution.receipt));
  const selectedReceiptExecution = selectedExecution?.receipt ? selectedExecution : receiptExecutions[0] || null;
  const latestReceiptExecution = receiptExecutions[0] || null;
  const searchEnabled = activeSection === "executions" || activeSection === "receipts";

  const filteredExecutions = useMemo(() => {
    if (!deferredSearch) {
      return executions;
    }
    return executions.filter((execution) => {
      const predicate = execution.receipt?.statement.predicate;
      const haystack = [
        execution.executionId,
        execution.demoLabel,
        execution.language,
        execution.profile,
        execution.status,
        execution.proofDir || "",
        predicate?.policy_digest || "",
        predicate?.result_class || "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(deferredSearch);
    });
  }, [deferredSearch, executions]);

  const filteredReceipts = useMemo(
    () =>
      filteredExecutions
        .filter((execution) => Boolean(execution.receipt))
        .slice()
        .sort((left, right) => {
          const leftFinished = left.receipt?.statement.predicate.finished_at
            ? new Date(left.receipt.statement.predicate.finished_at).getTime()
            : 0;
          const rightFinished = right.receipt?.statement.predicate.finished_at
            ? new Date(right.receipt.statement.predicate.finished_at).getTime()
            : 0;
          if (leftFinished !== rightFinished) {
            return rightFinished - leftFinished;
          }
          return right.updatedAt - left.updatedAt;
        }),
    [filteredExecutions],
  );

  useEffect(() => {
    try {
      window.localStorage.setItem("aegis.console.density", density);
    } catch {
      // ignore storage errors
    }
  }, [density]);

  useEffect(() => {
    return () => {
      eventsAbortRef.current?.abort();
      runAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const demo = params.get("demo");
    const autorun = params.get("autorun") === "1";
    if (demo === "clean" || demo === "exfil" || demo === "broker") {
      const next = applyTemplate(demo);
      if (autorun && next) {
        window.setTimeout(() => {
          void runExecution({
            ...next,
            targetSection: autorunTargetSection || undefined,
          });
        }, 0);
      }
    }
  }, [autorunTargetSection]);

  function applyTemplate(demoId: DemoKey) {
    const template = DEMOS.find((candidate) => candidate.id === demoId);
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

  function updateExecution(executionId: string, mutate: (current: ExecutionRecord) => ExecutionRecord) {
    setExecutions((current) =>
      current.map((execution) => (execution.executionId === executionId ? mutate(execution) : execution)),
    );
  }

  function appendTimeline(execution: ExecutionRecord, entry: TimelineEntry) {
    return {
      ...execution,
      updatedAt: Date.now(),
      timeline: [...execution.timeline, entry],
    };
  }

  async function runExecution(
    config?: {
      demo: DemoKey;
      language: "bash" | "python" | "node";
      profile: "nano" | "standard" | "crunch";
      timeoutMs: number;
      code: string;
      targetSection?: SectionId;
    },
  ) {
    const template = DEMOS.find((candidate) => candidate.id === (config?.demo || selectedDemo)) || selectedTemplate;
    const activeLanguage = config?.language || language;
    const activeProfile = config?.profile || profile;
    const activeTimeoutMs = config?.timeoutMs || timeoutMs;
    const activeCode = config?.code || code;
    const executionId = createExecutionId();

    const payload: ExecuteRequest = {
      execution_id: executionId,
      lang: activeLanguage,
      code: activeCode,
      timeout_ms: activeTimeoutMs,
      profile: activeProfile,
    };
    if (template.id === "exfil" || template.id === "broker") {
      payload.intent = buildIntent(template.id, executionId, activeLanguage, activeTimeoutMs, API_BASE);
    }

    eventsAbortRef.current?.abort();
    runAbortRef.current?.abort();
    setSubmitError("");
    const record = createExecutionRecord(executionId, template, activeLanguage, activeProfile, activeTimeoutMs, activeCode);
    setExecutions((current) => [record, ...current]);
    setSelectedExecutionId(executionId);
    setActiveSection(config?.targetSection || "executions");

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

      updateExecution(executionId, (current) =>
        appendTimeline(
          {
            ...current,
            status: "running",
            updatedAt: Date.now(),
          },
          buildTimelineEntry("stream", "Execution stream connected", "info"),
        ),
      );

      await readSse<GuestChunk>(response, (chunk) => {
        updateExecution(executionId, (current) => applyChunk(current, chunk));
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setSubmitError(message);
      updateExecution(executionId, (current) =>
        appendTimeline(
          {
            ...current,
            status: "failed",
            streamError: message,
            updatedAt: Date.now(),
          },
          buildTimelineEntry("error", "Execution request failed", "danger", message),
        ),
      );
    } finally {
      window.setTimeout(() => telemetryAbort.abort(), 1500);
    }
  }

  async function subscribeTelemetry(executionId: string, signal: AbortSignal) {
    try {
      const deadline = Date.now() + 8000;
      while (!signal.aborted) {
        const response = await fetch(`${API_BASE}/v1/events/${executionId}`, {
          headers: { Accept: "text/event-stream" },
          signal,
        });
        if (response.ok) {
          await readSse<TelemetryEvent>(response, (event) => {
            if (event.kind === "containment.receipt") {
              const receipt = event.data as SignedReceipt;
              updateExecution(executionId, (current) =>
                appendTimeline(
                  {
                    ...current,
                    receipt,
                    updatedAt: Date.now(),
                  },
                  buildTimelineEntry(
                    "receipt",
                    "Signed receipt received",
                    "success",
                    receipt.statement.predicate.policy_digest || "policy digest unavailable",
                  ),
                ),
              );
              return;
            }
            if (event.kind === "governed.action.v1") {
              const action = event.data as GovernedAction;
              updateExecution(executionId, (current) =>
                appendTimeline(
                  {
                    ...current,
                    governedEvents: [...current.governedEvents, action],
                    updatedAt: Date.now(),
                  },
                  buildTimelineEntry(
                    "governed",
                    `${action.decision === "deny" ? "Governed deny" : "Governed allow"} • ${action.action_type}`,
                    action.decision === "deny" ? "warning" : "success",
                    action.target,
                  ),
                ),
              );
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
        const message = error instanceof Error ? error.message : String(error);
        setSubmitError(message);
      }
    }
  }

  return (
    <div className="console-app" data-density={density}>
      <header className="console-topbar">
        <div className="console-heading">
          <div className="console-kicker">Aegis Console</div>
          <h1 className="console-title">Execution control and receipt evidence</h1>
          <p className="console-context">
            Local API <span className="mono">{API_BASE}</span>
          </p>
        </div>
        <div className="console-utilities">
          {searchEnabled ? (
            <label className="toolbar-search">
              <span className="toolbar-label">Search</span>
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder={activeSection === "receipts" ? "Search receipts" : "Search executions"}
              />
            </label>
          ) : null}
          <div className="segmented-control" role="group" aria-label="Density">
            <button type="button" className={classNames(density === "comfortable" && "is-active")} onClick={() => setDensity("comfortable")}>
              Comfortable
            </button>
            <button type="button" className={classNames(density === "compact" && "is-active")} onClick={() => setDensity("compact")}>
              Compact
            </button>
          </div>
        </div>
      </header>

      <div className="console-body">
        <aside className="console-sidebar">
          <nav className="nav-section" aria-label="Primary">
            <NavButton label="Run" note="submit execution" active={activeSection === "run"} onClick={() => setActiveSection("run")} />
            <NavButton label="Executions" note={`${executions.length} in session`} active={activeSection === "executions"} onClick={() => setActiveSection("executions")} />
            <NavButton label="Receipts" note={`${receiptExecutions.length} available`} active={activeSection === "receipts"} onClick={() => setActiveSection("receipts")} />
            <NavButton label="Demos" note="3 packaged flows" active={activeSection === "demos"} onClick={() => setActiveSection("demos")} />
          </nav>
        </aside>

        <main className="console-workspace">
          {activeSection === "run" ? (
            <RunWorkspace
              demos={DEMOS}
              selectedDemo={selectedDemo}
              selectedTemplate={selectedTemplate}
              language={language}
              profile={profile}
              timeoutMs={timeoutMs}
              code={code}
              latestExecution={latestReceiptExecution}
              submitError={submitError}
              onSelectDemo={(demo) => {
                applyTemplate(demo);
              }}
              onLanguageChange={setLanguage}
              onProfileChange={setProfile}
              onTimeoutChange={setTimeoutMs}
              onCodeChange={setCode}
              onRun={() => void runExecution()}
              onOpenDemos={() => setActiveSection("demos")}
            />
          ) : null}

          {activeSection === "executions" ? (
            <ExecutionsWorkspace executions={filteredExecutions} selectedExecution={selectedExecution} onSelectExecution={(executionId) => setSelectedExecutionId(executionId)} />
          ) : null}

          {activeSection === "receipts" ? (
            <ReceiptsWorkspace executions={filteredReceipts} selectedExecution={selectedReceiptExecution} onSelectExecution={(executionId) => setSelectedExecutionId(executionId)} />
          ) : null}

          {activeSection === "demos" ? (
            <DemosWorkspace
              demos={DEMOS}
              selectedDemo={selectedDemo}
              lastExecutions={executions}
              onSelectDemo={(demo) => {
                applyTemplate(demo);
              }}
              onLoadIntoRun={(demo) => {
                applyTemplate(demo);
                setActiveSection("run");
              }}
            />
          ) : null}
        </main>
      </div>
    </div>
  );
}

function NavButton({
  label,
  note,
  active,
  onClick,
}: {
  label: string;
  note: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className={classNames("nav-button", active && "is-active")} onClick={onClick}>
      <span className="nav-label">{label}</span>
      <span className="nav-note">{note}</span>
    </button>
  );
}

function PageHeader({ title, subtitle, action }: { title: string; subtitle: string; action?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        <h2 className="page-title">{title}</h2>
        <p className="page-subtitle">{subtitle}</p>
      </div>
      {action ? <div>{action}</div> : null}
    </div>
  );
}

function RunWorkspace({
  demos,
  selectedDemo,
  selectedTemplate,
  language,
  profile,
  timeoutMs,
  code,
  latestExecution,
  submitError,
  onSelectDemo,
  onLanguageChange,
  onProfileChange,
  onTimeoutChange,
  onCodeChange,
  onRun,
  onOpenDemos,
}: {
  demos: DemoTemplate[];
  selectedDemo: DemoKey;
  selectedTemplate: DemoTemplate;
  language: "bash" | "python" | "node";
  profile: "nano" | "standard" | "crunch";
  timeoutMs: number;
  code: string;
  latestExecution: ExecutionRecord | null;
  submitError: string;
  onSelectDemo: (demo: DemoKey) => void;
  onLanguageChange: (value: "bash" | "python" | "node") => void;
  onProfileChange: (value: "nano" | "standard" | "crunch") => void;
  onTimeoutChange: (value: number) => void;
  onCodeChange: (value: string) => void;
  onRun: () => void;
  onOpenDemos: () => void;
}) {
  const predicate = latestExecution?.receipt?.statement.predicate || null;

  return (
    <section className="page-stack">
      <PageHeader
        title="Run Request"
        subtitle="Build one execution request. Use Demos for the full packaged-demo browser, evidence expectations, and latest demo results."
        action={
          <button type="button" className="secondary-button" onClick={onOpenDemos}>
            Browse demos
          </button>
        }
      />

      <div className="run-layout">
        <div className="page-stack">
          <Surface title="Execution request" subtitle="Form values are sent directly to the current backend API. Selecting a packaged demo rewrites the request fields below.">
            <div className="form-grid form-grid-wide">
              <Field label="Loaded demo">
                <select value={selectedDemo} onChange={(event) => onSelectDemo(event.target.value as DemoKey)}>
                  {demos.map((demo) => (
                    <option key={demo.id} value={demo.id}>
                      {demo.label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Language">
                <select value={language} onChange={(event) => onLanguageChange(event.target.value as "bash" | "python" | "node")}>
                  <option value="bash">bash</option>
                  <option value="python">python</option>
                  <option value="node">node</option>
                </select>
              </Field>
              <Field label="Profile">
                <select value={profile} onChange={(event) => onProfileChange(event.target.value as "nano" | "standard" | "crunch")}>
                  <option value="nano">nano</option>
                  <option value="standard">standard</option>
                  <option value="crunch">crunch</option>
                </select>
              </Field>
              <Field label="Timeout (ms)">
                <input type="number" min={1000} step={1000} value={timeoutMs} onChange={(event) => onTimeoutChange(Number(event.target.value) || 1000)} />
              </Field>
            </div>
            <Field label="Code">
              <textarea value={code} rows={18} spellCheck={false} onChange={(event) => onCodeChange(event.target.value)} />
            </Field>
            <div className="action-row">
              <button type="button" className="primary-button" onClick={onRun}>
                Run execution
              </button>
              <span className="helper-text">{selectedTemplate.label} is loaded. Use Demos for full scenario detail and expected evidence.</span>
            </div>
            {submitError ? <div className="inline-alert danger">{submitError}</div> : null}
          </Surface>
        </div>

        <div className="page-stack run-sidebar">
          <Surface
            title="Loaded demo"
            subtitle="Compact context only. Full packaged-demo explanation lives in the Demos section."
            headerRight={
              <button type="button" className="secondary-button" onClick={onOpenDemos}>
                Open details
              </button>
            }
          >
            <DefinitionList
              compact
              items={[
                { label: "Demo", value: selectedTemplate.label },
                { label: "Expected result", value: selectedTemplate.expectedResult },
                { label: "Language", value: selectedTemplate.lang },
                { label: "Profile", value: selectedTemplate.profile },
              ]}
            />
            <p className="body-copy run-note">{selectedTemplate.description}</p>
          </Surface>

          <Surface title="Current runtime and policy" subtitle="Latest signed execution context seen by this browser session.">
            {!predicate ? (
              <EmptyState text="No signed execution selected yet. Run a demo or custom request to populate runtime and policy context." />
            ) : (
              <>
                <DefinitionList
                  items={[
                    { label: "Execution", value: latestExecution?.executionId || "none" },
                    { label: "Result", value: predicate.result_class },
                    { label: "Policy digest", value: predicate.policy_digest || "none" },
                    { label: "Runtime profile", value: predicate.runtime?.profile || "none" },
                    { label: "Policy profile", value: predicate.policy?.baseline.profile || "none" },
                  ]}
                />
                <Subsection title="Runtime envelope">
                  <DefinitionList
                    compact
                    items={[
                      { label: "VM shape", value: `${predicate.runtime?.vcpu_count || 0} vCPU • ${predicate.runtime?.memory_mb || 0} MB` },
                      { label: "Network", value: runtimeNetworkSummary(predicate) },
                      { label: "Broker", value: predicate.runtime?.broker?.enabled ? "enabled" : "disabled" },
                    ]}
                  />
                </Subsection>
                <Subsection title="Baseline policy">
                  <DefinitionList
                    compact
                    items={[
                      { label: "Language", value: predicate.policy?.baseline.language || "none" },
                      { label: "Timeout", value: predicate.policy ? `${predicate.policy.baseline.timeout_ms} ms` : "none" },
                      { label: "Network", value: predicate.policy ? policyNetworkSummary(predicate) : "none" },
                    ]}
                  />
                </Subsection>
              </>
            )}
          </Surface>
        </div>
      </div>
    </section>
  );
}

function ExecutionsWorkspace({
  executions,
  selectedExecution,
  onSelectExecution,
}: {
  executions: ExecutionRecord[];
  selectedExecution: ExecutionRecord | null;
  onSelectExecution: (executionId: string) => void;
}) {
  const predicate = selectedExecution?.receipt?.statement.predicate || null;
  const actions = predicate ? governedActionsFor(predicate) : selectedExecution?.governedEvents || [];

  return (
    <section className="page-stack">
      <PageHeader
        title="Executions"
        subtitle="Session-local execution history with live output, structured timeline, governed actions, and signed receipt detail."
      />
      <div className="resource-layout">
        <Surface title="Session executions" subtitle="Newest first. Select a row to inspect output and evidence.">
          <table className="data-table">
            <thead>
              <tr>
                <th>Execution</th>
                <th>Demo</th>
                <th>Status</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {executions.map((execution) => (
                <tr
                  key={execution.executionId}
                  className={classNames(selectedExecution?.executionId === execution.executionId && "is-selected")}
                  onClick={() => onSelectExecution(execution.executionId)}
                >
                  <td>
                    <div className="table-primary mono">{truncateMiddle(execution.executionId, 8)}</div>
                    <div className="table-secondary">{execution.language} • {execution.profile}</div>
                  </td>
                  <td>{execution.demoLabel}</td>
                  <td>
                    <span className={classNames("status-badge", statusTone(statusLabel(execution)))}>{statusLabel(execution)}</span>
                  </td>
                  <td>{formatTime(execution.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {executions.length === 0 ? <EmptyState text="No executions in this browser session yet." /> : null}
        </Surface>

        <div className="execution-detail-layout">
          <div className="page-stack">
            <Surface
              title={selectedExecution ? selectedExecution.demoLabel : "Live execution"}
              subtitle={selectedExecution ? `Execution ${selectedExecution.executionId}` : "Select an execution from the left list."}
              headerRight={
                selectedExecution ? (
                  <span className={classNames("status-badge", statusTone(statusLabel(selectedExecution)))}>{statusLabel(selectedExecution)}</span>
                ) : undefined
              }
            >
              {!selectedExecution ? (
                <EmptyState text="Select an execution to inspect stdout, stderr, timeline, and governed actions." />
              ) : (
                <div className="page-stack">
                  {selectedExecution.streamError ? <div className="inline-alert danger">{selectedExecution.streamError}</div> : null}
                  <div className="console-grid">
                    <ConsolePane label="stdout" value={selectedExecution.stdout} />
                    <ConsolePane label="stderr" value={selectedExecution.stderr} tone="danger" />
                  </div>
                  <TimelineTable timeline={selectedExecution.timeline} />
                  <GovernedActionTable actions={actions} />
                </div>
              )}
            </Surface>
          </div>

          <div className="page-stack">
            <Surface title="Execution metadata" subtitle="Primary identifiers and run status.">
              {selectedExecution ? (
                <DefinitionList
                  items={[
                    { label: "Execution ID", value: selectedExecution.executionId },
                    { label: "Demo", value: selectedExecution.demoLabel },
                    { label: "Proof dir", value: selectedExecution.proofDir || "pending" },
                    { label: "Duration", value: prettyDuration(selectedExecution.durationMs) },
                    {
                      label: "Exit code",
                      value:
                        selectedExecution.exitCode !== undefined
                          ? String(selectedExecution.exitCode)
                          : predicate && receiptExitCode(predicate) !== undefined
                            ? String(receiptExitCode(predicate))
                            : "pending",
                    },
                    { label: "Outcome", value: receiptOutcomeSummary(predicate) },
                  ]}
                />
              ) : (
                <EmptyState text="Execution metadata appears here after a row is selected." />
              )}
            </Surface>
            <Surface title="Runtime envelope" subtitle="Bound runtime facts from the signed receipt.">
              {predicate ? (
                <DefinitionList
                  items={[
                    { label: "Profile", value: predicate.runtime?.profile || "none" },
                    { label: "VM shape", value: `${predicate.runtime?.vcpu_count || 0} vCPU • ${predicate.runtime?.memory_mb || 0} MB` },
                    { label: "Cgroup memory", value: predicate.runtime?.cgroup?.memory_max_mb ? `${predicate.runtime.cgroup.memory_max_mb} MB max` : "none" },
                    { label: "Network", value: runtimeNetworkSummary(predicate) },
                    { label: "Broker", value: predicate.runtime?.broker?.enabled ? "enabled" : "disabled" },
                  ]}
                />
              ) : (
                <EmptyState text="Runtime envelope appears after the signed receipt arrives." />
              )}
            </Surface>
            <Surface title="Baseline policy" subtitle="Admission policy evidence bound into the receipt.">
              {predicate ? (
                <DefinitionList
                  items={[
                    { label: "Language", value: predicate.policy?.baseline.language || "none" },
                    { label: "Profile", value: predicate.policy?.baseline.profile || "none" },
                    { label: "Timeout", value: predicate.policy ? `${predicate.policy.baseline.timeout_ms} ms of ${predicate.policy.baseline.max_timeout_ms} ms` : "none" },
                    { label: "Code size", value: predicate.policy ? `${predicate.policy.baseline.code_size_bytes} bytes` : "none" },
                    { label: "Network", value: predicate.policy ? policyNetworkSummary(predicate) : "none" },
                    { label: "Intent", value: predicate.policy?.intent ? `${predicate.policy.intent.source || "intent"} • ${truncateMiddle(predicate.policy.intent.digest, 10)}` : "none" },
                  ]}
                />
              ) : (
                <EmptyState text="Baseline policy appears after the signed receipt arrives." />
              )}
            </Surface>
          </div>
        </div>
      </div>
    </section>
  );
}

function ReceiptsWorkspace({
  executions,
  selectedExecution,
  onSelectExecution,
}: {
  executions: ExecutionRecord[];
  selectedExecution: ExecutionRecord | null;
  onSelectExecution: (executionId: string) => void;
}) {
  const [inspectorTab, setInspectorTab] = useState<ReceiptInspectorTab>("trust");
  const predicate = selectedExecution?.receipt?.statement.predicate || null;
  const actions = predicate ? governedActionsFor(predicate) : [];
  const artifactItems = selectedExecution
    ? [
        { label: "Proof dir", value: selectedExecution.proofDir || "pending" },
        { label: "Receipt file", value: selectedExecution.receiptPath || "pending" },
        { label: "Receipt summary", value: selectedExecution.receiptSummaryPath || "pending" },
        { label: "Evidence digest", value: predicate?.evidence_digest || "pending" },
      ]
    : [];
  const inspectorTitle = inspectorTab === "trust" ? "Trust" : inspectorTab === "json" ? "Raw JSON" : "Artifacts";

  return (
    <section className="page-stack">
      <PageHeader
        title="Receipt Investigation"
        subtitle="Signed receipt investigation with a scan-first selector, structured evidence detail, and a secondary inspector for trust, artifacts, and JSON."
      />
      <div className="receipt-console-layout">
        <Surface
          title="Session receipts"
          subtitle="Newest finished receipts first."
          headerRight={<span className="surface-meta">{executions.length} receipts</span>}
        >
          <table className="data-table receipt-table scan-table">
            <thead>
              <tr>
                <th>Execution</th>
                <th>Result</th>
                <th>Finished</th>
                <th>Profile</th>
              </tr>
            </thead>
            <tbody>
              {executions.map((execution) => {
                const receipt = execution.receipt?.statement.predicate;
                return (
                  <tr
                    key={execution.executionId}
                    className={classNames(selectedExecution?.executionId === execution.executionId && "is-selected")}
                    onClick={() => onSelectExecution(execution.executionId)}
                  >
                    <td>
                      <div className="cell-stack">
                        <div className="table-primary mono">{truncateMiddle(execution.executionId, 8)}</div>
                        <div className="table-secondary text-truncate">{execution.demoLabel}</div>
                      </div>
                    </td>
                    <td>
                      <span className={classNames("status-badge", "is-compact", statusTone(receipt?.result_class || execution.status))}>
                        {receipt?.result_class || execution.status}
                      </span>
                    </td>
                    <td className="mono receipt-time-cell">{formatFinishedAt(receipt?.finished_at)}</td>
                    <td className="mono">{receipt?.runtime?.profile || receipt?.policy?.baseline.profile || execution.profile}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {executions.length === 0 ? <EmptyState text="No signed receipts are available in this browser session yet." /> : null}
        </Surface>

        <Surface
          title={selectedExecution ? "Structured evidence" : "Receipt detail"}
          subtitle={selectedExecution ? `Execution ${selectedExecution.executionId}` : "Select a receipt from the left list."}
        >
          {!selectedExecution || !predicate ? (
            <EmptyState text="Select a receipt-bearing execution to inspect structured evidence." />
          ) : (
            <div className="receipt-primary-stack">
              <Subsection title="Overview">
                <DefinitionList
                  compact
                  columns={2}
                  items={[
                    { label: "Result class", value: predicate.result_class },
                    { label: "Outcome", value: receiptOutcomeSummary(predicate) },
                    { label: "Execution ID", value: predicate.execution_id },
                    { label: "Proof dir", value: selectedExecution.proofDir || "pending" },
                    { label: "Finished", value: formatFinishedAt(predicate.finished_at) },
                  ]}
                />
              </Subsection>
              <Subsection title="Runtime">
                <DefinitionList
                  compact
                  columns={2}
                  items={[
                    { label: "Profile", value: predicate.runtime?.profile || "none" },
                    { label: "VM shape", value: `${predicate.runtime?.vcpu_count || 0} vCPU • ${predicate.runtime?.memory_mb || 0} MB` },
                    {
                      label: "Cgroup memory",
                      value: predicate.runtime?.cgroup?.memory_max_mb
                        ? `${predicate.runtime.cgroup.memory_max_mb} MB max`
                        : "none",
                    },
                    { label: "Network", value: runtimeNetworkSummary(predicate) },
                    { label: "Broker posture", value: predicate.runtime?.broker?.enabled ? "enabled" : "disabled" },
                    {
                      label: "Overrides",
                      value:
                        predicate.runtime?.applied_overrides && predicate.runtime.applied_overrides.length > 0
                          ? predicate.runtime.applied_overrides.join(", ")
                          : "none",
                    },
                  ]}
                />
              </Subsection>
              <Subsection title="Policy">
                <DefinitionList
                  compact
                  columns={2}
                  items={[
                    { label: "Policy digest", value: predicate.policy_digest || "none" },
                    { label: "Language", value: predicate.policy?.baseline.language || "none" },
                    { label: "Baseline profile", value: predicate.policy?.baseline.profile || "none" },
                    {
                      label: "Timeout",
                      value: predicate.policy
                        ? `${predicate.policy.baseline.timeout_ms} ms of ${predicate.policy.baseline.max_timeout_ms} ms`
                        : "none",
                    },
                    { label: "Code size", value: predicate.policy ? `${predicate.policy.baseline.code_size_bytes} bytes` : "none" },
                    { label: "Network", value: predicate.policy ? policyNetworkSummary(predicate) : "none" },
                    {
                      label: "Intent",
                      value: predicate.policy?.intent
                        ? `${predicate.policy.intent.source || "intent"} • ${truncateMiddle(predicate.policy.intent.digest, 10)}`
                        : "none",
                    },
                  ]}
                />
              </Subsection>
              <GovernedActionTable actions={actions} compact />
              <Subsection title="Trust limitations">
                <div className="inspector-note">
                  {predicate.trust.limitations?.length ? (
                    <BulletList items={predicate.trust.limitations} />
                  ) : (
                    <p className="body-copy">No additional browser-visible trust limitations were included in this receipt.</p>
                  )}
                </div>
              </Subsection>
              <Subsection title="Evidence references">
                <DefinitionList
                  compact
                  columns={2}
                  items={[
                    { label: "Proof dir", value: selectedExecution.proofDir || "pending" },
                    { label: "Evidence digest", value: predicate.evidence_digest },
                    { label: "Receipt file", value: selectedExecution.receiptPath || "pending" },
                    { label: "Receipt summary", value: selectedExecution.receiptSummaryPath || "pending" },
                  ]}
                />
              </Subsection>
            </div>
          )}
        </Surface>

        <Surface
          title={inspectorTitle}
          subtitle="Secondary inspection surface for trust, artifacts, and raw receipt JSON."
          headerRight={
            <div className="segmented-control segmented-control-tight" role="tablist" aria-label="Receipt inspector">
              <button type="button" role="tab" aria-selected={inspectorTab === "trust"} className={classNames(inspectorTab === "trust" && "is-active")} onClick={() => setInspectorTab("trust")}>
                Trust
              </button>
              <button type="button" role="tab" aria-selected={inspectorTab === "json"} className={classNames(inspectorTab === "json" && "is-active")} onClick={() => setInspectorTab("json")}>
                JSON
              </button>
              <button type="button" role="tab" aria-selected={inspectorTab === "artifacts"} className={classNames(inspectorTab === "artifacts" && "is-active")} onClick={() => setInspectorTab("artifacts")}>
                Artifacts
              </button>
            </div>
          }
        >
          {!selectedExecution || !predicate ? (
            <EmptyState text="Select a receipt to inspect trust data, artifact references, or raw JSON." />
          ) : null}
          {selectedExecution && predicate && inspectorTab === "trust" ? (
            <div className="page-stack">
              <div className="inspector-note">
                Browser view does not verify the DSSE signature. Use <span className="mono">aegis receipt verify</span> against the proof directory for verification.
              </div>
              <DefinitionList
                compact
                items={[
                  { label: "Signing mode", value: predicate.trust.signing_mode },
                  { label: "Key source", value: predicate.trust.key_source },
                  { label: "Attestation", value: predicate.trust.attestation },
                  { label: "Verification material", value: predicate.trust.verification_material },
                  { label: "Started", value: predicate.started_at },
                  { label: "Finished", value: predicate.finished_at },
                ]}
              />
            </div>
          ) : null}
          {selectedExecution && predicate && inspectorTab === "json" ? (
            <div className="page-stack">
              <div className="inspector-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void navigator.clipboard?.writeText(JSON.stringify(selectedExecution.receipt, null, 2))}
                >
                  Copy JSON
                </button>
              </div>
              <pre className="receipt-json-view">{JSON.stringify(selectedExecution.receipt, null, 2)}</pre>
            </div>
          ) : null}
          {selectedExecution && predicate && inspectorTab === "artifacts" ? <DefinitionList compact items={artifactItems} /> : null}
        </Surface>
      </div>
    </section>
  );
}

function DemosWorkspace({
  demos,
  selectedDemo,
  lastExecutions,
  onSelectDemo,
  onLoadIntoRun,
}: {
  demos: DemoTemplate[];
  selectedDemo: DemoKey;
  lastExecutions: ExecutionRecord[];
  onSelectDemo: (demo: DemoKey) => void;
  onLoadIntoRun: (demo: DemoKey) => void;
}) {
  const selectedTemplate = demos.find((demo) => demo.id === selectedDemo) || demos[0];
  const latestForDemo = lastExecutions.find((execution) => execution.demo === selectedTemplate.id) || null;
  const latestPredicate = latestForDemo?.receipt?.statement.predicate || null;
  const latestByDemo = useMemo(() => {
    const map = new Map<DemoKey, ExecutionRecord>();
    for (const execution of lastExecutions) {
      if (!map.has(execution.demo)) {
        map.set(execution.demo, execution);
      }
    }
    return map;
  }, [lastExecutions]);

  return (
    <section className="page-stack">
      <PageHeader
        title="Demo Templates"
        subtitle="Packaged operator workflows. Use the selector to inspect what each demo proves, then load it into Run."
      />
      <div className="demo-layout">
        <Surface title="Packaged demos" subtitle="Three flows only: clean execution, denied exfil, brokered outbound.">
          <table className="data-table demo-table scan-table">
            <thead>
              <tr>
                <th>Demo</th>
                <th>Language</th>
                <th>Profile</th>
                <th>Expected</th>
                <th>Latest</th>
              </tr>
            </thead>
            <tbody>
              {demos.map((demo) => {
                const latestExecution = latestByDemo.get(demo.id);
                const latestStatus = latestExecution?.receipt?.statement.predicate.result_class || latestExecution?.status || "none";
                return (
                  <tr key={demo.id} className={classNames(selectedDemo === demo.id && "is-selected")} onClick={() => onSelectDemo(demo.id)}>
                    <td>
                      <div className="table-primary text-truncate">{demo.label}</div>
                    </td>
                    <td className="mono">{demo.lang}</td>
                    <td className="mono">{demo.profile}</td>
                    <td className="mono">{demo.expectedResult}</td>
                    <td>
                      {latestExecution ? (
                        <span className={classNames("status-badge", "is-compact", statusTone(latestStatus))}>{latestStatus}</span>
                      ) : (
                        <span className="table-secondary">not run</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Surface>

        <Surface
          title={selectedTemplate.label}
          subtitle="Packaged demo detail, expected evidence, and latest session result for this template."
          headerRight={
            <button type="button" className="primary-button" onClick={() => onLoadIntoRun(selectedTemplate.id)}>
              Load into run
            </button>
          }
        >
          <div className="demo-detail-layout">
            <div className="page-stack">
              <Subsection title="Purpose">
                <p className="body-copy">{selectedTemplate.description}</p>
              </Subsection>
              <Subsection title="What it proves">
                <BulletList items={selectedTemplate.proves} />
              </Subsection>
              <Subsection title="Expected evidence">
                <BulletList items={selectedTemplate.expectedEvidence} />
              </Subsection>
            </div>

            <div className="page-stack">
              <Subsection title="Template settings">
                <DefinitionList
                  items={[
                    { label: "Language", value: selectedTemplate.lang },
                    { label: "Profile", value: selectedTemplate.profile },
                    { label: "Timeout", value: `${selectedTemplate.timeoutMs} ms` },
                    { label: "Expected result", value: selectedTemplate.expectedResult },
                  ]}
                />
              </Subsection>
              <Subsection title="Latest session run">
                {!latestForDemo ? (
                  <EmptyState text="This demo has not been run in the current browser session." />
                ) : (
                  <DefinitionList
                    items={[
                      { label: "Execution", value: latestForDemo.executionId },
                      { label: "Status", value: latestPredicate?.result_class || latestForDemo.status },
                      { label: "Proof dir", value: latestForDemo.proofDir || "pending" },
                      { label: "Policy digest", value: latestPredicate?.policy_digest || "none" },
                    ]}
                  />
                )}
              </Subsection>
            </div>
          </div>
        </Surface>
      </div>
    </section>
  );
}

function Surface({
  title,
  subtitle,
  children,
  headerRight,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  headerRight?: ReactNode;
}) {
  return (
    <section className="surface">
      <div className="surface-header">
        <div>
          <h3 className="surface-title">{title}</h3>
          <p className="surface-subtitle">{subtitle}</p>
        </div>
        {headerRight ? <div>{headerRight}</div> : null}
      </div>
      <div className="surface-body">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

function ConsolePane({ label, value, tone = "neutral" }: { label: string; value: string; tone?: "neutral" | "danger" }) {
  return (
    <div className={classNames("console-pane", tone === "danger" && "is-danger")}>
      <div className="console-pane-header">{label}</div>
      <pre className="console-pane-body">{value || `No ${label} received.`}</pre>
    </div>
  );
}

function DefinitionList({
  items,
  compact = false,
  columns = 1,
}: {
  items: Array<{ label: string; value: string }>;
  compact?: boolean;
  columns?: 1 | 2;
}) {
  return (
    <dl className={classNames("definition-list", compact && "is-compact", columns === 2 && "is-two-column")}>
      {items.map((item) => (
        <div key={`${item.label}-${item.value}`} className="definition-row">
          <dt>{item.label}</dt>
          <dd className={item.value.length > 28 ? "mono" : undefined}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function TimelineTable({ timeline }: { timeline: TimelineEntry[] }) {
  return (
    <div className="subsection">
      <div className="subsection-heading">Execution timeline</div>
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Stage</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {timeline.map((entry) => (
            <tr key={entry.id}>
              <td className="mono">{formatTime(entry.at)}</td>
              <td>
                <span className={classNames("status-badge", timelineToneClass(entry.tone))}>{entry.stage}</span>
              </td>
              <td>
                <div className="table-primary">{entry.message}</div>
                {entry.detail ? <div className="table-secondary mono">{entry.detail}</div> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function timelineToneClass(tone: TimelineTone) {
  switch (tone) {
    case "success":
      return "status-success";
    case "warning":
      return "status-warning";
    case "danger":
      return "status-danger";
    case "info":
      return "status-progress";
    default:
      return "status-neutral";
  }
}

function GovernedActionTable({
  actions,
  compact = false,
}: {
  actions: GovernedAction[];
  compact?: boolean;
}) {
  return (
    <div className="subsection">
      <div className="subsection-heading">Governed actions</div>
      {actions.length === 0 ? (
        <EmptyState text="No governed actions were emitted for this execution." compact={compact} />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Decision</th>
              <th>Action</th>
              <th>Target</th>
              <th>Marker / binding</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((action, index) => (
              <tr key={`${action.action_type}-${index}-${action.target}`}>
                <td>
                  <span className={classNames("status-badge", parseActionTone(action.decision))}>{action.decision}</span>
                </td>
                <td>
                  <div className="table-primary mono">{action.action_type}</div>
                  {action.reason ? <div className="table-secondary">{action.reason}</div> : null}
                </td>
                <td className="mono">{action.target}</td>
                <td className="mono">{action.denial_marker || action.binding_name || "none"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Subsection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="subsection">
      <div className="subsection-heading">{title}</div>
      {children}
    </section>
  );
}

function BulletList({ items }: { items: string[] }) {
  return (
    <ul className="bullet-list">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function EmptyState({ text, compact = false }: { text: string; compact?: boolean }) {
  return <div className={classNames("empty-state", compact && "is-compact")}>{text}</div>;
}

import React, { useEffect, useMemo, useRef, useState } from "react";

const API_BASE =
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_AEGIS_API_BASE) ||
  (typeof process !== "undefined" && process.env && (process.env.REACT_APP_AEGIS_API_BASE || process.env.NEXT_PUBLIC_AEGIS_API_BASE)) ||
  (typeof window !== "undefined" && window.location ? window.location.origin : undefined) ||
  "http://localhost:8080";

const PRESETS = [
  {
    id: "allowed-dns",
    label: "Allowed DNS",
    marker: "01",
    description: "Allowlisted resolution and selective egress rule installation.",
    lang: "python",
    timeout_ms: 10000,
    code: `import socket
infos = socket.getaddrinfo("pypi.org", 443, type=socket.SOCK_STREAM)
ips = list(dict.fromkeys(item[4][0] for item in infos))
print("RESOLVED:", ips)`,
  },
  {
    id: "denied-dns",
    label: "Denied DNS",
    marker: "02",
    description: "Query outside the allowlist and show the refusal cleanly.",
    lang: "python",
    timeout_ms: 10000,
    code: `import socket
try:
    socket.gethostbyname("example.com")
    print("BAD: resolved")
except Exception:
    print("GOOD: denied")`,
  },
  {
    id: "fork-bomb",
    label: "Fork Bomb",
    marker: "03",
    description: "Trigger guest PID pressure and watch the cap clamp it.",
    lang: "bash",
    timeout_ms: 10000,
    code: `for i in $(seq 1 256); do
  bash -c "sleep 30" &
done
wait`,
  },
  {
    id: "memory-bomb",
    label: "Memory Pressure",
    marker: "04",
    description: "Force a safe memory failure under pressure without overclaiming an OOM-kill proof.",
    lang: "python",
    timeout_ms: 10000,
    code: `x = b"x" * 10**9
print(len(x))`,
  },
  {
    id: "reverse-shell",
    label: "Blocked Outbound Connect",
    marker: "05",
    description: "Attempt a short outbound connect and show the blocked result cleanly.",
    lang: "python",
    timeout_ms: 5000,
    code: `import os, socket

s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
    if rc == 0:
        msg = "BAD: connected\\n"
    else:
        msg = f"GOOD: connection blocked: errno={rc}\\n"
except Exception as e:
    msg = f"GOOD: connection blocked: {type(e).__name__}: {e}\\n"
finally:
    try:
        s.close()
    except Exception:
        pass

os.write(1, msg.encode())`,
  },
  {
    id: "huge-stdout",
    label: "Huge Stdout",
    marker: "06",
    description: "Demonstrate truncation enforcement.",
    lang: "python",
    timeout_ms: 10000,
    code: `import sys
sys.stdout.write("A" * 70000)`,
  },
];

const PHASE_LABELS = {
  idle: "IDLE",
  executing: "EXECUTING",
  streaming: "STREAMING",
  complete: "COMPLETE",
};

const EVENT_STYLES = {
  "vm.boot.start": { badge: "BOOT", tone: "slate" },
  "vm.boot.ready": { badge: "VM READY", tone: "slate" },
  "cgroup.configured": { badge: "CGROUP", tone: "blue" },
  "dns.query:allow": { badge: "DNS ALLOW", tone: "green" },
  "dns.query:deny": { badge: "DNS DENY", tone: "red" },
  "dns.query:error": { badge: "DNS ERR", tone: "amber" },
  "net.rule.add": { badge: "RULE +", tone: "amber" },
  "net.rule.drop": { badge: "RULE DROP", tone: "slate" },
  "exec.exit:0": { badge: "EXIT 0", tone: "green" },
  "exec.exit:error": { badge: "EXIT", tone: "red" },
  "cleanup.start": { badge: "CLEANUP", tone: "slate" },
  "cleanup.done:clean": { badge: "CLEAN", tone: "green" },
  "cleanup.done:dirty": { badge: "DIRTY", tone: "red" },
  "containment.receipt:completed": { badge: "COMPLETED", tone: "green" },
  "containment.receipt:denied": { badge: "DENIED", tone: "gold" },
  "containment.receipt:abnormal": { badge: "ABNORMAL", tone: "red" },
  "containment.receipt:reconciled": { badge: "RECONCILED", tone: "slate" },
  "containment.receipt:unknown": { badge: "RECEIPT", tone: "slate" },
  "guest.proc.sample:limit": { badge: "PIDS LIMIT", tone: "red" },
  "output.truncated": { badge: "TRUNCATED", tone: "amber" },
};

function createExecutionId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID().toLowerCase();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join("-");
}

function formatNumber(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "0";
  }
  return new Intl.NumberFormat("en-US").format(value);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function bytesToHuman(bytes) {
  if (!bytes || bytes <= 0) {
    return "0 MB";
  }
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) {
    return `${(mb / 1024).toFixed(1)} GB`;
  }
  return `${Math.round(mb)} MB`;
}

function relativeTime(ts, startTs) {
  if (!ts || !startTs) {
    return "+0.00s";
  }
  const delta = Math.max(0, ts - startTs);
  return `+${(delta / 1000).toFixed(2)}s`;
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function receiptPredicate(receipt) {
  const predicate = receipt?.statement?.predicate;
  return predicate && typeof predicate === "object" ? predicate : null;
}

function receiptTone(receipt) {
  const resultClass = receiptPredicate(receipt)?.result_class;
  switch (resultClass) {
    case "completed":
      return "green";
    case "abnormal":
      return "red";
    case "denied":
      return "gold";
    default:
      return "slate";
  }
}

function receiptLabel(receipt) {
  return String(receiptPredicate(receipt)?.result_class || "pending").toUpperCase();
}

function toneClasses(tone) {
  switch (tone) {
    case "green":
      return "border-emerald-400/40 bg-emerald-500/10 text-emerald-300";
    case "red":
      return "border-red-400/40 bg-red-500/10 text-red-300";
    case "amber":
      return "border-amber-400/40 bg-amber-500/10 text-amber-200";
    case "gold":
      return "border-amber-300/60 bg-amber-400/10 text-amber-100";
    case "blue":
      return "border-sky-400/40 bg-sky-500/10 text-sky-200";
    default:
      return "border-white/10 bg-white/5 text-slate-300";
  }
}

function deriveEventPresentation(event) {
  if (!event) {
    return null;
  }

  if (event.kind === "cgroup.sample" || event.kind === "exec.stdout" || event.kind === "exec.stderr") {
    return null;
  }

  if (event.kind === "dns.query") {
    const action = event.data?.action || "error";
    const style = EVENT_STYLES[`dns.query:${action}`] || EVENT_STYLES["dns.query:error"];
    return {
      key: `${event.kind}:${action}:${event.ts}`,
      badge: style.badge,
      tone: style.tone,
      detail:
        action === "allow"
          ? `${event.data?.domain || "unknown"} -> ${(event.data?.resolved || []).join(", ")}`
          : `${event.data?.domain || "unknown"} :: ${event.data?.reason || "blocked"}`,
    };
  }

  if (event.kind === "net.rule.add") {
    const style = EVENT_STYLES["net.rule.add"];
    return {
      key: `${event.kind}:${event.ts}:${event.data?.dst || ""}:${event.data?.ports || ""}`,
      badge: style.badge,
      tone: style.tone,
      detail: `${event.data?.dst || "unknown"} ports ${event.data?.ports || "?"}`,
    };
  }

  if (event.kind === "net.rule.drop") {
    const style = EVENT_STYLES["net.rule.drop"];
    return {
      key: `${event.kind}:${event.ts}`,
      badge: style.badge,
      tone: style.tone,
      detail: `${event.data?.chain || "FORWARD"} ${event.data?.direction || ""}`.trim(),
    };
  }

  if (event.kind === "exec.exit") {
    const style = event.data?.exit_code === 0 ? EVENT_STYLES["exec.exit:0"] : EVENT_STYLES["exec.exit:error"];
    return {
      key: `${event.kind}:${event.ts}`,
      badge: style.badge,
      tone: style.tone,
      detail: `code ${event.data?.exit_code ?? "?"} :: ${event.data?.reason || "completed"}`,
    };
  }

  if (event.kind === "cleanup.done") {
    const style = event.data?.all_clean ? EVENT_STYLES["cleanup.done:clean"] : EVENT_STYLES["cleanup.done:dirty"];
    return {
      key: `${event.kind}:${event.ts}`,
      badge: style.badge,
      tone: style.tone,
      detail: event.data?.all_clean ? "all resources removed" : prettyJson(event.data || {}),
    };
  }

  if (event.kind === "containment.receipt") {
    const predicate = receiptPredicate(event.data);
    const resultClass = predicate?.result_class || "unknown";
    const style = EVENT_STYLES[`containment.receipt:${resultClass}`] || EVENT_STYLES["containment.receipt:unknown"];
    return {
      key: `${event.kind}:${event.ts}`,
      badge: style.badge,
      tone: style.tone,
      detail: `${resultClass} :: ${predicate?.outcome?.reason || "n/a"}`,
    };
  }

  if (event.kind === "guest.proc.sample") {
    const current = event.data?.pids_current || 0;
    const limit = event.data?.pids_limit || 0;
    if (limit > 0 && current >= limit) {
      const style = EVENT_STYLES["guest.proc.sample:limit"];
      return {
        key: `${event.kind}:${event.ts}`,
        badge: style.badge,
        tone: style.tone,
        detail: `${current}/${limit} guest processes`,
      };
    }
    return null;
  }

  const style = EVENT_STYLES[event.kind] || { badge: event.kind.toUpperCase(), tone: "slate" };
  return {
    key: `${event.kind}:${event.ts}`,
    badge: style.badge,
    tone: style.tone,
    detail: event.data && Object.keys(event.data).length > 0 ? prettyJson(event.data) : "no payload",
  };
}

function gaugeTone(pct) {
  if (pct >= 80) {
    return "from-red-500 to-orange-400";
  }
  if (pct >= 50) {
    return "from-amber-400 to-yellow-300";
  }
  return "from-emerald-400 to-lime-300";
}

function summarizeReceipt(receipt) {
  const predicate = receiptPredicate(receipt);
  if (!predicate) {
    return [];
  }
  const outcome = predicate.outcome || {};
  const divergence = predicate.divergence || {};
  const trust = predicate.trust || {};
  return [
    { label: "Result Class", value: String(predicate.result_class || "unknown").toUpperCase() },
    { label: "Outcome", value: `${outcome.reason || "unknown"} (${outcome.exit_code ?? "?"})` },
    { label: "Execution Status", value: predicate.execution_status || "unknown" },
    { label: "Divergence", value: String(divergence.verdict || "unknown").toUpperCase() },
    { label: "Runtime Events", value: predicate.runtime_event_count ?? 0 },
    { label: "Signing", value: trust.signing_mode || "unknown" },
    { label: "Key Source", value: trust.key_source || "unknown" },
    { label: "Evidence Digest", value: predicate.evidence_digest ? `${String(predicate.evidence_digest).slice(0, 16)}...` : "missing" },
  ];
}

function AegisProvingGround() {
  const [phase, setPhase] = useState("idle");
  const [selectedPresetId, setSelectedPresetId] = useState(PRESETS[0].id);
  const [language, setLanguage] = useState(PRESETS[0].lang);
  const [code, setCode] = useState(PRESETS[0].code);
  const [timeoutMs, setTimeoutMs] = useState(PRESETS[0].timeout_ms);
  const [stats, setStats] = useState(null);
  const [statsError, setStatsError] = useState("");
  const [executionId, setExecutionId] = useState("");
  const [executionResult, setExecutionResult] = useState(null);
  const [executionError, setExecutionError] = useState("");
  const [receipt, setReceipt] = useState(null);
  const [events, setEvents] = useState([]);
  const [displayEvents, setDisplayEvents] = useState([]);
  const [cgroupSamples, setCgroupSamples] = useState(0);
  const [sseStatus, setSseStatus] = useState("idle");
  const [memoryGauge, setMemoryGauge] = useState({ current: 0, max: 268435456, pct: 0 });
  const [pidGauge, setPidGauge] = useState({ current: 0, max: 128, pct: 0 });
  const eventSourceRef = useRef(null);
  const animationTimersRef = useRef([]);
  const streamAnchorRef = useRef(null);
  const firstEventTsRef = useRef(null);
  const staggerIndexRef = useRef(0);

  const selectedPreset = useMemo(
    () => PRESETS.find((preset) => preset.id === selectedPresetId) || PRESETS[0],
    [selectedPresetId]
  );

  useEffect(() => {
    loadStats();
    return () => {
      disconnectStream();
      clearAnimationTimers();
    };
  }, []);

  useEffect(() => {
    streamAnchorRef.current?.scrollIntoView({ block: "end" });
  }, [displayEvents]);

  function clearAnimationTimers() {
    for (const timer of animationTimersRef.current) {
      clearTimeout(timer);
    }
    animationTimersRef.current = [];
  }

  function resetExecutionState(nextExecutionId) {
    setExecutionId(nextExecutionId);
    setExecutionResult(null);
    setExecutionError("");
    setReceipt(null);
    setEvents([]);
    setDisplayEvents([]);
    setCgroupSamples(0);
    setMemoryGauge({ current: 0, max: 268435456, pct: 0 });
    setPidGauge({ current: 0, max: 128, pct: 0 });
    firstEventTsRef.current = null;
    staggerIndexRef.current = 0;
  }

  async function loadStats() {
    try {
      setStatsError("");
      const response = await fetch(`${API_BASE}/v1/stats`);
      if (!response.ok) {
        throw new Error(`stats ${response.status}`);
      }
      const payload = await response.json();
      setStats(payload);
    } catch (error) {
      setStatsError(error.message || String(error));
    }
  }

  function disconnectStream() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }

  function pushVisibleEvent(event) {
    const presented = deriveEventPresentation(event);
    if (!presented) {
      return;
    }
    if (!firstEventTsRef.current) {
      firstEventTsRef.current = event.ts || Date.now();
    }
    const sequence = staggerIndexRef.current;
    staggerIndexRef.current += 1;
    const timer = setTimeout(() => {
      setDisplayEvents((current) => [...current, { ...presented, relativeTs: relativeTime(event.ts, firstEventTsRef.current || event.ts) }]);
    }, 100 * sequence + 60);
    animationTimersRef.current.push(timer);
  }

  function updateGaugesFromEvent(event) {
    if (event.kind === "cgroup.sample") {
      setCgroupSamples((count) => count + 1);
      const max = event.data?.memory_max || 1;
      const current = event.data?.memory_current || 0;
      setMemoryGauge({
        current,
        max,
        pct: clamp(event.data?.memory_pct ?? (current / max) * 100, 0, 100),
      });
      const pidsCurrent = event.data?.pids_current || 0;
      const pidsMax = event.data?.pids_max || 128;
      setPidGauge((prev) => {
        if (prev.current > pidsCurrent && prev.max >= pidsMax) {
          return prev;
        }
        return {
          current: pidsCurrent,
          max: pidsMax,
          pct: clamp(event.data?.pids_pct ?? (pidsCurrent / pidsMax) * 100, 0, 100),
        };
      });
      return;
    }

    if (event.kind === "guest.proc.sample") {
      const current = event.data?.pids_current || 0;
      const max = event.data?.pids_limit || 128;
      setPidGauge({
        current,
        max,
        pct: clamp(event.data?.pids_pct ?? (current / max) * 100, 0, 100),
      });
    }
  }

  function handleTelemetryEvent(raw) {
    setEvents((current) => [...current, raw]);
    updateGaugesFromEvent(raw);

    if (raw.kind === "containment.receipt") {
      setReceipt(raw.data);
      setPhase("complete");
      loadStats();
    } else if (phase === "executing") {
      setPhase("streaming");
    }

    pushVisibleEvent(raw);
  }

  function openTelemetryStream(execId) {
    disconnectStream();
    setSseStatus("connecting");
    const stream = new EventSource(`${API_BASE}/v1/events/${execId}`);
    eventSourceRef.current = stream;

    stream.onopen = () => {
      setSseStatus("connected");
    };

    stream.onerror = () => {
      setSseStatus("disconnected");
    };

    stream.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data);
        handleTelemetryEvent(payload);
      } catch (error) {
        setExecutionError(`telemetry parse error: ${error.message || error}`);
      }
    };
  }

  async function runExecution() {
    const execId = createExecutionId();
    resetExecutionState(execId);
    clearAnimationTimers();
    setPhase("executing");
    setSseStatus("idle");
    openTelemetryStream(execId);

    try {
      const response = await fetch(`${API_BASE}/v1/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          execution_id: execId,
          lang: language,
          code,
          timeout_ms: Number(timeoutMs) || selectedPreset.timeout_ms,
        }),
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result?.error || `execute ${response.status}`);
      }

      setExecutionResult(result);
      if (result?.error) {
        setExecutionError(result.error);
      }

      if (result?.output_truncated) {
        handleTelemetryEvent({
          exec_id: execId,
          ts: Date.now(),
          kind: "output.truncated",
          data: { bytes: (result.stdout || "").length + (result.stderr || "").length },
        });
      }
    } catch (error) {
      setExecutionError(error.message || String(error));
      setPhase("complete");
      disconnectStream();
    } finally {
      setTimeout(() => {
        loadStats();
      }, 300);
    }
  }

  function loadPreset(preset) {
    setSelectedPresetId(preset.id);
    setLanguage(preset.lang);
    setCode(preset.code);
    setTimeoutMs(preset.timeout_ms);
  }

  const summaryStats = [
    { label: "executions", value: stats?.total_executions ?? 0, tone: "text-slate-100" },
    { label: "completed", value: stats?.total_completed ?? 0, tone: "text-emerald-300" },
    { label: "non-completed", value: stats?.total_contained ?? 0, tone: "text-amber-200" },
  ];

  const receiptSummary = summarizeReceipt(receipt);
  const stdout = executionResult?.stdout || "";
  const stderr = executionResult?.stderr || executionError || "";

  return (
    <div className="min-h-screen bg-[#090b10] text-slate-100">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&display=swap');
        .aegis-grid {
          background-image:
            linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
          background-size: 42px 42px;
        }
        .noise-overlay::before {
          content: "";
          position: absolute;
          inset: 0;
          pointer-events: none;
          background:
            radial-gradient(circle at 20% 20%, rgba(239,68,68,0.08), transparent 30%),
            radial-gradient(circle at 80% 0%, rgba(245,158,11,0.08), transparent 24%),
            radial-gradient(circle at 60% 100%, rgba(34,197,94,0.08), transparent 24%);
          mix-blend-mode: screen;
        }
        .telemetry-enter {
          animation: telemetry-enter 420ms cubic-bezier(0.16, 1, 0.3, 1) both;
        }
        @keyframes telemetry-enter {
          from { opacity: 0; transform: translateX(18px); }
          to { opacity: 1; transform: translateX(0); }
        }
        .receipt-pulse {
          animation: receipt-pulse 1200ms ease-out both;
        }
        @keyframes receipt-pulse {
          0% { box-shadow: 0 0 0 rgba(245, 158, 11, 0.0); transform: translateY(10px); opacity: 0; }
          100% { box-shadow: 0 0 40px rgba(245, 158, 11, 0.12); transform: translateY(0); opacity: 1; }
        }
      `}</style>

      <div className="relative overflow-hidden aegis-grid noise-overlay">
        <div className="mx-auto max-w-[1500px] px-4 py-6 md:px-6 lg:px-8">
          <header className="mb-6 border border-white/10 bg-white/[0.03] px-5 py-5 backdrop-blur-sm">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
              <div className="space-y-3">
                <div className="text-[11px] uppercase tracking-[0.45em] text-red-300/80">Industrial Security Terminal</div>
                <h1 className="font-['JetBrains_Mono'] text-3xl font-extrabold tracking-[0.18em] text-white md:text-5xl">
                  AEGIS PROVING GROUND
                </h1>
                <div className="max-w-3xl text-sm leading-6 text-slate-300 md:text-base">
                  Firecracker microVM sandbox for AI-generated code. Trigger a real attack, watch the defense plane react,
                  and read the signed DSSE receipt that closes the loop.
                </div>
                <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.24em] text-slate-400">
                  <span className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-emerald-200">
                    live backend
                  </span>
                  <span className="rounded-full border border-amber-400/20 bg-amber-500/10 px-3 py-1 text-amber-100">
                    self-hostable
                  </span>
                  <a
                    href="https://github.com/cellardoor/aegis"
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-full border border-white/10 px-3 py-1 text-slate-200 transition hover:border-white/25 hover:text-white"
                  >
                    open source
                  </a>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                {summaryStats.map((item) => (
                  <div key={item.label} className="min-w-[150px] border border-white/10 bg-black/20 px-4 py-3">
                    <div className="text-[10px] uppercase tracking-[0.3em] text-slate-500">{item.label}</div>
                    <div className={`mt-2 font-['JetBrains_Mono'] text-2xl font-bold ${item.tone}`}>{formatNumber(item.value)}</div>
                  </div>
                ))}
              </div>
            </div>
          </header>

          <div className="grid gap-6 xl:grid-cols-[420px_minmax(0,1fr)]">
            <section className="border border-white/10 bg-[#10131b]/90 p-4 backdrop-blur-md">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <div className="text-xs uppercase tracking-[0.32em] text-slate-500">Attack Scenarios</div>
                  <div className="mt-1 font-['JetBrains_Mono'] text-lg font-semibold text-slate-100">Choose a detonation</div>
                </div>
                <div className="rounded-full border border-white/10 px-3 py-1 font-['JetBrains_Mono'] text-xs uppercase tracking-[0.24em] text-slate-300">
                  {PHASE_LABELS[phase]}
                </div>
              </div>

              <div className="space-y-2">
                {PRESETS.map((preset) => {
                  const active = preset.id === selectedPresetId;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => loadPreset(preset)}
                      disabled={phase === "executing" || phase === "streaming"}
                      className={`group w-full border px-4 py-3 text-left transition ${
                        active
                          ? "border-red-400/70 bg-red-500/10 shadow-[0_0_0_1px_rgba(239,68,68,0.15)]"
                          : "border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.05]"
                      } disabled:cursor-not-allowed disabled:opacity-60`}
                    >
                      <div className="flex items-start gap-4">
                        <div
                          className={`mt-0.5 flex h-10 w-10 items-center justify-center border font-['JetBrains_Mono'] text-sm font-semibold ${
                            active ? "border-red-300/50 text-red-200" : "border-white/10 text-slate-400"
                          }`}
                        >
                          {preset.marker}
                        </div>
                        <div className="min-w-0">
                          <div className="font-['JetBrains_Mono'] text-sm font-semibold uppercase tracking-[0.14em] text-white">
                            {preset.label}
                          </div>
                          <div className="mt-1 text-sm leading-5 text-slate-400">{preset.description}</div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>

              <div className="mt-5 border border-white/10 bg-black/20 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-[0.32em] text-slate-500">Custom Code</div>
                    <div className="mt-1 font-['JetBrains_Mono'] text-sm font-semibold text-slate-100">
                      Modify the payload before execution
                    </div>
                    <div className="mt-2 max-w-md text-xs leading-5 text-slate-400">
                      Profile selection is not exposed in this UI yet. Runs use the policy default unless another client sets <code>profile</code>.
                    </div>
                  </div>
                  <div className="rounded-full border border-white/10 px-2 py-1 text-[10px] uppercase tracking-[0.24em] text-slate-400">
                    live VM
                  </div>
                </div>

                <div className="mb-3 grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1">
                    <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Language</div>
                    <select
                      value={language}
                      onChange={(event) => setLanguage(event.target.value)}
                      className="w-full border border-white/10 bg-[#0b0f16] px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-red-300/50"
                    >
                      <option value="python">Python</option>
                      <option value="bash">Bash</option>
                      <option value="node">Node.js</option>
                    </select>
                  </label>

                  <label className="space-y-1">
                    <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Timeout</div>
                    <input
                      value={timeoutMs}
                      onChange={(event) => setTimeoutMs(event.target.value)}
                      type="number"
                      min="1000"
                      step="500"
                      className="w-full border border-white/10 bg-[#0b0f16] px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-red-300/50"
                    />
                  </label>
                </div>

                <textarea
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  spellCheck={false}
                  className="h-64 w-full resize-none border border-white/10 bg-[#070a11] p-4 font-['JetBrains_Mono'] text-sm leading-6 text-slate-100 outline-none transition focus:border-red-300/50"
                />

                <div className="mt-4 flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    onClick={runExecution}
                    disabled={phase === "executing" || phase === "streaming"}
                    className="inline-flex items-center gap-3 border border-red-400/40 bg-red-500/15 px-5 py-3 font-['JetBrains_Mono'] text-sm font-semibold uppercase tracking-[0.18em] text-red-100 transition hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <span className="inline-flex h-2 w-2 rounded-full bg-red-300" />
                    {phase === "executing" || phase === "streaming" ? "Booting VM..." : "Execute"}
                  </button>
                  <div className="text-xs uppercase tracking-[0.22em] text-slate-500">
                    Base URL: <span className="text-slate-300">{API_BASE}</span>
                  </div>
                </div>
              </div>
            </section>

            <section className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <GaugeCard
                  label="Memory"
                  currentLabel={bytesToHuman(memoryGauge.current)}
                  maxLabel={bytesToHuman(memoryGauge.max)}
                  pct={memoryGauge.pct}
                />
                <GaugeCard
                  label="PIDs"
                  currentLabel={String(pidGauge.current)}
                  maxLabel={String(pidGauge.max)}
                  pct={pidGauge.pct}
                />
              </div>

              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
                <div className="border border-white/10 bg-[#10131b]/90 p-4 backdrop-blur-md">
                  <div className="mb-3 flex items-center justify-between">
                    <div>
                      <div className="text-xs uppercase tracking-[0.32em] text-slate-500">Defense Telemetry</div>
                      <div className="mt-1 font-['JetBrains_Mono'] text-lg font-semibold text-slate-100">Event stream</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <StatusPill label={sseStatus.toUpperCase()} tone={sseStatus === "connected" ? "green" : sseStatus === "disconnected" ? "red" : "slate"} />
                      <StatusPill label={`${cgroupSamples} samples`} tone="slate" />
                    </div>
                  </div>

                  <div className="h-[480px] overflow-y-auto border border-white/10 bg-[#070a11]">
                    {displayEvents.length === 0 ? (
                      <div className="flex h-full items-center justify-center px-6 text-center text-sm leading-6 text-slate-500">
                        Trigger a scenario to watch the sandbox report back: boot, policy decisions, enforcement, cleanup, and receipt.
                      </div>
                    ) : (
                      <div className="space-y-3 p-4">
                        {displayEvents.map((event, index) => (
                          <div
                            key={`${event.key}:${index}`}
                            className="telemetry-enter border-l border-white/10 pl-4"
                            style={{ animationDelay: `${Math.min(index * 70, 700)}ms` }}
                          >
                            <div className="flex flex-wrap items-center gap-3">
                              <div className="font-['JetBrains_Mono'] text-xs uppercase tracking-[0.22em] text-slate-500">
                                {event.relativeTs}
                              </div>
                              <div className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] ${toneClasses(event.tone)}`}>
                                {event.badge}
                              </div>
                            </div>
                            <div className="mt-2 font-['JetBrains_Mono'] text-sm leading-6 text-slate-200">{event.detail}</div>
                          </div>
                        ))}
                        <div ref={streamAnchorRef} />
                      </div>
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="border border-white/10 bg-[#10131b]/90 p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <div>
                        <div className="text-xs uppercase tracking-[0.32em] text-slate-500">Execution Output</div>
                        <div className="mt-1 font-['JetBrains_Mono'] text-lg font-semibold text-slate-100">Stdout / stderr</div>
                      </div>
                      <div className="font-['JetBrains_Mono'] text-xs uppercase tracking-[0.22em] text-slate-500">
                        {executionId ? executionId.slice(0, 8) : "no exec"}
                      </div>
                    </div>

                    <div className="border border-white/10 bg-[#070a11]">
                      <div className="border-b border-white/10 px-4 py-2 font-['JetBrains_Mono'] text-[11px] uppercase tracking-[0.24em] text-slate-500">
                        response
                      </div>
                      <div className="max-h-[220px] overflow-auto p-4 font-['JetBrains_Mono'] text-sm leading-6">
                        {executionResult || executionError ? (
                          <>
                            {stdout ? <pre className="whitespace-pre-wrap text-slate-100">{stdout}</pre> : null}
                            {stderr ? <pre className="mt-3 whitespace-pre-wrap text-red-300">{stderr}</pre> : null}
                            {executionResult?.output_truncated ? (
                              <div className="mt-3 border border-amber-400/20 bg-amber-500/10 px-3 py-2 text-amber-200">
                                Output was truncated by the sandbox.
                              </div>
                            ) : null}
                          </>
                        ) : (
                          <div className="text-slate-500">No execution yet.</div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className={`border bg-[#10131b]/90 p-4 ${receipt ? "receipt-pulse border-amber-400/20" : "border-white/10"}`}>
                    <div className="mb-3 flex items-center justify-between">
                      <div>
                        <div className="text-xs uppercase tracking-[0.32em] text-slate-500">Signed Receipt</div>
                        <div className="mt-1 font-['JetBrains_Mono'] text-lg font-semibold text-slate-100">
                          {receipt ? "Signed receipt emitted" : "Awaiting receipt"}
                        </div>
                      </div>
                      <StatusPill
                        label={receipt ? receiptLabel(receipt) : "PENDING"}
                        tone={receipt ? receiptTone(receipt) : "slate"}
                      />
                    </div>

                    <div className="grid gap-3 sm:grid-cols-2">
                      {receiptSummary.map((item) => (
                        <div key={item.label} className="border border-white/10 bg-black/20 px-3 py-3">
                          <div className="text-[10px] uppercase tracking-[0.24em] text-slate-500">{item.label}</div>
                          <div className="mt-2 font-['JetBrains_Mono'] text-sm text-slate-100">{item.value}</div>
                        </div>
                      ))}
                    </div>

                    <div className="mt-4 grid gap-4 lg:grid-cols-2">
                      <MiniBlock
                        title="Predicate"
                        body={
                          receiptPredicate(receipt)
                            ? `version: ${receiptPredicate(receipt)?.version || "unknown"}\nbackend: ${receiptPredicate(receipt)?.backend || "unknown"}\nworkspace: ${receiptPredicate(receipt)?.workspace_id || "none"}\nexecution_status: ${receiptPredicate(receipt)?.execution_status || "unknown"}\nresult_class: ${receiptPredicate(receipt)?.result_class || "unknown"}`
                            : "No receipt yet."
                        }
                      />
                      <MiniBlock
                        title="Trust"
                        body={
                          receiptPredicate(receipt)
                            ? `signing_mode: ${receiptPredicate(receipt)?.trust?.signing_mode || "unknown"}\nkey_source: ${receiptPredicate(receipt)?.trust?.key_source || "unknown"}\nattestation: ${receiptPredicate(receipt)?.trust?.attestation || "unknown"}\nlimitations: ${(receiptPredicate(receipt)?.limitations || []).join(", ") || "none"}`
                            : "No signed receipt yet."
                        }
                      />
                    </div>

                    <div className="mt-4 border border-white/10 bg-[#070a11]">
                      <div className="border-b border-white/10 px-4 py-2 font-['JetBrains_Mono'] text-[11px] uppercase tracking-[0.24em] text-slate-500">
                        raw receipt
                      </div>
                      <pre className="max-h-[220px] overflow-auto whitespace-pre-wrap p-4 font-['JetBrains_Mono'] text-xs leading-6 text-slate-300">
                        {receipt ? prettyJson(receipt) : "Waiting for containment.receipt"}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>

              <footer className="flex flex-col gap-2 border border-white/10 bg-[#10131b]/70 px-5 py-4 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
                <div>Built by Jess - github.com/cellardoor/aegis - San Francisco State University CS '25</div>
                <div className="font-['JetBrains_Mono'] text-xs uppercase tracking-[0.22em] text-slate-500">
                  {statsError ? `stats error: ${statsError}` : `exec_id ${executionId || "none"}`}
                </div>
              </footer>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}

function GaugeCard({ label, currentLabel, maxLabel, pct }) {
  const safePct = clamp(pct || 0, 0, 100);
  return (
    <div className="border border-white/10 bg-[#10131b]/90 p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-xs uppercase tracking-[0.32em] text-slate-500">{label}</div>
        <div className="font-['JetBrains_Mono'] text-xs uppercase tracking-[0.24em] text-slate-500">{safePct.toFixed(0)}%</div>
      </div>
      <div className="h-4 overflow-hidden rounded-full border border-white/10 bg-[#070a11]">
        <div
          className={`h-full bg-gradient-to-r ${gaugeTone(safePct)} transition-all duration-1000 ease-out`}
          style={{ width: `${safePct}%` }}
        />
      </div>
      <div className="mt-3 flex items-end justify-between font-['JetBrains_Mono']">
        <div className="text-2xl font-bold text-white">{currentLabel}</div>
        <div className="text-sm text-slate-400">/ {maxLabel}</div>
      </div>
    </div>
  );
}

function StatusPill({ label, tone }) {
  return <div className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] ${toneClasses(tone)}`}>{label}</div>;
}

function MiniBlock({ title, body }) {
  return (
    <div className="border border-white/10 bg-black/20">
      <div className="border-b border-white/10 px-3 py-2 text-[10px] uppercase tracking-[0.24em] text-slate-500">{title}</div>
      <pre className="overflow-auto whitespace-pre-wrap px-3 py-3 font-['JetBrains_Mono'] text-xs leading-6 text-slate-300">{body}</pre>
    </div>
  );
}

if (typeof window !== "undefined") {
  window.AegisProvingGround = AegisProvingGround;
}

export default AegisProvingGround;

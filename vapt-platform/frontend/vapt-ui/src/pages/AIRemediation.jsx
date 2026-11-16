import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../ops.css";
import "../airem.css";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const OPEN = new Set(["open", "in_progress", "reopened", "new", "triaged"]);
const ANALYSES = [
  { key: "remediation", label: "Fix steps", always: true },
  { key: "explain", label: "Explain", always: false },
  { key: "risk-score", label: "Risk score", always: false },
  { key: "false-positive", label: "False-positive check", always: false },
  { key: "threat-intel", label: "Threat context", always: false },
];

const sevOf = (f) => (SEV_RANK[(f.severity || "info").toLowerCase()] != null ? (f.severity || "info").toLowerCase() : "info");
const targetOf = (f) => {
  const m = f.finding_metadata || {};
  return m.host || m.url || m.ip_address || m.hostname || f.target || "";
};
const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`);
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "—");
const errText = (err, fallback) => (err?.response?.data?.detail ? String(err.response.data.detail) : fallback);

function AnalysisResult({ type, result }) {
  const d = result.data || {};
  const tag = result.provider === "local-fallback" ? "Rule-based" : `${result.provider} · ${result.model}${result.cached ? " · cached" : ""}`;
  return (
    <div className="ai-result">
      <p className="ai-result__tag">{tag}</p>
      {type === "remediation" ? (
        <>
          <ol className="ai-steps">{(d.remediation_steps || []).map((s) => <li key={s}>{s}</li>)}</ol>
          {d.configuration_fix ? <p><strong>Configuration:</strong> {d.configuration_fix}</p> : null}
          {d.patches?.length ? <ul>{d.patches.map((p) => <li key={p}>{p}</li>)}</ul> : null}
        </>
      ) : type === "explain" ? (
        <>
          <p>{d.summary}</p>
          <p><strong>Impact:</strong> {d.impact}</p>
          <p><strong>How it's exploited:</strong> {d.exploitation}</p>
          <p className="so-sub">{d.technical_details}</p>
        </>
      ) : type === "risk-score" ? (
        <p><strong>{d.risk_score}/100 · {d.priority}.</strong> {d.reason}</p>
      ) : type === "false-positive" ? (
        <p><strong>{d.false_positive_probability}% likely false positive</strong> ({d.confidence} confidence). {d.reason}</p>
      ) : (
        <>
          <p><strong>{d.actively_exploited ? "Actively exploited" : "No active exploitation known"}</strong> · threat level {d.threat_level}</p>
          {d.known_attacks?.length ? <ul>{d.known_attacks.map((a) => <li key={a}>{a}</li>)}</ul> : null}
        </>
      )}
    </div>
  );
}

export function Workspace({ findingId, aiReady }) {
  const [ctx, setCtx] = useState(null);
  const [error, setError] = useState("");
  const [results, setResults] = useState({});
  const [busy, setBusy] = useState("");

  useEffect(() => {
    let live = true;
    api.get(`/ai/finding-context/${findingId}`)
      .then((r) => { if (live) { setCtx(r.data); setError(""); setResults({}); } })
      .catch((err) => { if (live) setError(errText(err, "Couldn't load this finding.")); });
    return () => { live = false; };
  }, [findingId]);

  const run = async (type) => {
    setBusy(type);
    try {
      const r = await api.post(`/ai/finding/${findingId}/${type}`);
      setResults((prev) => ({ ...prev, [type]: { ok: true, ...r.data } }));
    } catch (err) {
      setResults((prev) => ({ ...prev, [type]: { ok: false, error: errText(err, "The analysis failed.") } }));
    } finally {
      setBusy("");
    }
  };

  if (error) return <p className="so-error">{error}</p>;
  if (!ctx || ctx.finding.id !== findingId) return <p className="cc-empty">Loading finding…</p>;
  const f = ctx.finding;
  const kevHit = ctx.cves.find((c) => c.kev);
  const maxEpss = ctx.cves.reduce((m, c) => (c.epss != null && c.epss > (m ?? -1) ? c.epss : m), null);
  const same = ctx.same_issue;

  return (
    <div className="ai-ws">
      <header className="ai-ws__head">
        <span className={`mc-sev mc-sev--${sevOf(f) === "info" ? "low" : sevOf(f)}`}>{f.severity}</span>
        <h2>{f.title}</h2>
        <p className="so-sub cc-mono">{f.target}{f.port ? `:${f.port}` : ""} · {f.source} · found {fmtDate(f.detected_at)}{f.assigned_to ? ` · owner ${f.assigned_to}` : ""}</p>
      </header>

      <div className="op-facts">
        <div className={`op-fact${kevHit ? " op-fact--bad" : ""}`}>
          <span>CISA KEV</span>
          <strong>{kevHit ? "Exploited in the wild" : ctx.cves.length ? "Not listed" : "No CVE"}</strong>
          <small>{kevHit ? `Fix by ${kevHit.kev.due_date}${kevHit.kev.ransomware ? " · ransomware" : ""}` : ctx.cves.length ? ctx.cves.map((c) => c.cve).join(", ") : "Configuration issue, not a CVE"}</small>
        </div>
        <div className={`op-fact${maxEpss != null && maxEpss >= 0.1 ? " op-fact--bad" : ""}`}>
          <span>EPSS · 30 days</span>
          <strong>{pct(maxEpss)}</strong>
          <small>{maxEpss == null ? "No score for this finding" : "chance of exploitation"}</small>
        </div>
        <div className="op-fact">
          <span>Target</span>
          <strong>{ctx.asset ? `${ctx.asset.exposure || "internal"} · ${ctx.asset.criticality || "?"}` : "Not in inventory"}</strong>
          <small>{ctx.asset ? (ctx.asset.owner ? `Owner ${ctx.asset.owner}` : "No owner") : "Exposure unknown"}</small>
        </div>
        <div className="op-fact">
          <span>Same issue</span>
          <strong>{same.open_target_count} target{same.open_target_count === 1 ? "" : "s"}</strong>
          <small>{same.total} finding{same.total === 1 ? "" : "s"} with this title</small>
        </div>
        <div className={`op-fact${same.triaged && same.false_positive / same.triaged >= 0.5 ? " op-fact--bad" : ""}`}>
          <span>Triage history</span>
          <strong>{same.triaged ? `${same.false_positive}/${same.triaged} false positive` : "Not triaged yet"}</strong>
          <small>{same.resolved} fixed before</small>
        </div>
      </div>

      {kevHit?.kev?.action ? <p className="op-banner"><strong>CISA required action:</strong> {kevHit.kev.action}</p> : null}

      <section className="ai-block">
        <h3>Scanner guidance</h3>
        <p>{f.remediation || "The scanner gave no remediation guidance for this finding."}</p>
        {f.possible_cves?.length ? <p className="so-sub">Possible CVEs (port-based, unconfirmed): {f.possible_cves.join(", ")}</p> : null}
      </section>

      {f.evidence ? (
        <section className="ai-block">
          <h3>Evidence</h3>
          <pre className="fx-proof">{f.evidence}</pre>
        </section>
      ) : null}

      <section className="ai-block">
        <h3>{aiReady ? "AI analysis" : "Analysis"}</h3>
        <div className="op-row">
          {ANALYSES.filter((a) => a.always || aiReady).map((a) => (
            <button key={a.key} type="button" className="cc-btn" disabled={busy === a.key} onClick={() => run(a.key)}>
              {busy === a.key ? "Working…" : aiReady ? a.label : `${a.label} (rule-based)`}
            </button>
          ))}
        </div>
        {busy && aiReady ? <p className="so-sub" role="status">The local model is thinking. On a CPU-only server this takes 30–90 seconds.</p> : null}
        {ANALYSES.map((a) => results[a.key] ? (
          <div key={a.key} className="ai-out">
            <h4>{a.label}</h4>
            {results[a.key].ok ? <AnalysisResult type={a.key} result={results[a.key]} /> : <p className="so-error">{results[a.key].error}</p>}
          </div>
        ) : null)}
      </section>

      {same.open_targets.length > 1 ? (
        <section className="ai-block">
          <h3>Also open on</h3>
          <ul className="mc-targets">{same.open_targets.map((t) => <li key={t}><Link className="cc-mono" to={`/findings?target=${encodeURIComponent(t)}`}>{t}</Link></li>)}</ul>
        </section>
      ) : null}

      <div className="op-row">
        <Link className="cc-btn" to={`/findings?search=${encodeURIComponent(f.title)}`}>Open in Findings to assign or close</Link>
      </div>
    </div>
  );
}

export default function AIRemediation({ findings = [] }) {
  const [ai, setAi] = useState(null);
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("urgent");
  const [picked, setPicked] = useState([]);
  const [plan, setPlan] = useState(null);
  const [planBusy, setPlanBusy] = useState(false);

  useEffect(() => {
    api.get("/ai/status").then((r) => setAi(r.data)).catch(() => setAi(null));
  }, []);

  const queue = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings
      .filter((f) => OPEN.has(String(f.status || "open").toLowerCase()))
      .filter((f) => {
        const s = sevOf(f);
        if (severity === "urgent" && !["critical", "high"].includes(s)) return false;
        if (severity === "medium" && s !== "medium") return false;
        if (severity === "low" && !["low", "info"].includes(s)) return false;
        return !q || `${f.title} ${targetOf(f)} ${f.cve_id || ""}`.toLowerCase().includes(q);
      })
      .sort((a, b) => SEV_RANK[sevOf(a)] - SEV_RANK[sevOf(b)] || (b.cvss_score || 0) - (a.cvss_score || 0))
      .slice(0, 150);
  }, [findings, query, severity]);

  const activeId = selected && queue.some((f) => f.id === selected) ? selected : queue[0]?.id;
  const aiReady = Boolean(ai?.available);

  const buildPlan = async () => {
    setPlanBusy(true);
    try {
      const r = await api.post("/ai/assist", { mode: "remediation-plan", prompt: "Group these findings into an ordered remediation plan.", finding_ids: picked });
      setPlan(r.data);
    } catch (err) {
      setPlan({ error: errText(err, "Couldn't build the plan.") });
    } finally {
      setPlanBusy(false);
    }
  };

  return (
    <div className="cc ai-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>AI Remediation</h1>
        </div>
        <div className="cc-top__tools">
          {ai ? <span className={`op-status op-status--${aiReady ? "ok" : "warn"}`}>{aiReady ? `Model: ${ai.model}` : "No AI model configured"}</span> : null}
        </div>
      </header>

      {ai && !aiReady ? (
        <p className="op-banner"><strong>Running without an AI model.</strong> {ai.setup_hint} Risk scores, false-positive odds and threat context need a model, so they're hidden rather than guessed.</p>
      ) : null}

      <div className="ai-layout">
        <section className="cc-panel ai-queue" aria-label="Remediation queue">
          <header className="cc-panel__head"><h2>Queue ({queue.length})</h2></header>
          <div className="cc-range ai-sev" role="group" aria-label="Severity">
            {[["urgent", "Critical + high"], ["medium", "Medium"], ["low", "Low"], ["all", "All"]].map(([k, l]) => (
              <button key={k} type="button" aria-pressed={severity === k} onClick={() => setSeverity(k)}>{l}</button>
            ))}
          </div>
          <input className="so-input ai-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search title, target or CVE" aria-label="Search findings" />
          <ul className="ai-list">
            {queue.map((f) => (
              <li key={f.id} className={f.id === activeId ? "is-active" : ""}>
                <input type="checkbox" aria-label={`Add ${f.title} to plan`} checked={picked.includes(f.id)}
                  onChange={(e) => setPicked((p) => (e.target.checked ? [...p, f.id].slice(-12) : p.filter((x) => x !== f.id)))} />
                <button type="button" onClick={() => setSelected(f.id)}>
                  <span className={`cc-dot cc-dot--${sevOf(f)}`} aria-hidden="true" />
                  <span className="ai-list__main">
                    <span className="ai-list__title">{f.title}</span>
                    <span className="so-sub cc-mono">{targetOf(f) || "—"}{f.cve_id ? ` · ${f.cve_id}` : ""}</span>
                  </span>
                </button>
              </li>
            ))}
            {!queue.length ? <li className="cc-empty">No open findings match.</li> : null}
          </ul>
          <div className="ai-plan-bar">
            <span className="so-sub">{picked.length} selected (max 12)</span>
            <button type="button" className="cc-btn cc-btn--primary" disabled={!picked.length || planBusy} onClick={buildPlan}>{planBusy ? "Building…" : "Build remediation plan"}</button>
          </div>
        </section>

        <section className="cc-panel ai-main" aria-label="Fix workspace">
          {activeId ? <Workspace key={activeId} findingId={activeId} aiReady={aiReady} /> : <p className="cc-empty">Pick a finding from the queue.</p>}
        </section>
      </div>

      {plan ? (
        <section className="cc-panel sh-section" aria-label="Remediation plan">
          <header className="cc-panel__head">
            <h2>Remediation plan</h2>
            <span className="op-row">
              {plan.content ? <button type="button" className="cc-btn" onClick={() => navigator.clipboard?.writeText(plan.content).catch(() => {})}>Copy</button> : null}
              <button type="button" className="cc-btn" onClick={() => setPlan(null)}>Close</button>
            </span>
          </header>
          {plan.error ? <p className="so-error">{plan.error}</p> : (
            <>
              <p className="ai-result__tag">{plan.provider === "local-fallback" ? "Rule-based: compiled from scanner guidance" : `${plan.provider} · ${plan.model}`}</p>
              <pre className="ai-plan">{plan.content}</pre>
            </>
          )}
        </section>
      ) : null}
    </div>
  );
}

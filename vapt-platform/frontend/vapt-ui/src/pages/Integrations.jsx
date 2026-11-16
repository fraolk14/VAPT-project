import { useCallback, useEffect, useState } from "react";

import api from "../api/client";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../ops.css";

const ENGINE_ORDER = ["openvas", "zap", "mobsf", "misp"];
const SEVS = ["critical", "high", "medium", "low"];
const TOOL_LABEL = { "": "All engines", openvas: "Network", zap: "Web", mobsf: "Mobile" };
const REFRESH_MS = 60_000;

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "—");
const errText = (err, fallback) => (err?.response?.data?.detail ? String(err.response.data.detail) : fallback);

function Kpi({ label, value, total, tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value == null ? "—" : total != null ? `${shown}/${total}` : shown}</strong>
      {hint ? <small className="an-kpi-hint">{hint}</small> : null}
    </div>
  );
}

function Status({ ok, warn, label }) {
  return <span className={`op-status op-status--${ok ? "ok" : warn ? "warn" : "bad"}`}>{label}</span>;
}

function Secret({ label, value, onDone }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <div className="op-secret" role="status">
      <p><strong>{label}</strong> It won't be shown again — copy it now.</p>
      <code>{value}</code>
      <div className="op-row">
        <button type="button" className="cc-btn" onClick={() => navigator.clipboard?.writeText(value).then(() => setCopied(true)).catch(() => {})}>{copied ? "Copied" : "Copy"}</button>
        <button type="button" className="cc-btn" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

export default function Integrations({ canAdmin = false, canOperate = false }) {
  const [health, setHealth] = useState(null);
  const [feeds, setFeeds] = useState(null);
  const [rules, setRules] = useState([]);
  const [deliveries, setDeliveries] = useState([]);
  const [monRules, setMonRules] = useState([]);
  const [monEvents, setMonEvents] = useState([]);
  const [hooks, setHooks] = useState([]);
  const [pipeEvents, setPipeEvents] = useState([]);
  const [notice, setNotice] = useState(null);
  const [checking, setChecking] = useState(false);
  const [secret, setSecret] = useState({ label: "", value: "" });
  const [alertForm, setAlertForm] = useState({ name: "", channel: "email", destination: "", min_severity: "high", scan_tool: "" });
  const [ruleForm, setRuleForm] = useState({ name: "", event_source: "siem", event_type: "", target_match: "", action: "queue_scan", tool: "openvas" });
  const [hookForm, setHookForm] = useState({ name: "", provider: "github", project_name: "", target_url: "" });

  const say = (ok, text) => setNotice({ ok, text });
  const take = (path, set) => api.get(path).then((r) => set(r.data)).catch(() => {});

  const load = useCallback(() => {
    setChecking(true);
    const jobs = [
      take("/integrations/health", setHealth),
      take("/integrations/feeds", setFeeds),
    ];
    if (canOperate) {
      jobs.push(take("/alerts/rules", setRules), take("/alerts/events", setDeliveries),
        take("/operations/monitoring/rules", setMonRules), take("/operations/monitoring/events", setMonEvents),
        take("/platform/devsecops/hooks", setHooks), take("/platform/devsecops/events", setPipeEvents));
    }
    Promise.allSettled(jobs).finally(() => setChecking(false));
  }, [canOperate]);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const timer = window.setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [load]);

  const act = async (fn, okText, failText) => {
    try {
      const res = await fn();
      say(true, typeof okText === "function" ? okText(res) : okText);
      load();
      return res;
    } catch (err) {
      say(false, errText(err, failText));
      return null;
    }
  };

  const engines = health ? ENGINE_ORDER.filter((k) => health[k]).map((k) => ({ key: k, ...health[k] })) : [];
  const keyFree = (feeds || []).filter((f) => !["needs_key", "configured"].includes(f.status));
  const keyed = (feeds || []).filter((f) => ["needs_key", "configured"].includes(f.status));
  const failedDeliveries = deliveries.filter((d) => d.status === "failed").length;
  const apiBase = `${window.location.origin}/api`;

  return (
    <div className="cc op-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Integrations</h1>
        </div>
        <div className="cc-top__tools">
          <button type="button" className="cc-btn" onClick={load} disabled={checking}>{checking ? "Checking…" : "Re-check all"}</button>
        </div>
      </header>

      {notice ? <p className={notice.ok ? "mc-ok op-notice" : "so-error op-notice"} role={notice.ok ? "status" : "alert"}>{notice.text}</p> : null}

      <div className="cc-kpis">
        <Kpi label="Engines healthy" value={engines.filter((e) => e.healthy).length} total={engines.length || null} tone={engines.some((e) => !e.healthy) ? "hot" : "live"} />
        <Kpi label="Threat feeds online" value={keyFree.filter((f) => f.status === "connected").length} total={keyFree.length || null} hint={keyed.length ? `${keyed.filter((f) => f.status === "configured").length} of ${keyed.length} keyed feeds set up` : undefined} />
        {canOperate ? <Kpi label="Alert routes on" value={rules.filter((r) => r.enabled).length} total={rules.length} /> : null}
        {canOperate ? <Kpi label="Failed deliveries" value={failedDeliveries} tone={failedDeliveries ? "hot" : ""} hint="last 50 alerts" /> : null}
        {canOperate ? <Kpi label="Event rules on" value={monRules.filter((r) => r.enabled).length} total={monRules.length} /> : null}
        {canOperate ? <Kpi label="CI/CD hooks on" value={hooks.filter((h) => h.enabled).length} total={hooks.length} /> : null}
      </div>

      <section className="cc-panel" aria-label="Scan engines">
        <header className="cc-panel__head"><h2>Scan engines</h2></header>
        <div className="op-engines">
          {engines.map((e) => (
            <article key={e.key} className={`op-engine${e.healthy ? "" : " is-down"}`}>
              <div className="op-engine__head">
                <span className={`cc-dot cc-dot--${e.healthy ? "healthy" : "critical"}`} aria-hidden="true" />
                <h3>{e.name}</h3>
                <Status ok={e.healthy} label={e.healthy ? "Healthy" : "Unavailable"} />
              </div>
              <p className="op-engine__role">{e.role}</p>
              <p className="cc-mono op-engine__detail">{e.detail || (e.healthy ? "Reachable" : "No response")}</p>
              <p className="so-sub cc-mono">{e.url} · {e.latency_ms} ms</p>
            </article>
          ))}
          {!engines.length ? <p className="cc-empty">{health ? "No engines reported." : "Checking engines…"}</p> : null}
        </div>
      </section>

      <div className="an-grid op-grid">
        <section className="cc-panel an-w" aria-label="Threat intelligence feeds">
          <header className="cc-panel__head"><h2>Threat-intel feeds</h2></header>
          {feeds ? (
            <ul className="cc-list">
              {feeds.map((f) => (
                <li key={f.name} className="an-overdue">
                  <span className="an-overdue__main">
                    <span>{f.name}</span>
                    <span className="so-sub">{f.detail}</span>
                  </span>
                  <span className="op-feed__right">
                    <Status ok={f.status === "connected" || f.status === "configured"} warn={f.status === "rate_limited" || f.status === "needs_key"}
                      label={{ connected: "Online", configured: "Key set", needs_key: "Needs key", rate_limited: "Rate-limited", unavailable: "Offline" }[f.status] || f.status} />
                    {f.latency_ms != null ? <span className="so-sub cc-mono">{f.latency_ms} ms</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">Probing feeds…</p>}
          <p className="an-note">Key-free feeds are probed live (cached 5 min). Add keys as environment variables on the API service.</p>
        </section>

        {canOperate ? (
          <section className="cc-panel an-w" aria-label="Alert routes">
            <header className="cc-panel__head"><h2>Alert routes</h2></header>
            <ul className="cc-list">
              {rules.map((r) => (
                <li key={r.id} className="an-overdue">
                  <span className={`cc-dot cc-dot--${r.enabled ? "healthy" : "down"}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <span>{r.name}</span>
                    <span className="so-sub cc-mono">{r.channel} → {r.destination}</span>
                    <span className="so-sub">{r.min_severity}+ · {TOOL_LABEL[r.scan_tool || ""] || r.scan_tool}</span>
                  </span>
                  <span className="op-row">
                    <button type="button" className="cc-btn" disabled={!r.enabled}
                      onClick={() => act(() => api.post(`/alerts/rules/${r.id}/test`), (res) => `Test sent: ${res.data.event.status}${res.data.event.response_message ? ` — ${res.data.event.response_message}` : ""}`, "Couldn't send the test.")}>Send test</button>
                    {canAdmin ? <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/alerts/rules/${r.id}/toggle`), `${r.name} ${r.enabled ? "paused" : "enabled"}.`, "Couldn't update the rule.")}>{r.enabled ? "Pause" : "Enable"}</button> : null}
                  </span>
                </li>
              ))}
              {!rules.length ? <li className="cc-empty">No alert routes. New findings at or above a severity can be emailed or posted to a webhook.</li> : null}
            </ul>
            {canAdmin ? (
              <details className="op-form">
                <summary>Add an alert route</summary>
                <form onSubmit={(e) => { e.preventDefault(); act(() => api.post("/alerts/rules", { ...alertForm, scan_tool: alertForm.scan_tool || null, metadata_json: {} }), "Alert route added. Send a test to confirm delivery.", "Couldn't add the route.").then((r) => r && setAlertForm({ ...alertForm, name: "", destination: "" })); }}>
                  <label><span>Name</span><input className="so-input" required value={alertForm.name} onChange={(e) => setAlertForm({ ...alertForm, name: e.target.value })} /></label>
                  <label><span>Channel</span>
                    <select className="so-input" value={alertForm.channel} onChange={(e) => setAlertForm({ ...alertForm, channel: e.target.value })}><option value="email">Email</option><option value="webhook">Webhook</option></select>
                  </label>
                  <label className="op-wide"><span>{alertForm.channel === "email" ? "Email address" : "Webhook URL (https://…)"}</span><input className="so-input" required value={alertForm.destination} onChange={(e) => setAlertForm({ ...alertForm, destination: e.target.value })} /></label>
                  <label><span>Minimum severity</span>
                    <select className="so-input" value={alertForm.min_severity} onChange={(e) => setAlertForm({ ...alertForm, min_severity: e.target.value })}>{SEVS.map((s) => <option key={s} value={s}>{s}</option>)}</select>
                  </label>
                  <label><span>Engine</span>
                    <select className="so-input" value={alertForm.scan_tool} onChange={(e) => setAlertForm({ ...alertForm, scan_tool: e.target.value })}>{Object.entries(TOOL_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
                  </label>
                  <button type="submit" className="cc-btn cc-btn--primary">Add route</button>
                </form>
              </details>
            ) : null}
            <p className="an-note">"Send test" delivers a labelled test message only. It doesn't create a finding.</p>
          </section>
        ) : null}

        {canOperate ? (
          <section className="cc-panel an-w" aria-label="Alert delivery log">
            <header className="cc-panel__head"><h2>Delivery log</h2></header>
            <ul className="cc-list op-scroll">
              {deliveries.slice(0, 20).map((d) => (
                <li key={d.id} className="an-overdue">
                  <span className={`cc-dot cc-dot--${d.status === "sent" ? "healthy" : d.status === "failed" ? "critical" : "medium"}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <span>{d.payload?.test ? "Test · " : ""}{d.payload?.finding_title || d.rule_name}</span>
                    <span className="so-sub cc-mono">{d.rule_name} → {d.destination}</span>
                    <span className="so-sub">{fmtTime(d.created_at)} · {d.response_message}</span>
                  </span>
                  {d.status !== "sent" ? <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/alerts/events/${d.id}/retry`), (res) => `Retry ${res.data.status}.`, "Retry failed.")}>Retry</button> : null}
                </li>
              ))}
              {!deliveries.length ? <li className="cc-empty">No alerts sent yet.</li> : null}
            </ul>
          </section>
        ) : null}

        {canOperate ? (
          <section className="cc-panel an-w" aria-label="Event-driven scanning">
            <header className="cc-panel__head"><h2>Event-driven scanning</h2></header>
            <ul className="cc-list">
              {monRules.map((r) => (
                <li key={r.id} className="an-overdue">
                  <span className={`cc-dot cc-dot--${r.enabled ? "healthy" : "down"}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <span>{r.name}</span>
                    <span className="so-sub cc-mono">{r.event_source} / {r.event_type}{r.target_match ? ` · target ~ ${r.target_match}` : ""}</span>
                    <span className="so-sub">Runs a {TOOL_LABEL[r.tool] || r.tool} scan of the event's target</span>
                  </span>
                  {canAdmin ? <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/operations/monitoring/rules/${r.id}/toggle`), `${r.name} ${r.enabled ? "paused" : "enabled"}.`, "Couldn't update the rule.")}>{r.enabled ? "Pause" : "Enable"}</button> : null}
                </li>
              ))}
              {!monRules.length ? <li className="cc-empty">No event rules.</li> : null}
            </ul>
            {canAdmin ? (
              <details className="op-form">
                <summary>Add an event rule</summary>
                <form onSubmit={(e) => { e.preventDefault(); act(() => api.post("/operations/monitoring/rules", { ...ruleForm, metadata_json: {} }), "Event rule added.", "Couldn't add the rule.").then((r) => r && setRuleForm({ ...ruleForm, name: "", event_type: "", target_match: "" })); }}>
                  <label><span>Name</span><input className="so-input" required value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} /></label>
                  <label><span>Event source</span>
                    <select className="so-input" value={ruleForm.event_source} onChange={(e) => setRuleForm({ ...ruleForm, event_source: e.target.value })}><option value="siem">SIEM</option><option value="edr">EDR</option><option value="firewall">Firewall</option></select>
                  </label>
                  <label><span>Event type</span><input className="so-input" required placeholder="e.g. suspicious_login" value={ruleForm.event_type} onChange={(e) => setRuleForm({ ...ruleForm, event_type: e.target.value })} /></label>
                  <label><span>Only targets containing</span><input className="so-input" placeholder="optional, e.g. 10.20." value={ruleForm.target_match} onChange={(e) => setRuleForm({ ...ruleForm, target_match: e.target.value })} /></label>
                  <label><span>Scan with</span>
                    <select className="so-input" value={ruleForm.tool} onChange={(e) => setRuleForm({ ...ruleForm, tool: e.target.value })}><option value="openvas">Network engine</option><option value="zap">Web engine</option></select>
                  </label>
                  <button type="submit" className="cc-btn cc-btn--primary">Add rule</button>
                </form>
              </details>
            ) : null}
            <p className="an-note">Your SIEM or EDR sends events to <code className="cc-mono">POST {apiBase}/operations/monitoring/events</code> using a signed-in analyst's bearer token (long-lived API keys aren't supported yet). Matching events queue a real scan of the event's target, so only route targets you're authorized to test.</p>
            {monEvents.length ? (
              <>
                <h3 className="an-subhead">Recent events</h3>
                <ul className="cc-list op-scroll">
                  {monEvents.slice(0, 8).map((ev) => (
                    <li key={ev.id}>
                      <span className="an-overdue__main">
                        <span>{ev.event_type} · <span className="cc-mono">{ev.target}</span></span>
                        <span className="so-sub">{ev.source} · {ev.status} · {fmtTime(ev.created_at)}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </section>
        ) : null}

        {canOperate ? (
          <section className="cc-panel an-w" aria-label="CI/CD hooks">
            <header className="cc-panel__head"><h2>CI/CD hooks</h2></header>
            <Secret label={secret.label === "hook" ? "Hook token." : ""} value={secret.label === "hook" ? secret.value : ""} onDone={() => setSecret({ label: "", value: "" })} />
            <ul className="cc-list">
              {hooks.map((h) => (
                <li key={h.id} className="an-overdue">
                  <span className={`cc-dot cc-dot--${h.enabled ? "healthy" : "down"}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <span>{h.project_name} <span className="so-sub">· {h.provider}</span></span>
                    <span className="so-sub cc-mono op-break">POST {apiBase}/platform/devsecops/ingest/{h.id}</span>
                    <span className="so-sub">Header X-Hook-Token: •••{h.secret_hint}</span>
                  </span>
                  {canAdmin ? <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/platform/devsecops/hooks/${h.id}/toggle`), `${h.project_name} hook ${h.enabled ? "disabled" : "enabled"}.`, "Couldn't update the hook.")}>{h.enabled ? "Disable" : "Enable"}</button> : null}
                </li>
              ))}
              {!hooks.length ? <li className="cc-empty">No pipeline hooks. A hook lets GitHub, GitLab or Jenkins post build events here.</li> : null}
            </ul>
            {canAdmin ? (
              <details className="op-form">
                <summary>Add a pipeline hook</summary>
                <form onSubmit={(e) => { e.preventDefault(); act(() => api.post("/platform/devsecops/hooks", { ...hookForm, metadata_json: {} }), "Hook created.", "Couldn't create the hook.").then((r) => { if (r) { setSecret({ label: "hook", value: r.data.secret }); setHookForm({ ...hookForm, name: "", project_name: "", target_url: "" }); } }); }}>
                  <label><span>Name</span><input className="so-input" required value={hookForm.name} onChange={(e) => setHookForm({ ...hookForm, name: e.target.value })} /></label>
                  <label><span>Provider</span>
                    <select className="so-input" value={hookForm.provider} onChange={(e) => setHookForm({ ...hookForm, provider: e.target.value })}><option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="jenkins">Jenkins</option></select>
                  </label>
                  <label><span>Project</span><input className="so-input" required value={hookForm.project_name} onChange={(e) => setHookForm({ ...hookForm, project_name: e.target.value })} /></label>
                  <label><span>App URL</span><input className="so-input" placeholder="https://staging.example.com" value={hookForm.target_url} onChange={(e) => setHookForm({ ...hookForm, target_url: e.target.value })} /></label>
                  <button type="submit" className="cc-btn cc-btn--primary">Create hook</button>
                </form>
              </details>
            ) : null}
            {pipeEvents.length ? (
              <>
                <h3 className="an-subhead">Recent pipeline events</h3>
                <ul className="cc-list op-scroll">
                  {pipeEvents.slice(0, 8).map((ev) => (
                    <li key={ev.id}><span className="an-overdue__main"><span>{ev.event_type}</span><span className="so-sub">{ev.summary || ev.provider} · {ev.status} · {fmtTime(ev.created_at)}</span></span></li>
                  ))}
                </ul>
              </>
            ) : null}
          </section>
        ) : null}

      </div>
    </div>
  );
}

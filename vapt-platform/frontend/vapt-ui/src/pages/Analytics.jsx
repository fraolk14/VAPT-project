import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import RiskTerrain from "../components/cc/RiskTerrain";
import { AgeChart, BacklogChart, ScanActivityChart, SlaChart } from "../components/cc/anCharts";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";

const PREFS_KEY = "vapt_analytics_v1";
const RANGES = [
  { days: 30, label: "30 d" },
  { days: 90, label: "90 d" },
  { days: 180, label: "180 d" },
  { days: 365, label: "1 y" },
];
const RISK = ["critical", "high", "medium", "low"];
const REFRESH_MS = 60_000;

const WIDGETS = {
  terrain: { title: "Risk terrain · new findings over time", wide: true },
  backlog: { title: "Backlog trend", wide: true },
  sla: { title: "SLA status" },
  overdue: { title: "Most overdue" },
  age: { title: "Backlog age" },
  mttr: { title: "Time to fix (MTTR)" },
  signal: { title: "Scanner signal quality" },
  scans: { title: "Scan activity" },
  coverage: { title: "Scan coverage · last 30 days" },
  recurring: { title: "Recurring issues" },
  riskiest: { title: "Riskiest targets" },
  categories: { title: "Open issues by category" },
  owners: { title: "Workload by owner" },
};
const DEFAULT_ORDER = Object.keys(WIDGETS);

function loadPrefs() {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(PREFS_KEY) || "null");
    if (!parsed) return { order: DEFAULT_ORDER, hidden: [], days: 90 };
    const order = (parsed.order || []).filter((id) => WIDGETS[id]);
    DEFAULT_ORDER.forEach((id) => { if (!order.includes(id)) order.push(id); });
    return { order, hidden: (parsed.hidden || []).filter((id) => WIDGETS[id]), days: RANGES.some((r) => r.days === parsed.days) ? parsed.days : 90 };
  } catch {
    return { order: DEFAULT_ORDER, hidden: [], days: 90 };
  }
}

function savePrefs(prefs) {
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {
    // Storage unavailable: preferences just aren't remembered.
  }
}

const pct = (v) => (v == null ? null : Math.round(v * 100));

function Kpi({ label, value, suffix = "", tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`} title={hint}>
      <span>{label}</span>
      <strong>{value == null ? "—" : `${shown}${suffix}`}</strong>
      {hint ? <small className="an-kpi-hint">{hint}</small> : null}
    </div>
  );
}

function StackedBars({ rows, nameKey, linkFor, valueFor }) {
  const max = Math.max(1, ...rows.map((r) => RISK.reduce((sum, s) => sum + (r[s] || 0), 0)));
  return (
    <ol className="cc-bars">
      {rows.map((r) => {
        const total = RISK.reduce((sum, s) => sum + (r[s] || 0), 0);
        const name = r[nameKey];
        return (
          <li key={name}>
            {linkFor ? <Link to={linkFor(r)} className="cc-bars__name" title={name}>{name}</Link> : <span className="cc-bars__name" title={name}>{name}</span>}
            <div className="cc-bars__track" aria-hidden="true">
              {RISK.filter((s) => r[s]).map((s) => (
                <span key={s} className={`cc-fill cc-fill--${s}`} style={{ width: `${(r[s] / max) * 100}%` }} />
              ))}
            </div>
            <span className="cc-bars__value">{valueFor ? valueFor(r) : total}</span>
          </li>
        );
      })}
    </ol>
  );
}

function SevLegend() {
  return (
    <ul className="cc-legend an-legend" aria-label="Severity colors">
      {RISK.map((s) => <li key={s}><span className={`cc-swatch cc-swatch--${s}`} />{s}</li>)}
    </ul>
  );
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "Never");

export default function Analytics() {
  const rootRef = useRef(null);
  const [prefs, setPrefs] = useState(loadPrefs);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [customizing, setCustomizing] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  const updatePrefs = (next) => {
    setPrefs(next);
    savePrefs(next);
  };

  const load = useCallback(async () => {
    try {
      const res = await api.get("/dashboard/analytics", { params: { days: prefs.days } });
      setData(res.data);
      setError("");
    } catch {
      setError("Couldn't load analytics. Check that the API is running.");
    } finally {
      setLoading(false);
    }
  }, [prefs.days]);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const timer = window.setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [load]);

  useEffect(() => {
    const onChange = () => setFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else rootRef.current?.requestFullscreen?.();
  };

  const toggleWidget = (id) => {
    const hidden = prefs.hidden.includes(id) ? prefs.hidden.filter((x) => x !== id) : [...prefs.hidden, id];
    updatePrefs({ ...prefs, hidden });
  };
  const moveWidget = (id, delta) => {
    const order = [...prefs.order];
    const i = order.indexOf(id);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= order.length) return;
    [order[i], order[j]] = [order[j], order[i]];
    updatePrefs({ ...prefs, order });
  };

  const k = data?.kpis;
  const policy = data?.sla_policy_days || {};
  const empty = (text) => <p className="cc-empty">{loading ? "Loading…" : text}</p>;

  const render = {
    terrain: () => (data ? <RiskTerrain labels={data.labels} detection={data.detection} bucket={data.bucket} /> : empty("No data.")),
    backlog: () => (data ? (
      <>
        <BacklogChart labels={data.labels} backlog={data.backlog} />
        <p className="an-note">Open backlog excludes info-level and false-positive findings. {data.kpis.resolved_in_range ? "" : "Nothing has been marked resolved yet, so the backlog only grows — closing fixed findings is what bends this line."}</p>
      </>
    ) : empty("No data.")),
    sla: () => (data ? (
      <>
        <SlaChart sla={data.sla} />
        <p className="an-note">
          Default policy from detection: critical {policy.critical} d · high {policy.high} d · medium {policy.medium} d · low {policy.low} d. A due date set on a finding overrides it.
        </p>
      </>
    ) : empty("No data.")),
    overdue: () => (data?.overdue?.length ? (
      <ul className="cc-list">
        {data.overdue.slice(0, 6).map((f) => (
          <li key={f.id} className="an-overdue">
            <span className={`cc-dot cc-dot--${f.severity}`} aria-hidden="true" />
            <span className="an-overdue__main">
              <Link to={`/findings?search=${encodeURIComponent(f.title)}`}>{f.title}</Link>
              <span className="so-sub cc-mono">{f.target}</span>
            </span>
            <span className="an-late cc-mono">{f.days_overdue} d late</span>
          </li>
        ))}
      </ul>
    ) : empty("Nothing is past its SLA.")),
    age: () => (data ? (
      <>
        <AgeChart age={data.age} />
        <p className="an-note">Median open finding is {k.median_age_days ?? "—"} days old.</p>
      </>
    ) : empty("No data.")),
    mttr: () => (data ? (
      data.kpis.resolved_in_range ? (
        <table className="so-table an-table">
          <thead><tr><th scope="col">Severity</th><th scope="col">Fixed</th><th scope="col">Mean</th><th scope="col">Median</th><th scope="col">SLA</th></tr></thead>
          <tbody>
            {RISK.map((s) => {
              const m = data.mttr[s];
              const breach = m.mean_days != null && m.mean_days > policy[s];
              return (
                <tr key={s}>
                  <th scope="row"><span className={`cc-swatch cc-swatch--${s}`} /> {s}</th>
                  <td className="cc-mono">{m.count}</td>
                  <td className={`cc-mono${breach ? " an-bad" : ""}`}>{m.mean_days != null ? `${m.mean_days} d` : "—"}</td>
                  <td className="cc-mono">{m.median_days != null ? `${m.median_days} d` : "—"}</td>
                  <td className="cc-mono cc-muted">{policy[s]} d</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div className="an-callout">
          <strong>No fixes recorded in this period.</strong>
          <p>MTTR is measured from detection to the moment a finding is marked <em>resolved</em>. Mark findings resolved in <Link to="/findings">Findings</Link> as they're fixed and this fills in automatically.</p>
        </div>
      )
    ) : empty("No data.")),
    signal: () => (data?.signal?.length ? (
      <>
        <table className="so-table an-table">
          <thead><tr><th scope="col">Engine</th><th scope="col">Findings</th><th scope="col">False positives</th></tr></thead>
          <tbody>
            {data.signal.map((r) => (
              <tr key={r.source}>
                <th scope="row">{r.label}</th>
                <td className="cc-mono">{r.total}</td>
                <td>
                  <div className="an-fp">
                    <span className="an-fp__track"><span className={`an-fp__fill${r.fp_rate >= 0.3 ? " an-fp__fill--bad" : ""}`} style={{ width: `${Math.max(r.fp_rate * 100, r.false_positive ? 2 : 0)}%` }} /></span>
                    <span className="cc-mono">{Math.round(r.fp_rate * 100)}%</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="an-note">Share of each engine's findings an analyst marked as false positive. A high rate means that engine's results need tuning before they're trusted. Engines with 0% may simply not have been triaged yet.</p>
      </>
    ) : empty("No findings yet.")),
    scans: () => (data ? (
      <>
        <ScanActivityChart labels={data.labels} series={data.scans.series} />
        {data.scans.tools.length ? (
          <table className="so-table an-table">
            <thead><tr><th scope="col">Engine</th><th scope="col">Runs</th><th scope="col">Success</th><th scope="col">Median time</th></tr></thead>
            <tbody>
              {data.scans.tools.map((t) => (
                <tr key={t.tool}>
                  <th scope="row">{t.label}</th>
                  <td className="cc-mono">{t.completed + t.failed}</td>
                  <td className={`cc-mono${t.success_rate != null && t.success_rate < 0.9 ? " an-bad" : ""}`}>{t.success_rate != null ? `${Math.round(t.success_rate * 100)}%` : "—"}</td>
                  <td className="cc-mono">{t.median_minutes != null ? `${t.median_minutes} min` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </>
    ) : empty("No data.")),
    coverage: () => (data ? (
      <>
        <div className="an-coverage">
          <div className="an-gauge" style={{ "--p": `${pct(k.coverage) ?? 0}%` }} role="img" aria-label={`${pct(k.coverage) ?? 0}% of assets scanned in the last 30 days`}>
            <strong>{pct(k.coverage) ?? "—"}%</strong>
          </div>
          <p><strong>{k.assets_covered}</strong> of <strong>{k.assets}</strong> active targets had a completed scan or fresh finding in the last 30 days.</p>
        </div>
        {data.coverage.some((r) => r.stale) ? (
          <>
            <h3 className="an-subhead">Not scanned recently</h3>
            <ul className="cc-list">
              {data.coverage.filter((r) => r.stale).slice(0, 6).map((r) => (
                <li key={r.id} className="an-stale">
                  <span className="an-overdue__main">
                    <Link to="/assets">{r.name}</Link>
                    <span className="so-sub cc-mono">{r.address}</span>
                  </span>
                  <span className="cc-mono cc-muted">{r.last_scanned ? fmtDate(r.last_scanned) : "Never"}</span>
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </>
    ) : empty("No data.")),
    recurring: () => (data?.recurring?.length ? (
      <ul className="cc-list">
        {data.recurring.slice(0, 8).map((r) => (
          <li key={r.name} className="an-overdue">
            <span className={`cc-dot cc-dot--${r.severity}`} aria-hidden="true" />
            <span className="an-overdue__main">
              <Link to={`/findings?search=${encodeURIComponent(r.name)}`}>{r.name}</Link>
              <span className="so-sub">{r.count} open finding{r.count === 1 ? "" : "s"}</span>
            </span>
            <span className="cc-mono">{r.targets} target{r.targets === 1 ? "" : "s"}</span>
          </li>
        ))}
      </ul>
    ) : empty("No open issues.")),
    riskiest: () => (data?.riskiest?.length ? (
      <>
        <StackedBars rows={data.riskiest} nameKey="target" linkFor={(r) => `/findings?target=${encodeURIComponent(r.target)}`} valueFor={(r) => Math.round(r.score)} />
        <SevLegend />
        <p className="an-note">Bars show open findings by severity; the number is risk points (critical 10 · high 5 · medium 2 · low 0.5), which sets the order.</p>
      </>
    ) : empty("No open issues.")),
    categories: () => (data?.categories?.length ? (
      <>
        <StackedBars rows={data.categories} nameKey="category" linkFor={(r) => `/findings?search=${encodeURIComponent(r.category)}`} />
        <SevLegend />
      </>
    ) : empty("No open issues.")),
    owners: () => (data?.owners?.length ? (
      <>
        <StackedBars rows={data.owners} nameKey="owner" />
        <SevLegend />
        {data.owners[0]?.owner === "Unassigned" ? (
          <p className="an-note">{data.owners[0].total} open findings have no owner. Assign them in <Link to="/findings">Findings</Link> so the SLA clock has someone behind it.</p>
        ) : null}
      </>
    ) : empty("No open issues.")),
  };

  const visible = prefs.order.filter((id) => !prefs.hidden.includes(id));
  const updated = data ? new Date(data.generated_at) : null;

  return (
    <div ref={rootRef} className={`cc an-page${fullscreen ? " cc--fullscreen" : ""}`}>
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Security Analytics</h1>
        </div>
        <div className="cc-top__tools">
          <div className="cc-range" role="group" aria-label="Time range">
            {RANGES.map((r) => (
              <button key={r.days} type="button" aria-pressed={prefs.days === r.days} onClick={() => updatePrefs({ ...prefs, days: r.days })}>
                {r.label}
              </button>
            ))}
          </div>
          {updated ? <time className="cc-clock" dateTime={updated.toISOString()}>Updated {updated.toLocaleTimeString([], { hour12: false })}</time> : null}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
          <button type="button" className="cc-btn" aria-expanded={customizing} aria-controls="an-customize" onClick={() => setCustomizing((v) => !v)}>Customize</button>
          <button type="button" className="cc-btn" onClick={toggleFullscreen}>{fullscreen ? "Exit full screen" : "Full screen"}</button>
        </div>
      </header>

      {customizing && (
        <section id="an-customize" className="cc-customize" aria-label="Customize analytics">
          <div className="cc-customize__head">
            <h2>Panels</h2>
            <div>
              <button type="button" className="cc-btn" onClick={() => updatePrefs({ ...prefs, order: DEFAULT_ORDER, hidden: [] })}>Reset layout</button>
              <button type="button" className="cc-btn cc-btn--primary" onClick={() => setCustomizing(false)}>Done</button>
            </div>
          </div>
          <div className="an-customize__list">
            {prefs.order.map((id, index) => (
              <div key={id} className="cc-customize__row">
                <label className="cc-check">
                  <input type="checkbox" checked={!prefs.hidden.includes(id)} onChange={() => toggleWidget(id)} />
                  {WIDGETS[id].title.split(" · ")[0]}
                </label>
                <span className="cc-customize__order">
                  <button type="button" className="cc-icon" disabled={index === 0} onClick={() => moveWidget(id, -1)} aria-label={`Move ${WIDGETS[id].title} up`}>↑</button>
                  <button type="button" className="cc-icon" disabled={index === prefs.order.length - 1} onClick={() => moveWidget(id, 1)} aria-label={`Move ${WIDGETS[id].title} down`}>↓</button>
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {error && <p className="so-error" role="alert">{error}</p>}

      <div className="cc-kpis">
        <Kpi label="Open backlog" value={k?.open_backlog} hint={k ? `${k.new_in_range} new in range` : undefined} />
        <Kpi label="Past SLA" value={k?.overdue} tone="hot" />
        <Kpi label="SLA compliance" value={pct(k?.sla_compliance)} suffix="%" />
        <Kpi label="Mean time to fix" value={k?.mttr_days != null ? Math.round(k.mttr_days) : null} suffix=" d" hint={k && k.mttr_days == null ? "No fixes recorded yet" : undefined} />
        <Kpi label="False-positive rate" value={pct(k?.fp_rate)} suffix="%" hint={k ? `${k.triaged} findings triaged` : undefined} />
        <Kpi label="Scan coverage · 30 d" value={pct(k?.coverage)} suffix="%" tone={k?.coverage != null && k.coverage < 0.8 ? "hot" : "live"} />
      </div>

      <div className="an-grid">
        {visible.map((id) => (
          <section key={id} className={`cc-panel an-w${WIDGETS[id].wide ? " an-w--wide" : ""}`} aria-label={WIDGETS[id].title}>
            <header className="cc-panel__head"><h2>{WIDGETS[id].title}</h2></header>
            <div className="cc-panel__body">{render[id]()}</div>
          </section>
        ))}
        {!visible.length && <p className="cc-empty">All panels are hidden. Use Customize to turn some back on.</p>}
      </div>
    </div>
  );
}

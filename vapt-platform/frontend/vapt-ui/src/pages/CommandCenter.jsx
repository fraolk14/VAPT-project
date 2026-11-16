import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import ReactorCore from "../components/cc/ReactorCore";
import SeverityTowers from "../components/cc/SeverityTowers";
import { SEV_ORDER } from "../components/cc/ccConstants";
import { DetectionTrend, IssueRing, SeverityPeaks } from "../components/cc/ccCharts";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";

const PREFS_KEY = "vapt_command_center_v1";
const WIDGET_IDS = new Set([
  "top-targets", "severity-peaks", "top-cves",
  "reactor", "severity-towers", "detection-trend",
  "issue-ring", "engine-health", "live-feed",
]);
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ACTIVE = new Set(["running", "queued", "waiting"]);
const RANGES = [
  { key: "1h", label: "1 hr", ms: 3600e3, buckets: 12 },
  { key: "24h", label: "24 hr", ms: 86400e3, buckets: 24 },
  { key: "7d", label: "7 days", ms: 7 * 86400e3, buckets: 7 },
  { key: "all", label: "All", ms: null, buckets: 14 },
];
const TYPE_LABELS = { network: "Network", web: "Web", mobile: "Mobile", endpoint: "Endpoint" };

// ---------- data helpers ----------

const sevOf = (value) => {
  const s = String(value || "info").toLowerCase();
  return SEV_RANK[s] === undefined ? "info" : s;
};

function kindOf(finding) {
  const category = String(finding.category || "").toLowerCase();
  const source = String(finding.source || "").toLowerCase();
  if (category === "mobile" || source === "mobsf") return "mobile";
  if (category === "web" || source === "zap") return "web";
  if (source.includes("agent") || category === "endpoint" || category === "software") return "endpoint";
  return "network";
}

const timeOf = (value) => {
  const t = value ? new Date(value).getTime() : NaN;
  return Number.isNaN(t) ? null : t;
};

function bucketLabel(ms, rangeKey) {
  const d = new Date(ms);
  if (rangeKey === "1h" || rangeKey === "24h") return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return d.toLocaleDateString([], { day: "numeric", month: "short" });
}

function buildModel(findings, scans, integrations, rangeKey, now) {
  const range = RANGES.find((r) => r.key === rangeKey) || RANGES[1];
  const open = findings.filter((f) => String(f.status || "open").toLowerCase() === "open");

  // One issue = same title on the same target (matches the Findings page grouping).
  const issues = new Map();
  for (const f of open) {
    const key = `${f.title}::${f.target || f.asset_name || ""}`;
    const sev = sevOf(f.severity);
    const prev = issues.get(key);
    if (!prev || SEV_RANK[sev] < SEV_RANK[prev.sev]) {
      issues.set(key, { title: f.title, target: f.target || f.asset_name || "unknown", sev, kind: kindOf(f) });
    }
  }
  const issueList = [...issues.values()];

  const sevCounts = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
  issueList.forEach((i) => { sevCounts[i.sev] += 1; });

  const towers = Object.keys(TYPE_LABELS).map((kind) => {
    const sev = Object.fromEntries(SEV_ORDER.map((s) => [s, 0]));
    issueList.filter((i) => i.kind === kind).forEach((i) => { sev[i.sev] += 1; });
    return { key: kind, label: TYPE_LABELS[kind], sev, total: Object.values(sev).reduce((a, b) => a + b, 0) };
  });

  // Targets ranked by weighted severity.
  const byTarget = new Map();
  issueList.forEach((i) => {
    const t = byTarget.get(i.target) || { name: i.target, kind: i.kind, sev: Object.fromEntries(SEV_ORDER.map((s) => [s, 0])), total: 0 };
    t.sev[i.sev] += 1;
    t.total += 1;
    byTarget.set(i.target, t);
  });
  const weight = (t) => t.sev.critical * 1000 + t.sev.high * 100 + t.sev.medium * 10 + t.sev.low;
  const targets = [...byTarget.values()].sort((a, b) => weight(b) - weight(a)).slice(0, 6);
  const maxTarget = Math.max(1, ...targets.map((t) => t.total));

  // CVEs seen on open findings.
  const cves = new Map();
  open.forEach((f) => {
    String(f.cve_id || "").split(/[,\s]+/).filter((c) => /^CVE-\d{4}-\d+$/i.test(c)).forEach((cve) => {
      const id = cve.toUpperCase();
      const entry = cves.get(id) || { id, hosts: new Set(), sev: "info", cvss: 0 };
      entry.hosts.add(f.target || f.asset_name);
      if (SEV_RANK[sevOf(f.severity)] < SEV_RANK[entry.sev]) entry.sev = sevOf(f.severity);
      entry.cvss = Math.max(entry.cvss, Number(f.cvss_score) || 0);
      cves.set(id, entry);
    });
  });
  const topCves = [...cves.values()].sort((a, b) => b.cvss - a.cvss || b.hosts.size - a.hosts.size).slice(0, 6);

  // Most common issue types.
  const byTitle = new Map();
  issueList.forEach((i) => byTitle.set(i.title, (byTitle.get(i.title) || 0) + 1));
  const sortedTitles = [...byTitle.entries()].sort((a, b) => b[1] - a[1]);
  const ring = sortedTitles.slice(0, 6).map(([name, value]) => ({ name, value }));
  const rest = sortedTitles.slice(6).reduce((sum, [, v]) => sum + v, 0);
  if (rest) ring.push({ name: "Others", value: rest });

  // Detection trend from real detected_at timestamps.
  const stamps = findings.map((f) => ({ t: timeOf(f.detected_at || f.discovered_at), sev: sevOf(f.severity) })).filter((s) => s.t);
  let start;
  let span;
  if (range.ms) {
    span = range.ms;
    start = now - span;
  } else {
    const first = stamps.length ? Math.min(...stamps.map((s) => s.t)) : now - 7 * 86400e3;
    start = first;
    span = Math.max(now - first, 3600e3);
  }
  const step = span / range.buckets;
  const labels = [];
  const series = { critical: [], high: [], medium: [], low: [] };
  for (let b = 0; b < range.buckets; b += 1) {
    labels.push(bucketLabel(start + step * (b + 1), range.ms ? rangeKey : span > 2 * 86400e3 ? "7d" : "24h"));
    Object.keys(series).forEach((s) => series[s].push(0));
  }
  let newInRange = 0;
  stamps.forEach(({ t, sev }) => {
    if (t < start || t > now) return;
    newInRange += 1;
    const b = Math.min(range.buckets - 1, Math.floor((t - start) / step));
    if (series[sev]) series[sev][b] += 1;
  });

  // Engines: health from the API, "active" while a scan for that engine is running.
  const running = scans.filter((s) => ACTIVE.has(String(s.status).toLowerCase()));
  const toolRunning = (tools) => running.some((s) => tools.includes(String(s.tool).toLowerCase()));
  const h = integrations || {};
  const state = (healthy, active) => (active ? "active" : healthy ? "healthy" : "down");
  const engines = [
    { name: "Nmap", state: state(true, toolRunning(["openvas", "nmap"])) },
    { name: "ZAP", state: state(h.zap?.healthy, toolRunning(["zap"])) },
    { name: "MobSF", state: state(h.mobsf?.healthy, toolRunning(["mobsf"])) },
    { name: "Threat feed", state: state(h.misp?.healthy, false) },
  ];

  const feed = [...scans]
    .filter((s) => s.finished_at || s.started_at)
    .sort((a, b) => timeOf(b.finished_at || b.started_at) - timeOf(a.finished_at || a.started_at))
    .slice(0, 7)
    .map((s) => {
      const st = String(s.status).toLowerCase();
      const n = s.result_summary?.finding_count;
      const kind = s.tool === "zap" ? "Web" : s.tool === "mobsf" ? "Mobile" : "Network";
      const text = st === "completed" ? `${kind} scan of ${s.target} finished${n !== undefined ? ` · ${n} findings` : ""}`
        : st === "failed" ? `${kind} scan of ${s.target} failed`
        : ACTIVE.has(st) ? `${kind} scan of ${s.target} running · ${Number(s.progress) || 0}%`
        : `${kind} scan of ${s.target} ${st}`;
      return { id: s.id, when: timeOf(s.finished_at || s.started_at), text, tone: st };
    });

  return {
    open: issueList.length,
    urgent: sevCounts.critical + sevCounts.high,
    targetsAtRisk: byTarget.size,
    newInRange,
    running,
    sevCounts,
    towers,
    targets,
    maxTarget,
    topCves,
    ring,
    distinctTypes: byTitle.size,
    trend: { labels, series },
    engines,
    feed,
  };
}

// ---------- layout preferences ----------

function defaultLayout() {
  return {
    left: ["top-targets", "severity-peaks", "top-cves"],
    center: ["reactor", "severity-towers", "detection-trend"],
    right: ["issue-ring", "engine-health", "live-feed"],
    showKpis: true,
  };
}

function loadLayout(validIds) {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(PREFS_KEY) || "null");
    if (!parsed) return defaultLayout();
    const clean = (list) => (Array.isArray(list) ? list.filter((id) => validIds.has(id)) : []);
    return { left: clean(parsed.left), center: clean(parsed.center), right: clean(parsed.right), showKpis: parsed.showKpis !== false };
  } catch {
    return defaultLayout();
  }
}

function saveLayout(layout) {
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify(layout));
  } catch {
    // Storage may be unavailable (private mode); the layout simply isn't remembered.
  }
}

// ---------- small presentational pieces ----------

function Panel({ title, children, action, className = "" }) {
  return (
    <section className={`cc-panel ${className}`} aria-label={title}>
      <header className="cc-panel__head">
        <h2>{title}</h2>
        {action}
      </header>
      <div className="cc-panel__body">{children}</div>
    </section>
  );
}

function Kpi({ label, value, tone }) {
  const shown = useAnimatedNumber(value);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{shown}</strong>
    </div>
  );
}

function timeAgo(ms, now) {
  if (!ms) return "";
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

// ---------- page ----------

export default function CommandCenter({ findings = [], scans = [], integrations = {}, loading = false }) {
  const rootRef = useRef(null);
  const [rangeKey, setRangeKey] = useState("24h");
  const [now, setNow] = useState(() => Date.now());
  const [customizing, setCustomizing] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === rootRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  // Recompute the model at most once a minute for the clock; immediately when data changes.
  const minute = Math.floor(now / 60000);
  const model = useMemo(
    () => buildModel(findings, scans, integrations, rangeKey, minute * 60000 + 59999),
    [findings, scans, integrations, rangeKey, minute],
  );
  const rangeLabel = (RANGES.find((r) => r.key === rangeKey) || RANGES[1]).label;

  const widgets = {
    "top-targets": {
      zone: "left",
      title: "Most exposed targets",
      render: () => (
        model.targets.length ? (
          <ol className="cc-bars">
            {model.targets.map((t) => (
              <li key={t.name}>
                <Link to={`/findings?target=${encodeURIComponent(t.name)}`} className="cc-bars__name" title={t.name}>{t.name}</Link>
                <div className="cc-bars__track" aria-hidden="true">
                  {SEV_ORDER.filter((s) => t.sev[s]).map((s) => (
                    <span key={s} className={`cc-fill cc-fill--${s}`} style={{ width: `${(t.sev[s] / model.maxTarget) * 100}%` }} />
                  ))}
                </div>
                <span className="cc-bars__value">{t.total}</span>
              </li>
            ))}
          </ol>
        ) : <p className="cc-empty">{loading ? "Loading…" : "No open issues."}</p>
      ),
    },
    "severity-peaks": {
      zone: "left",
      title: "Severity peaks",
      render: () => <SeverityPeaks counts={model.sevCounts} />,
    },
    "top-cves": {
      zone: "left",
      title: "Known CVEs on open findings",
      render: () => (
        model.topCves.length ? (
          <ul className="cc-list">
            {model.topCves.map((c) => (
              <li key={c.id}>
                <span className={`cc-dot cc-dot--${c.sev}`} />
                <a className="cc-mono" href={`https://www.cve.org/CVERecord?id=${c.id}`} target="_blank" rel="noreferrer">{c.id}</a>
                <span className="cc-muted">{c.hosts.size} {c.hosts.size === 1 ? "host" : "hosts"}</span>
                <span className="cc-mono cc-right">{c.cvss ? c.cvss.toFixed(1) : "—"}</span>
              </li>
            ))}
          </ul>
        ) : <p className="cc-empty">No CVEs referenced by open findings.</p>
      ),
    },
    reactor: {
      zone: "center",
      title: "Scan reactor",
      render: () => (
        <ReactorCore
          engines={model.engines}
          running={model.running.length}
          total={model.open}
          label={model.running.length ? `open issues · ${model.running.length} scan${model.running.length > 1 ? "s" : ""} running` : "open issues"}
        />
      ),
    },
    "severity-towers": {
      zone: "center",
      title: "Exposure by type",
      render: () => <SeverityTowers groups={model.towers} />,
    },
    "detection-trend": {
      zone: "center",
      title: `Detections · last ${rangeLabel}`,
      render: () => <DetectionTrend buckets={model.trend} />,
    },
    "issue-ring": {
      zone: "right",
      title: "Top issue types",
      render: () => (model.ring.length ? <IssueRing items={model.ring} total={model.distinctTypes} /> : <p className="cc-empty">No open issues.</p>),
    },
    "engine-health": {
      zone: "right",
      title: "Engines",
      render: () => (
        <ul className="cc-list">
          {model.engines.map((e) => (
            <li key={e.name}>
              <span className={`cc-dot cc-dot--${e.state}`} />
              <span>{e.name}</span>
              <span className={`cc-state cc-state--${e.state}`}>{e.state === "active" ? "Scanning" : e.state === "healthy" ? "Ready" : "Offline"}</span>
            </li>
          ))}
        </ul>
      ),
    },
    "live-feed": {
      zone: "right",
      title: "Live activity",
      render: () => (
        <>
          {model.running.slice(0, 2).map((s) => {
            const pct = Math.max(0, Math.min(100, Number(s.progress) || 0));
            return (
              <div key={s.id} className="cc-live">
                <div className="cc-live__head"><span className="cc-mono">{s.target}</span><span className="cc-mono">{pct}%</span></div>
                <div className="cc-progress" role="progressbar" aria-label={`Scan progress for ${s.target}`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
                  <span style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
          {model.feed.length ? (
            <ul className="cc-feed">
              {model.feed.map((e) => (
                <li key={e.id} className={`cc-feed__item cc-feed__item--${e.tone}`}>
                  <time>{timeAgo(e.when, now)}</time>
                  <p>{e.text}</p>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">No scan activity yet.</p>}
        </>
      ),
    },
  };

  const [layout, setLayout] = useState(() => loadLayout(WIDGET_IDS));
  const updateLayout = (next) => {
    setLayout(next);
    saveLayout(next);
  };

  const toggleWidget = (id) => {
    const zone = widgets[id].zone;
    const list = layout[zone];
    updateLayout({ ...layout, [zone]: list.includes(id) ? list.filter((x) => x !== id) : [...list, id] });
  };
  const moveWidget = (id, delta) => {
    const zone = widgets[id].zone;
    const list = [...layout[zone]];
    const i = list.indexOf(id);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    updateLayout({ ...layout, [zone]: list });
  };

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else rootRef.current?.requestFullscreen?.();
  };

  const renderZone = (zone) => layout[zone].map((id) => {
    const widget = widgets[id];
    return (
      <Panel key={id} title={widget.title} className={`cc-w-${id}`}>
        {widget.render()}
      </Panel>
    );
  });

  const clock = new Date(now);

  return (
    <div ref={rootRef} className={`cc${fullscreen ? " cc--fullscreen" : ""}`}>
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Threat Command Center</h1>
        </div>
        <div className="cc-top__tools">
          <div className="cc-range" role="group" aria-label="Time range">
            {RANGES.map((r) => (
              <button key={r.key} type="button" aria-pressed={rangeKey === r.key} onClick={() => setRangeKey(r.key)}>
                {r.label}
              </button>
            ))}
          </div>
          <time className="cc-clock" dateTime={clock.toISOString()}>
            {clock.toLocaleDateString([], { day: "2-digit", month: "short" })} · {clock.toLocaleTimeString([], { hour12: false })}
          </time>
          <button type="button" className="cc-btn" aria-expanded={customizing} aria-controls="cc-customize" onClick={() => setCustomizing((v) => !v)}>
            Customize
          </button>
          <button type="button" className="cc-btn" onClick={toggleFullscreen}>
            {fullscreen ? "Exit full screen" : "Full screen"}
          </button>
        </div>
      </header>

      {customizing && (
        <section id="cc-customize" className="cc-customize" aria-label="Customize dashboard">
          <div className="cc-customize__head">
            <h2>Widgets</h2>
            <div>
              <label className="cc-check">
                <input type="checkbox" checked={layout.showKpis} onChange={() => updateLayout({ ...layout, showKpis: !layout.showKpis })} />
                Headline counters
              </label>
              <button type="button" className="cc-btn" onClick={() => updateLayout(defaultLayout())}>Reset layout</button>
              <button type="button" className="cc-btn cc-btn--primary" onClick={() => setCustomizing(false)}>Done</button>
            </div>
          </div>
          <div className="cc-customize__zones">
            {["left", "center", "right"].map((zone) => (
              <fieldset key={zone}>
                <legend>{zone === "center" ? "Centre" : zone === "left" ? "Left column" : "Right column"}</legend>
                {Object.entries(widgets).filter(([, w]) => w.zone === zone).map(([id, w]) => {
                  const on = layout[zone].includes(id);
                  const position = layout[zone].indexOf(id);
                  return (
                    <div key={id} className="cc-customize__row">
                      <label className="cc-check">
                        <input type="checkbox" checked={on} onChange={() => toggleWidget(id)} />
                        {w.title.split(" · ")[0]}
                      </label>
                      <span className="cc-customize__order">
                        <button type="button" className="cc-icon" disabled={!on || position === 0} onClick={() => moveWidget(id, -1)} aria-label={`Move ${w.title} up`}>↑</button>
                        <button type="button" className="cc-icon" disabled={!on || position === layout[zone].length - 1} onClick={() => moveWidget(id, 1)} aria-label={`Move ${w.title} down`}>↓</button>
                      </span>
                    </div>
                  );
                })}
              </fieldset>
            ))}
          </div>
        </section>
      )}

      {layout.showKpis && (
        <div className="cc-kpis">
          <Kpi label="Open issues" value={model.open} />
          <Kpi label="Critical + high" value={model.urgent} tone="hot" />
          <Kpi label={`New · ${rangeLabel}`} value={model.newInRange} />
          <Kpi label="Targets at risk" value={model.targetsAtRisk} />
          <Kpi label="Scans running" value={model.running.length} tone={model.running.length ? "live" : ""} />
        </div>
      )}

      <div className="cc-grid">
        <div className="cc-col cc-col--side">{renderZone("left")}</div>
        <div className="cc-col cc-col--center">{renderZone("center")}</div>
        <div className="cc-col cc-col--side">{renderZone("right")}</div>
      </div>
    </div>
  );
}

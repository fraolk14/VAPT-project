import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import BarField3D from "../components/cc/BarField3D";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import { SEV_HEX } from "../components/cc/ccConstants";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../shadow.css";
import "../ops.css";
import "../hosts.css";

const SEVS = ["critical", "high", "medium", "low"];
const ENGINE_LABEL = { network: "Network", web: "Web", mobile: "Mobile", agent: "Agent" };
const REFRESH_MS = 60_000;

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "Never");
const errText = (err, fallback) => (err?.response?.data?.detail ? String(err.response.data.detail) : fallback);

function Kpi({ label, value, tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value == null ? "—" : shown}</strong>
      {hint ? <small className="an-kpi-hint">{hint}</small> : null}
    </div>
  );
}

function Rescan({ host, onDone }) {
  const webTarget = host.engines.web?.last_target || host.targets.find((t) => /^https?:\/\//i.test(t));
  const netTarget = host.engines.network?.last_target || host.targets.find((t) => !/^https?:\/\//i.test(t)) || (/^[\d.:]+$/.test(host.host) ? host.host : null);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState("");

  const launch = async (kind, target) => {
    setBusy(kind);
    try {
      await api.post(kind === "web" ? "/scans/web" : "/scans/network", { target, label: `Re-scan ${host.host}` });
      onDone(true, `${ENGINE_LABEL[kind]} re-scan of ${target} queued.`);
      setAuthorized(false);
    } catch (err) {
      onDone(false, errText(err, "Couldn't start the re-scan."));
    } finally {
      setBusy("");
    }
  };

  if (!webTarget && !netTarget) return <p className="so-sub">No scan target recorded for this host.</p>;
  return (
    <div className="hs-rescan">
      <label className="cc-check so-consent">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
        I'm still authorized to test this host.
      </label>
      <div className="op-row">
        {netTarget ? <button type="button" className="cc-btn" disabled={!authorized || !!busy} onClick={() => launch("network", netTarget)}>{busy === "network" ? "Queueing…" : `Network re-scan · ${netTarget}`}</button> : null}
        {webTarget ? <button type="button" className="cc-btn" disabled={!authorized || !!busy} onClick={() => launch("web", webTarget)}>{busy === "web" ? "Queueing…" : `Web re-scan · ${webTarget}`}</button> : null}
      </div>
    </div>
  );
}

export default function Hosts({ canOperate = false }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(null);
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get("/hosts/overview");
      setData(r.data);
      setError("");
    } catch {
      setError("Couldn't load hosts. Check that the API is running.");
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const timer = window.setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [load]);

  const hosts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.hosts || []).filter((h) => {
      if (filter === "stale" && !h.stale) return false;
      if (filter === "urgent" && !(h.open.critical + h.open.high)) return false;
      if (filter === "clean" && h.open_total) return false;
      return !q || `${h.host} ${h.targets.join(" ")} ${h.asset?.os || ""} ${h.services.join(" ")}`.toLowerCase().includes(q);
    });
  }, [data, filter, query]);

  const k = data?.kpis;
  const rows = (data?.matrix?.rows || []).map((r) => ({ ...r, color: SEV_HEX[r.key] }));
  const hasMatrix = data?.matrix?.values?.some((row) => row.some(Boolean));

  return (
    <div className="cc hs-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Hosts</h1>
        </div>
        <div className="cc-top__tools">
          {data ? <time className="cc-clock" dateTime={data.generated_at}>Updated {new Date(data.generated_at).toLocaleTimeString([], { hour12: false })}</time> : null}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
        </div>
      </header>

      {error && <p className="so-error" role="alert">{error}</p>}
      {notice ? <p className={notice.ok ? "mc-ok op-notice" : "so-error op-notice"} role={notice.ok ? "status" : "alert"}>{notice.text} {notice.ok ? <Link to="/scans">Open Scans</Link> : null}</p> : null}

      <div className="cc-kpis">
        <Kpi label="Hosts assessed" value={k?.hosts} />
        <Kpi label={`Not scanned in ${data?.stale_days ?? 30} d`} value={k?.stale} tone={k?.stale ? "hot" : "live"} />
        <Kpi label="With critical / high" value={k?.with_urgent} tone={k?.with_urgent ? "hot" : ""} />
        <Kpi label="Open findings" value={k?.open_findings} hint="excluding info" />
        <Kpi label="Median days since scan" value={k?.median_days_since_scan} />
        <Kpi label="Failed scans · 30 d" value={k?.failed_scans_30d} />
      </div>

      <section className="cc-panel" aria-label="Open findings by host">
        <header className="cc-panel__head"><h2>Open findings · severity × host</h2></header>
        {hasMatrix ? (
          <BarField3D rows={rows} cols={data.matrix.cols} values={data.matrix.values} caption="Open findings per host and severity"
            describe={(row, col, value) => <><strong>{value}</strong> {row.label} open on <span className="cc-mono">{col}</span></>} />
        ) : <p className="cc-empty">{data ? "No open findings on scanned hosts." : "Loading…"}</p>}
        {data?.ranges_scanned?.length ? <p className="an-note">Range scans ({data.ranges_scanned.join(", ")}) are counted under each host they found, not as hosts themselves.</p> : null}
      </section>

      <section className="cc-panel sh-section" aria-label="Hosts">
        <header className="cc-panel__head"><h2>Hosts ({hosts.length})</h2></header>
        <div className="mc-filters">
          <div className="cc-range" role="group" aria-label="Filter hosts">
            {[["all", "All"], ["urgent", "Critical / high"], ["stale", "Stale"], ["clean", "No open issues"]].map(([key, label]) => (
              <button key={key} type="button" aria-pressed={filter === key} onClick={() => setFilter(key)}>{label}</button>
            ))}
          </div>
          <input className="so-input mc-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search host, OS or service" aria-label="Search hosts" />
        </div>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead><tr><th scope="col">Host</th><th scope="col">Coverage</th><th scope="col">Last scan</th><th scope="col">Open</th><th scope="col">New in last scan</th></tr></thead>
            <tbody>
              {hosts.map((h) => {
                const expanded = open === h.host;
                return (
                  <Fragment key={h.host}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : h.host)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>
                            <span className="cc-mono">{h.host}</span>
                            <span className="so-sub" style={{ display: "block" }}>{[h.asset?.os, h.asset?.exposure, h.asset?.owner].filter(Boolean).join(" · ") || "Not in inventory"}</span>
                          </span>
                        </button>
                      </td>
                      <td>
                        <span className="sh-chips">
                          {Object.keys(ENGINE_LABEL).map((e) => (
                            <span key={e} className={`hs-engine${h.engines[e] ? " is-on" : ""}`} title={h.engines[e] ? `${ENGINE_LABEL[e]}: last ${fmtDate(h.engines[e].last)}, ${h.engines[e].runs} run(s)` : `${ENGINE_LABEL[e]}: never`}>{ENGINE_LABEL[e]}</span>
                          ))}
                        </span>
                      </td>
                      <td className={`cc-mono${h.stale ? " an-bad" : ""}`}>
                        {fmtDate(h.last_scan)}
                        {h.days_since_scan != null ? <span className="so-sub" style={{ display: "block" }}>{h.days_since_scan === 0 ? "today" : `${h.days_since_scan} d ago`}</span> : null}
                      </td>
                      <td>
                        {h.open_total ? (
                          <span className="sh-sevmini">{SEVS.filter((s) => h.open[s]).map((s) => <span key={s} className={`sh-sevmini__chip sh-sevmini__chip--${s}`} title={`${s}: ${h.open[s]}`}>{h.open[s]}</span>)}</span>
                        ) : <span className="cc-muted">None</span>}
                      </td>
                      <td className="cc-mono">{h.new_since_last_scan || "—"}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row">
                        <td colSpan={5}>
                          <div className="mc-detail">
                            <section>
                              <h3>Worst open findings</h3>
                              {h.top_findings.length ? (
                                <ul className="cc-list">
                                  {h.top_findings.map((f) => (
                                    <li key={f.id}><span className={`cc-dot cc-dot--${f.severity}`} aria-hidden="true" /><Link to={`/findings/${f.id}`}>{f.title}</Link></li>
                                  ))}
                                </ul>
                              ) : <p>No open findings.</p>}
                              <p className="so-sub">{h.resolved} fixed · {h.false_positive} marked false positive · {h.scans} scan{h.scans === 1 ? "" : "s"}{h.failed_scans ? ` (${h.failed_scans} failed)` : ""}</p>
                              <Link className="cc-btn" to={`/findings?target=${encodeURIComponent(h.host)}`}>All findings for this host</Link>
                            </section>
                            <section>
                              <h3>Services seen</h3>
                              {h.services.length ? <span className="sh-chips">{h.services.map((s) => <span key={s} className="ti-chip">{s}</span>)}</span> : <p>None recorded.</p>}
                              <h3 className="hs-subhead">Engine coverage</h3>
                              <ul className="hs-cov">
                                {Object.entries(ENGINE_LABEL).map(([e, label]) => (
                                  <li key={e}><span>{label}</span><span className="cc-mono">{h.engines[e] ? `${fmtDate(h.engines[e].last)} · ${h.engines[e].runs}×` : "never"}</span></li>
                                ))}
                              </ul>
                            </section>
                            <section>
                              <h3>Re-scan</h3>
                              {canOperate ? <Rescan host={h} onDone={(ok, text) => { setNotice({ ok, text }); }} /> : <p>Ask an analyst to re-scan this host.</p>}
                              {h.asset ? <p className="so-sub">Inventory: {h.asset.name} · criticality {h.asset.criticality || "?"}</p> : <p className="so-sub">Not in the inventory. <Link to="/shadow-it">Review it in Shadow IT</Link>.</p>}
                            </section>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!hosts.length ? <tr><td colSpan={5} className="cc-empty so-empty">{data ? "No hosts match." : "Loading…"}</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

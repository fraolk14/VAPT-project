import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import BarField3D from "../components/cc/BarField3D";
import { FamilyRadar } from "../components/cc/anCharts";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";

const FAMILY_COLORS = {
  "os-hardening": 0xa78bfa,
  auth: 0xff6b6b,
  "cors-cookies": 0xf5d76e,
  headers: 0x5ce1ff,
  transport: 0x3ddc97,
  "exposed-services": 0xff9f5a,
  disclosure: 0x2e7bff,
};
const SEVS = ["critical", "high", "medium", "low"];
const REFRESH_MS = 60_000;

const isUrl = (value) => /^https?:\/\//i.test(value.trim());
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "—");
const hex = (n) => `#${n.toString(16).padStart(6, "0")}`;

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

function CheckTarget({ onQueued }) {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const web = isUrl(target);

  const submit = async (event) => {
    event.preventDefault();
    const t = target.trim();
    if (!t) return setNotice({ ok: false, text: "Enter a URL, host, IP or CIDR range." });
    if (!authorized) return setNotice({ ok: false, text: "Confirm you are authorized to test this target." });
    setBusy(true);
    setNotice(null);
    try {
      await api.post(web ? "/scans/web" : "/scans/network", { target: t, label: "Configuration check" });
      setNotice({ ok: true, text: `${web ? "Web" : "Network"} check of ${t} queued. Configuration issues it finds appear here when it finishes — follow progress on the Scans page.` });
      setTarget("");
      setAuthorized(false);
      onQueued?.();
    } catch (err) {
      setNotice({ ok: false, text: err?.response?.data?.detail ? String(err.response.data.detail) : "Couldn't start the check." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="mc-check" onSubmit={submit} aria-label="Check a target for misconfigurations">
      <label className="mc-check__field">
        <span>Target</span>
        <input className="so-input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://app.example.com  ·  10.0.0.5  ·  10.0.0.0/24" autoComplete="off" />
      </label>
      <p className="mc-check__engine cc-muted">
        {target.trim() ? (web ? "Runs the web engine: headers, TLS, cookies, CORS, exposed files and admin pages." : "Runs the network engine: exposed services, cleartext protocols, unauthenticated databases.") : "URLs use the web engine; IPs, hosts and ranges use the network engine."}
      </p>
      <label className="cc-check so-consent">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
        I'm authorized to test this target.
      </label>
      <button type="submit" className="cc-btn cc-btn--primary" disabled={busy || !authorized}>{busy ? "Starting…" : "Run check"}</button>
      {notice && <p className={notice.ok ? "mc-ok" : "so-error"} role={notice.ok ? "status" : "alert"}>{notice.text} {notice.ok ? <Link to="/scans">Open Scans</Link> : null}</p>}
    </form>
  );
}

export default function Misconfigurations({ canOperate = false }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [showCheck, setShowCheck] = useState(false);
  const [family, setFamily] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get("/misconfig/posture");
      setData(res.data);
      setError("");
    } catch {
      setError("Couldn't load configuration posture. Check that the API is running.");
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

  const families = useMemo(() => data?.families || [], [data]);
  const issues = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.issues || []).filter((i) =>
      (family === "all" || i.family === family) &&
      (severity === "all" || i.severity === severity) &&
      (!q || i.title.toLowerCase().includes(q) || i.targets.some((t) => t.toLowerCase().includes(q)) || (i.control || "").toLowerCase().includes(q)));
  }, [data, family, severity, query]);

  const k = data?.kpis;
  const matrixRows = (data?.matrix?.rows || []).map((r) => ({ ...r, color: FAMILY_COLORS[r.key] }));
  const maxTarget = Math.max(1, ...(data?.targets || []).map((t) => t.open));

  return (
    <div className="cc mc-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Misconfigurations</h1>
        </div>
        <div className="cc-top__tools">
          {data ? <time className="cc-clock" dateTime={data.generated_at}>Updated {new Date(data.generated_at).toLocaleTimeString([], { hour12: false })}</time> : null}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
          {canOperate ? (
            <button type="button" className="cc-btn cc-btn--primary" aria-expanded={showCheck} aria-controls="mc-check" onClick={() => setShowCheck((v) => !v)}>
              {showCheck ? "Close" : "Check a target"}
            </button>
          ) : null}
        </div>
      </header>

      {showCheck && canOperate ? (
        <section id="mc-check" className="cc-panel mc-check-panel" aria-label="Check a target">
          <header className="cc-panel__head"><h2>Check a target</h2></header>
          <CheckTarget onQueued={load} />
        </section>
      ) : null}

      {error && <p className="so-error" role="alert">{error}</p>}

      <div className="cc-kpis">
        <Kpi label="Open misconfigurations" value={k?.open} hint={k ? `${k.issue_types} distinct issues` : undefined} />
        <Kpi label="Critical + high" value={k?.urgent} tone="hot" />
        <Kpi label="Targets affected" value={k?.targets} />
        <Kpi label="Control families failing" value={k?.families_failing} hint="of 7" />
        <Kpi label="CIS checks failing" value={k?.cis_failing} hint="on agent endpoints" />
        <Kpi label="Fixed · 30 d" value={k?.fixed_30d} tone="live" />
      </div>

      <div className="an-grid">
        <section className="cc-panel an-w an-w--wide" aria-label="Misconfiguration matrix">
          <header className="cc-panel__head"><h2>Misconfiguration matrix · family × target</h2></header>
          {data?.matrix?.cols?.length ? (
            <BarField3D
              rows={matrixRows}
              cols={data.matrix.cols}
              values={data.matrix.values}
              caption="Open configuration issues per control family and target"
              describe={(row, col, value) => <><strong>{value}</strong> {row.label.toLowerCase()} issue{value === 1 ? "" : "s"} on <span className="cc-mono">{col}</span></>}
              footer={<div className="an-terrain__axis cc-mono"><span>Most exposed</span><span>← top {data.matrix.cols.length} targets →</span><span>Less exposed</span></div>}
            />
          ) : <p className="cc-empty">{data ? "No configuration issues open." : "Loading…"}</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Control families">
          <header className="cc-panel__head"><h2>Control families</h2></header>
          {families.length ? (
            <>
              <FamilyRadar families={families} />
              <ul className="mc-families">
                {families.map((f) => (
                  <li key={f.key}>
                    <button type="button" className={`mc-family${family === f.key ? " is-active" : ""}`} aria-pressed={family === f.key} onClick={() => setFamily(family === f.key ? "all" : f.key)}>
                      <span className="cc-swatch" style={{ background: hex(FAMILY_COLORS[f.key]) }} />
                      <span className="mc-family__name">{f.label}</span>
                      <span className="cc-mono">{f.open}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          ) : <p className="cc-empty">{data ? "Nothing to show." : "Loading…"}</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Most misconfigured targets">
          <header className="cc-panel__head"><h2>Most misconfigured targets</h2></header>
          {data?.targets?.length ? (
            <>
              <ol className="cc-bars">
                {data.targets.map((t) => (
                  <li key={t.target}>
                    <Link to={`/findings?target=${encodeURIComponent(t.target)}`} className="cc-bars__name" title={`${t.target} — ${Object.entries(t.families).map(([n, c]) => `${n}: ${c}`).join(", ")}`}>{t.target}</Link>
                    <div className="cc-bars__track" aria-hidden="true">
                      {SEVS.filter((s) => t[s]).map((s) => <span key={s} className={`cc-fill cc-fill--${s}`} style={{ width: `${(t[s] / maxTarget) * 100}%` }} />)}
                    </div>
                    <span className="cc-bars__value">{t.open}</span>
                  </li>
                ))}
              </ol>
              <ul className="cc-legend an-legend">{SEVS.map((s) => <li key={s}><span className={`cc-swatch cc-swatch--${s}`} />{s}</li>)}</ul>
            </>
          ) : <p className="cc-empty">{data ? "No targets affected." : "Loading…"}</p>}
        </section>

        <section className="cc-panel an-w" aria-label="CIS hardening checks failing">
          <header className="cc-panel__head"><h2>CIS hardening checks failing</h2></header>
          {data?.cis?.length ? (
            <ul className="cc-list">
              {data.cis.map((c) => (
                <li key={c.title} className="an-overdue">
                  <span className={`cc-dot cc-dot--${c.severity}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <span>{c.title}</span>
                    <span className="so-sub cc-mono">{c.control !== "—" ? c.control : "No CIS reference"} · {c.endpoints.slice(0, 3).join(", ")}{c.endpoints.length > 3 ? "…" : ""}</span>
                  </span>
                  <span className="cc-mono">{c.endpoint_count} endpoint{c.endpoint_count === 1 ? "" : "s"}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="cc-empty">{data ? <>No failing checks. CIS results come from the endpoint agent — <Link to="/agent-management">deploy it</Link> to Windows hosts to audit them.</> : "Loading…"}</p>
          )}
        </section>
      </div>

      <section className="cc-panel mc-issues" aria-label="Configuration issues">
        <header className="cc-panel__head">
          <h2>Configuration issues ({issues.length})</h2>
        </header>
        <div className="mc-filters">
          <input className="so-input mc-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search issue, target or CIS control" aria-label="Search configuration issues" />
          <select className="so-input" value={family} onChange={(e) => setFamily(e.target.value)} aria-label="Control family">
            <option value="all">All families</option>
            {families.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
          </select>
          <select className="so-input" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
            <option value="all">All severities</option>
            {SEVS.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead>
              <tr>
                <th scope="col">Issue</th>
                <th scope="col">Family</th>
                <th scope="col">Severity</th>
                <th scope="col">Targets</th>
                <th scope="col">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {issues.map((i) => {
                const expanded = open === i.key;
                return (
                  <Fragment key={i.key}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} aria-controls={`mc-d-${i.key}`} onClick={() => setOpen(expanded ? null : i.key)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>{i.title}{i.control ? <span className="so-sub cc-mono"> · {i.control}</span> : null}</span>
                        </button>
                      </td>
                      <td><span className="mc-fam-tag" style={{ "--fam": hex(FAMILY_COLORS[i.family]) }}>{i.family_label}</span></td>
                      <td><span className={`mc-sev mc-sev--${i.severity}`}>{i.severity}</span></td>
                      <td className="cc-mono">{i.target_count}</td>
                      <td className="cc-mono cc-muted">{fmtDate(i.last_seen)}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row" id={`mc-d-${i.key}`}>
                        <td colSpan={5}>
                          <div className="mc-detail">
                            <section>
                              <h3>How to fix</h3>
                              <p>{i.remediation || "The scanner gave no remediation guidance for this issue."}</p>
                            </section>
                            {i.evidence ? (
                              <section>
                                <h3>Evidence</h3>
                                <pre className="fx-proof">{i.evidence}</pre>
                              </section>
                            ) : null}
                            <section>
                              <h3>Affected targets ({i.target_count})</h3>
                              <ul className="mc-targets">
                                {i.targets.slice(0, 24).map((t) => <li key={t}><Link className="cc-mono" to={`/findings?target=${encodeURIComponent(t)}`}>{t}</Link></li>)}
                              </ul>
                              <p className="so-sub">{i.count} finding{i.count === 1 ? "" : "s"} · reported by {i.sources.join(", ")} · first seen {fmtDate(i.first_seen)}</p>
                              <Link className="cc-btn" to={`/findings?search=${encodeURIComponent(i.title)}`}>Open in Findings</Link>
                            </section>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!issues.length && <tr><td colSpan={5} className="cc-empty so-empty">{data ? "No issues match these filters." : "Loading…"}</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="an-note">
          Built from network, web and endpoint-agent findings that describe a configuration problem. Software vulnerabilities, injection flaws and Shadow IT have their own pages. Triage and assign individual findings in <Link to="/findings">Findings</Link>.
        </p>
      </section>
    </div>
  );
}

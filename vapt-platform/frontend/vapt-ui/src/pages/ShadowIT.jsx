import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import BarField3D from "../components/cc/BarField3D";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../shadow.css";

const CATEGORY_COLORS = {
  "remote-access": 0xff6b6b,
  "cloud-storage": 0xff9f5a,
  "removable-media": 0xf5d76e,
  "browser-extensions": 0x5ce1ff,
  other: 0xa78bfa,
};
const STATE_LABEL = { unreviewed: "Unreviewed", sanctioned: "Sanctioned", unsanctioned: "Unsanctioned" };
const REFRESH_MS = 60_000;
const SEVS = ["critical", "high", "medium", "low"];

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "—");
const hex = (n) => `#${n.toString(16).padStart(6, "0")}`;
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

function SevMini({ row }) {
  const total = SEVS.reduce((sum, s) => sum + (row[s] || 0), 0);
  if (!total) return <span className="cc-muted">None open</span>;
  return (
    <span className="sh-sevmini" title={SEVS.map((s) => `${s}: ${row[s] || 0}`).join(" · ")}>
      {SEVS.filter((s) => row[s]).map((s) => <span key={s} className={`sh-sevmini__chip sh-sevmini__chip--${s}`}>{row[s]}</span>)}
    </span>
  );
}

function ReviewForm({ device, onDone }) {
  const [owner, setOwner] = useState(device.owner || "");
  const initialUnit = device.business_unit && device.business_unit !== "Discovered" ? device.business_unit : "";
  const [unit, setUnit] = useState(initialUnit);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const decide = async (decision) => {
    setBusy(true);
    setMsg(null);
    try {
      // Only send fields the user changed, so a blank box never wipes existing values.
      const body = { decision };
      if (owner !== (device.owner || "")) body.owner = owner;
      if (unit !== initialUnit) body.business_unit = unit;
      await api.post(`/shadow-it/devices/${device.id}/review`, body);
      const where = device.address || device.name;
      onDone(decision === "unreviewed" ? `${where} moved back to the review queue.` : `${where} marked ${decision}.`);
    } catch (err) {
      setMsg({ ok: false, text: errText(err, "Couldn't save the review.") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sh-review">
      <label>
        <span>Owner</span>
        <input className="so-input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="name@company.com" />
      </label>
      <label>
        <span>Business unit</span>
        <input className="so-input" value={unit} onChange={(e) => setUnit(e.target.value)} placeholder="e.g. Finance" />
      </label>
      <div className="sh-review__actions">
        <button type="button" className="cc-btn sh-btn-ok" disabled={busy} onClick={() => decide("sanctioned")}>Sanction</button>
        <button type="button" className="cc-btn sh-btn-bad" disabled={busy} onClick={() => decide("unsanctioned")}>Flag as unsanctioned</button>
        {device.state !== "unreviewed" ? <button type="button" className="cc-btn" disabled={busy} onClick={() => decide("unreviewed")}>Reset</button> : null}
      </div>
      {msg ? <p className={msg.ok ? "mc-ok" : "so-error"} role={msg.ok ? "status" : "alert"}>{msg.text}</p> : null}
    </div>
  );
}

export default function ShadowIT({ canOperate = false }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("unreviewed");
  const [query, setQuery] = useState("");
  const [openDevice, setOpenDevice] = useState(null);
  const [openApp, setOpenApp] = useState(null);
  const [notice, setNotice] = useState(null);
  const [showAll, setShowAll] = useState(false);
  const [reviewNotice, setReviewNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await api.get("/shadow-it/posture");
      setData(res.data);
      setError("");
    } catch {
      setError("Couldn't load Shadow IT data. Check that the API is running.");
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

  const onReviewed = (text) => {
    setReviewNotice(text);
    setOpenDevice(null);
    load();
  };

  const register = async (address) => {
    setNotice(null);
    try {
      await api.post("/shadow-it/untracked/register", { address });
      setNotice({ ok: true, text: `${address} added to the inventory. Review it below to sanction it and set an owner.` });
      load();
    } catch (err) {
      setNotice({ ok: false, text: errText(err, `Couldn't add ${address}.`) });
    }
  };

  const devices = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.devices || []).filter((d) => d.state === tab && (!q || `${d.name} ${d.address} ${d.services.join(" ")} ${d.owner || ""}`.toLowerCase().includes(q)));
  }, [data, tab, query]);

  const k = data?.kpis;
  const inv = data?.inventory;
  const invTotal = inv ? Object.values(inv).reduce((a, b) => a + b, 0) : 0;
  const matrixRows = (data?.matrix?.rows || []).map((r) => ({ ...r, color: CATEGORY_COLORS[r.key] }));
  const segments = inv ? [
    ["managed", "Agent-managed", "#3ddc97"],
    ["sanctioned", "Reviewed · sanctioned", "#2e7bff"],
    ["registered", "Registered by a person", "#5ce1ff"],
    ["unreviewed", "Discovered · unreviewed", "#f5d76e"],
    ["unsanctioned", "Flagged unsanctioned", "#ff6b6b"],
  ] : [];

  return (
    <div className="cc sh-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Shadow IT</h1>
        </div>
        <div className="cc-top__tools">
          {data ? <time className="cc-clock" dateTime={data.generated_at}>Updated {new Date(data.generated_at).toLocaleTimeString([], { hour12: false })}</time> : null}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
        </div>
      </header>

      {error && <p className="so-error" role="alert">{error}</p>}

      <div className="cc-kpis">
        <Kpi label="Unreviewed devices" value={k?.unreviewed_devices} tone={k?.unreviewed_devices ? "hot" : "live"} hint="found by scans, no owner" />
        <Kpi label="Hosts not in inventory" value={k?.untracked_hosts} tone={k?.untracked_hosts ? "hot" : "live"} />
        <Kpi label="Shadow apps" value={k?.shadow_apps} hint={k ? `on ${k.endpoints_with_apps} of ${k.managed_endpoints} agent endpoints` : undefined} />
        <Kpi label="Remote-access tools" value={k?.remote_access} tone={k?.remote_access ? "hot" : ""} />
        <Kpi label="Internet-facing, no owner" value={k?.unowned_external} />
        <Kpi label="Flagged unsanctioned" value={k?.unsanctioned} />
      </div>

      <div className="an-grid">
        <section className="cc-panel an-w an-w--wide" aria-label="Shadow apps by endpoint">
          <header className="cc-panel__head"><h2>Shadow apps · category × endpoint</h2></header>
          {data?.matrix?.cols?.length ? (
            <BarField3D
              rows={matrixRows}
              cols={data.matrix.cols}
              values={data.matrix.values}
              caption="Unsanctioned app detections per category and endpoint"
              describe={(row, col, value) => <><strong>{value}</strong> {row.label.toLowerCase()} detection{value === 1 ? "" : "s"} on <span className="cc-mono">{col}</span></>}
            />
          ) : (
            <p className="cc-empty">{data ? <>No unsanctioned apps reported. App detection comes from the endpoint agent — <Link to="/agent-management">deploy it</Link> to see what's installed.</> : "Loading…"}</p>
          )}
        </section>

        <section className="cc-panel an-w" aria-label="Inventory status">
          <header className="cc-panel__head"><h2>Inventory status</h2></header>
          {inv ? (
            <>
              <div className="sh-stack" role="img" aria-label={segments.map(([key, label]) => `${label}: ${inv[key]}`).join(", ")}>
                {segments.filter(([key]) => inv[key]).map(([key, label, color]) => (
                  <span key={key} style={{ flexGrow: inv[key], background: color }} title={`${label}: ${inv[key]}`} />
                ))}
              </div>
              <ul className="sh-stack-legend">
                {segments.map(([key, label, color]) => (
                  <li key={key}><span className="cc-swatch" style={{ background: color }} />{label}<span className="cc-mono">{inv[key]}</span></li>
                ))}
              </ul>
              <p className="an-note">{invTotal} active targets. Devices the scanners discover are added automatically; until someone sanctions them and names an owner, they count as shadow IT.</p>
            </>
          ) : <p className="cc-empty">Loading…</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Hosts not in inventory">
          <header className="cc-panel__head"><h2>Seen on the network, not in inventory</h2></header>
          {notice ? <p className={notice.ok ? "mc-ok" : "so-error"} role={notice.ok ? "status" : "alert"}>{notice.text}</p> : null}
          {data?.untracked?.length ? (
            <ul className="cc-list">
              {data.untracked.map((u) => (
                <li key={u.address} className="an-overdue">
                  <span className={`cc-dot cc-dot--${u.severity}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <Link className="cc-mono" to={`/findings?target=${encodeURIComponent(u.address)}`}>{u.address}</Link>
                    <span className="sh-chips">{u.services.map((s) => <span key={s} className="ti-chip">{s}</span>)}</span>
                    <span className="so-sub">{u.findings} open finding{u.findings === 1 ? "" : "s"} · first seen {fmtDate(u.first_seen)} · last {fmtDate(u.last_seen)}</span>
                  </span>
                  {canOperate ? <button type="button" className="cc-btn" onClick={() => register(u.address)}>Add to inventory</button> : null}
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">{data ? "Every host the scanners reached is in the inventory." : "Loading…"}</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Internet-facing targets without an owner">
          <header className="cc-panel__head"><h2>Internet-facing, no owner</h2></header>
          {data?.unowned_external?.length ? (
            <ul className="cc-list">
              {data.unowned_external.slice(0, 8).map((a) => (
                <li key={a.id}>
                  <span className="an-overdue__main">
                    <span>{a.name}</span>
                    {a.address !== a.name ? <span className="so-sub cc-mono">{a.address}</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">{data ? "Every internet-facing target has an owner." : "Loading…"}</p>}
          {data?.unowned_external?.length ? <p className="an-note">Set owners in the review queue below or in <Link to="/assets">Targets</Link>.</p> : null}
        </section>
      </div>

      <section className="cc-panel sh-section" aria-label="Unsanctioned apps on endpoints">
        <header className="cc-panel__head"><h2>Unsanctioned apps on endpoints ({data?.apps?.length ?? 0})</h2></header>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead>
              <tr><th scope="col">App</th><th scope="col">Category</th><th scope="col">Risk</th><th scope="col">Endpoints</th><th scope="col">Last seen</th></tr>
            </thead>
            <tbody>
              {(data?.apps || []).map((a) => {
                const expanded = openApp === a.key;
                return (
                  <Fragment key={a.key}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} onClick={() => setOpenApp(expanded ? null : a.key)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>{a.name}{a.versions.length ? <span className="so-sub cc-mono"> · v{a.versions.join(", ")}</span> : null}{a.max_count ? <span className="so-sub"> · up to {a.max_count}</span> : null}</span>
                        </button>
                      </td>
                      <td><span className="mc-fam-tag" style={{ "--fam": hex(CATEGORY_COLORS[a.category]) }}>{a.category_label}</span></td>
                      <td><span className={`mc-sev mc-sev--${a.severity === "info" ? "low" : a.severity}`}>{a.severity}</span></td>
                      <td className="cc-mono">{a.endpoint_count}</td>
                      <td className="cc-mono cc-muted">{fmtDate(a.last_seen)}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row">
                        <td colSpan={5}>
                          <div className="mc-detail">
                            <section>
                              <h3>What to do</h3>
                              <p>{a.remediation || "Confirm whether the app is approved. If not, uninstall it and block it through your endpoint or application-control policy."}</p>
                            </section>
                            {a.evidence ? <section><h3>Agent evidence</h3><pre className="fx-proof">{a.evidence}</pre></section> : null}
                            <section>
                              <h3>Endpoints ({a.endpoint_count})</h3>
                              <ul className="mc-targets">{a.endpoints.map((e) => <li key={e}><Link className="cc-mono" to={`/findings?search=${encodeURIComponent(e)}`}>{e}</Link></li>)}</ul>
                              <p className="so-sub">{a.findings} detection{a.findings === 1 ? "" : "s"} · first seen {fmtDate(a.first_seen)}</p>
                              <Link className="cc-btn" to={`/findings?search=${encodeURIComponent(a.name)}`}>Open in Findings</Link>
                            </section>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!data?.apps?.length && <tr><td colSpan={5} className="cc-empty so-empty">{data ? "No unsanctioned apps reported by the endpoint agent." : "Loading…"}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="cc-panel sh-section" aria-label="Discovered device review">
        <header className="cc-panel__head"><h2>Discovered devices</h2></header>
        {reviewNotice ? <p className="mc-ok" role="status">{reviewNotice}</p> : null}
        <div className="mc-filters">
          <div className="cc-range" role="group" aria-label="Review state">
            {["unreviewed", "unsanctioned", "sanctioned"].map((s) => (
              <button key={s} type="button" aria-pressed={tab === s} onClick={() => { setTab(s); setOpenDevice(null); setShowAll(false); }}>
                {STATE_LABEL[s]} {inv ? `(${inv[s]})` : ""}
              </button>
            ))}
          </div>
          <input className="so-input mc-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search address, service or owner" aria-label="Search devices" />
        </div>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead>
              <tr><th scope="col">Device</th><th scope="col">Exposure</th><th scope="col">Services seen</th><th scope="col">Open findings</th><th scope="col">Discovered</th></tr>
            </thead>
            <tbody>
              {(showAll ? devices : devices.slice(0, 15)).map((d) => {
                const expanded = openDevice === d.id;
                return (
                  <Fragment key={d.id}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} onClick={() => setOpenDevice(expanded ? null : d.id)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>
                            <span className="cc-mono">{d.address || d.name}</span>
                            {d.name && d.name !== d.address ? <span className="so-sub"> · {d.name}</span> : null}
                            {d.owner ? <span className="so-sub"> · {d.owner}</span> : null}
                          </span>
                        </button>
                      </td>
                      <td><span className={`sh-exposure sh-exposure--${d.exposure === "external" ? "ext" : "int"}`}>{d.exposure === "external" ? "Internet" : "Internal"}</span></td>
                      <td><span className="sh-chips">{d.services.length ? d.services.slice(0, 5).map((s) => <span key={s} className="ti-chip">{s}</span>) : <span className="cc-muted">—</span>}</span></td>
                      <td><SevMini row={d} /></td>
                      <td className="cc-mono cc-muted">{fmtDate(d.first_seen)}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row">
                        <td colSpan={5}>
                          <div className="mc-detail">
                            <section>
                              <h3>Decide</h3>
                              {canOperate ? <ReviewForm device={d} onDone={onReviewed} /> : <p>Ask an analyst to review this device.</p>}
                            </section>
                            <section>
                              <h3>What we know</h3>
                              <p>
                                Type: {d.type || "unknown"} · {d.open_findings} open finding{d.open_findings === 1 ? "" : "s"}
                                {d.last_seen ? ` · last finding ${fmtDate(d.last_seen)}` : ""}
                              </p>
                              <Link className="cc-btn" to={`/findings?target=${encodeURIComponent(d.address || d.name)}`}>Open its findings</Link>
                            </section>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!devices.length && <tr><td colSpan={5} className="cc-empty so-empty">{data ? (tab === "unreviewed" ? "Nothing left to review." : `No devices marked ${tab}.`) : "Loading…"}</td></tr>}
            </tbody>
          </table>
        </div>
        {devices.length > 15 ? (
          <button type="button" className="cc-btn sh-more" onClick={() => setShowAll((v) => !v)}>
            {showAll ? "Show first 15" : `Show all ${devices.length}`}
          </button>
        ) : null}
      </section>
    </div>
  );
}

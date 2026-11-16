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
import "../software.css";

const POLICY_COLORS = {
  offensive: 0xff3b6b,
  "remote-access": 0xff6b6b,
  p2p: 0xff9f5a,
  crypto: 0xf5d76e,
  "cloud-storage": 0xffc46b,
  "network-tools": 0x5ce1ff,
  games: 0xa78bfa,
  messaging: 0x2e7bff,
};
const RISK_SEV = { high: "high", medium: "medium", low: "low" };
const TABS = [
  ["review", "Needs review"],
  ["risky", "Policy risk"],
  ["approved", "Approved"],
  ["system", "System components"],
  ["all", "All"],
];
const REFRESH_MS = 60_000;

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }) : "—");
const hex = (n) => `#${n.toString(16).padStart(6, "0")}`;
const errText = (err, fallback) => (err?.response?.data?.detail ? String(err.response.data.detail) : fallback);

function Kpi({ label, value, suffix = "", tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value == null ? "—" : `${shown}${suffix}`}</strong>
      {hint ? <small className="an-kpi-hint">{hint}</small> : null}
    </div>
  );
}

function Decision({ product, approvedEntry, canOperate, onDone }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!canOperate) return <p>{product.approved ? `Approved: ${product.approved_reason || "no reason given"}.` : "Ask an analyst to approve or remove this product."}</p>;

  const approve = async () => {
    setBusy(true);
    setError("");
    try {
      await api.post("/software/whitelist", { name: product.name, vendor: product.vendor, reason: reason.trim() || undefined });
      onDone(`${product.name} approved on every endpoint.`);
    } catch (err) {
      setError(errText(err, "Couldn't approve this product."));
    } finally {
      setBusy(false);
    }
  };
  const revoke = async () => {
    if (!approvedEntry) return;
    setBusy(true);
    setError("");
    try {
      await api.delete(`/software/whitelist/${approvedEntry.id}`);
      onDone(`Approval for ${product.name} revoked.`);
    } catch (err) {
      setError(errText(err, "Couldn't revoke the approval."));
    } finally {
      setBusy(false);
    }
  };

  return product.approved ? (
    <div className="sw-decision">
      <p>Approved{product.approved_reason ? `: ${product.approved_reason}` : ""}.</p>
      <button type="button" className="cc-btn sh-btn-bad" disabled={busy || !approvedEntry} onClick={revoke}>Revoke approval</button>
      {error ? <p className="so-error" role="alert">{error}</p> : null}
    </div>
  ) : (
    <div className="sw-decision">
      <label>
        <span>Business reason</span>
        <input className="so-input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Needed by the network team" maxLength={200} />
      </label>
      <button type="button" className="cc-btn sh-btn-ok" disabled={busy} onClick={approve}>Approve product</button>
      <p className="so-sub">Approving covers every version of {product.name}. To remove it, uninstall it on the endpoint; the agent's next report clears it here.</p>
      {error ? <p className="so-error" role="alert">{error}</p> : null}
    </div>
  );
}

export default function UnauthorizedSoftware({ canOperate = false }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("review");
  const [policy, setPolicy] = useState("all");
  const [endpoint, setEndpoint] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);
  const [limit, setLimit] = useState(25);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await api.get("/software/posture");
      setData(res.data);
      setError("");
    } catch {
      setError("Couldn't load the software inventory. Check that the API is running.");
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

  const onDecided = (text) => {
    setNotice(text);
    setOpen(null);
    load();
  };

  const approvedByName = useMemo(() => Object.fromEntries((data?.approved_list || []).map((a) => [a.name, a])), [data]);

  const products = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.products || []).filter((p) => {
      if (tab === "review" && (p.approved || p.system)) return false;
      if (tab === "risky" && (!p.policy || p.approved)) return false;
      if (tab === "approved" && !p.approved) return false;
      if (tab === "system" && !p.system) return false;
      if (policy !== "all" && p.policy !== policy) return false;
      if (endpoint !== "all" && !p.endpoints.includes(endpoint)) return false;
      return !q || `${p.name} ${p.vendor || ""} ${p.endpoints.join(" ")}`.toLowerCase().includes(q);
    });
  }, [data, tab, policy, endpoint, query]);

  const tabCount = (key) => {
    const all = data?.products || [];
    if (key === "review") return all.filter((p) => !p.approved && !p.system).length;
    if (key === "risky") return all.filter((p) => p.policy && !p.approved).length;
    if (key === "approved") return all.filter((p) => p.approved).length;
    if (key === "system") return all.filter((p) => p.system).length;
    return all.length;
  };

  const k = data?.kpis;
  const matrixRows = (data?.matrix?.rows || []).map((r) => ({ ...r, color: POLICY_COLORS[r.key] }));
  const hasMatrix = data?.matrix?.values?.some((row) => row.some(Boolean));

  return (
    <div className="cc sw-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Unauthorized Software</h1>
        </div>
        <div className="cc-top__tools">
          {data ? <time className="cc-clock" dateTime={data.generated_at}>Updated {new Date(data.generated_at).toLocaleTimeString([], { hour12: false })}</time> : null}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
        </div>
      </header>

      {error && <p className="so-error" role="alert">{error}</p>}

      <div className="cc-kpis">
        <Kpi label="Needs review" value={k?.unapproved} tone={k?.unapproved ? "hot" : "live"} hint={k ? `of ${k.products} products` : undefined} />
        <Kpi label="High-risk apps" value={k?.high_risk} tone={k?.high_risk ? "hot" : ""} hint="remote access, hacking, P2P" />
        <Kpi label="Policy-risk apps" value={k?.risky} />
        <Kpi label="Approved products" value={k?.approved} />
        <Kpi label="Baseline coverage" value={k?.baseline_coverage != null ? Math.round(k.baseline_coverage * 100) : null} suffix="%" hint="products on the approved list" />
        <Kpi label="Endpoints reporting" value={k?.endpoints} tone="live" />
      </div>

      <div className="an-grid">
        <section className="cc-panel an-w an-w--wide" aria-label="Policy-risk apps by endpoint">
          <header className="cc-panel__head"><h2>Policy-risk apps · category × endpoint</h2></header>
          {hasMatrix ? (
            <BarField3D
              rows={matrixRows}
              cols={data.matrix.cols}
              values={data.matrix.values}
              caption="Unapproved apps per policy category and endpoint"
              describe={(row, col, value) => <><strong>{value}</strong> {row.label.toLowerCase()} app{value === 1 ? "" : "s"} on <span className="cc-mono">{col}</span></>}
            />
          ) : (
            <p className="cc-empty">{data ? <>No unapproved apps in a policy-risk category. Inventory comes from the endpoint agent — <Link to="/agent-management">deploy it</Link> to more machines.</> : "Loading…"}</p>
          )}
        </section>

        <section className="cc-panel an-w" aria-label="Policy categories">
          <header className="cc-panel__head"><h2>Policy categories</h2></header>
          {data ? (
            <ul className="mc-families">
              {data.policy_classes.map((c) => (
                <li key={c.key}>
                  <button type="button" className={`mc-family${policy === c.key ? " is-active" : ""}`} aria-pressed={policy === c.key} title={c.why}
                    onClick={() => { setPolicy(policy === c.key ? "all" : c.key); setTab("all"); setOpen(null); }}>
                    <span className="cc-swatch" style={{ background: hex(POLICY_COLORS[c.key]) }} />
                    <span className="mc-family__name">{c.label}</span>
                    <span className={`mc-sev mc-sev--${RISK_SEV[c.risk]} sw-risk`}>{c.risk}</span>
                    <span className="cc-mono">{c.products}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">Loading…</p>}
          <p className="an-note">Categories come from the product name and reflect policy, not a known vulnerability. Click one to filter the list.</p>
        </section>

        <section className="cc-panel an-w" aria-label="Endpoints reporting software">
          <header className="cc-panel__head"><h2>Endpoints</h2></header>
          {data?.endpoints?.length ? (
            <ul className="cc-list">
              {data.endpoints.map((e) => (
                <li key={e.endpoint} className="an-overdue">
                  <span className={`cc-dot cc-dot--${e.agent_status === "active" ? "healthy" : "down"}`} aria-hidden="true" />
                  <span className="an-overdue__main">
                    <button type="button" className={`sw-endpoint${endpoint === e.endpoint ? " is-active" : ""}`} aria-pressed={endpoint === e.endpoint}
                      onClick={() => { setEndpoint(endpoint === e.endpoint ? "all" : e.endpoint); setOpen(null); }}>
                      {e.endpoint}
                    </button>
                    <span className="so-sub cc-mono">{e.ip_address || ""}</span>
                    <span className="so-sub">
                      {e.agent_status === "active" ? `Agent active · checked in ${fmtDate(e.agent_last_seen)}` : e.agent_status ? `Agent ${e.agent_status} · inventory may be stale` : "No agent record"}
                    </span>
                  </span>
                  <span className="sw-endpoint__nums">
                    <span><strong className="cc-mono">{e.products}</strong> products</span>
                    <span><strong className="cc-mono">{e.unapproved}</strong> unapproved</span>
                    <span className={e.risky_total ? "an-bad" : ""}><strong className="cc-mono">{e.risky_total}</strong> policy risk</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">{data ? <>No endpoint has reported its software yet. <Link to="/agent-management">Deploy the agent</Link>.</> : "Loading…"}</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Approved products">
          <header className="cc-panel__head"><h2>Approved list ({data?.approved_list?.length ?? 0})</h2></header>
          {data?.approved_list?.length ? (
            <ul className="cc-list">
              {data.approved_list.map((a) => (
                <li key={a.id}>
                  <span className="an-overdue__main">
                    <span>{a.name}</span>
                    <span className="so-sub">{a.reason || "No reason recorded"} · {fmtDate(a.created_at)}</span>
                  </span>
                </li>
              ))}
            </ul>
          ) : <p className="cc-empty">{data ? "Nothing approved yet." : "Loading…"}</p>}
          <p className="an-note">Approve or revoke products from the list below.</p>
        </section>
      </div>

      <section className="cc-panel sh-section" aria-label="Installed software">
        <header className="cc-panel__head"><h2>Installed software ({products.length})</h2></header>
        {notice ? <p className="mc-ok" role="status">{notice}</p> : null}
        <div className="mc-filters">
          <div className="cc-range" role="group" aria-label="Review state">
            {TABS.map(([key, label]) => (
              <button key={key} type="button" aria-pressed={tab === key} onClick={() => { setTab(key); setOpen(null); setLimit(25); }}>
                {label} {data ? `(${tabCount(key)})` : ""}
              </button>
            ))}
          </div>
          <input className="so-input mc-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search product, vendor or endpoint" aria-label="Search software" />
          {policy !== "all" || endpoint !== "all" ? (
            <button type="button" className="cc-btn" onClick={() => { setPolicy("all"); setEndpoint("all"); }}>Clear filters</button>
          ) : null}
        </div>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead>
              <tr><th scope="col">Product</th><th scope="col">Category</th><th scope="col">Status</th><th scope="col">Endpoints</th><th scope="col">First seen</th></tr>
            </thead>
            <tbody>
              {products.slice(0, limit).map((p) => {
                const expanded = open === p.key;
                return (
                  <Fragment key={p.key}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : p.key)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>
                            {p.name}
                            {p.vendor ? <span className="so-sub"> · {p.vendor}</span> : null}
                          </span>
                        </button>
                      </td>
                      <td>
                        {p.policy ? <span className="mc-fam-tag" style={{ "--fam": hex(POLICY_COLORS[p.policy]) }}>{p.policy_label}</span>
                          : p.system ? <span className="cc-muted">System component</span> : <span className="cc-muted">—</span>}
                      </td>
                      <td>
                        {p.approved ? <span className="sw-status sw-status--ok">Approved</span>
                          : p.risk ? <span className={`mc-sev mc-sev--${RISK_SEV[p.risk]}`}>{p.risk} risk</span>
                            : <span className="sw-status">Unreviewed</span>}
                      </td>
                      <td className="cc-mono">{p.endpoint_count}</td>
                      <td className="cc-mono cc-muted">{fmtDate(p.first_seen)}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row">
                        <td colSpan={5}>
                          <div className="mc-detail">
                            <section>
                              <h3>Decision</h3>
                              {p.why ? <p className="sw-why">{p.why}</p> : null}
                              <Decision product={p} approvedEntry={approvedByName[p.approved_name]} canOperate={canOperate} onDone={onDecided} />
                            </section>
                            <section>
                              <h3>Installed</h3>
                              <p>
                                Version{p.versions.length === 1 ? "" : "s"}: <span className="cc-mono">{p.versions.join(", ") || "not reported"}</span>
                              </p>
                              {p.paths.length ? <ul className="sw-paths">{p.paths.map((path) => <li key={path} className="cc-mono">{path}</li>)}</ul> : null}
                              <p className="so-sub">First reported {fmtDate(p.first_seen)} · last reported {fmtDate(p.last_reported)}</p>
                              {p.cves.length ? <p className="an-bad">NVD matches: {p.cves.join(", ")}</p> : null}
                            </section>
                            <section>
                              <h3>Endpoints ({p.endpoint_count})</h3>
                              <ul className="mc-targets">{p.endpoints.map((e) => <li key={e}><button type="button" className="sw-chip cc-mono" onClick={() => { setEndpoint(e); setOpen(null); }}>{e}</button></li>)}</ul>
                            </section>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!products.length && <tr><td colSpan={5} className="cc-empty so-empty">{data ? "No products match." : "Loading…"}</td></tr>}
            </tbody>
          </table>
        </div>
        {products.length > limit ? (
          <button type="button" className="cc-btn sh-more" onClick={() => setLimit((n) => n + 50)}>Show {Math.min(50, products.length - limit)} more</button>
        ) : null}
        {k?.network_services_excluded ? (
          <p className="an-note">
            {k.network_services_excluded} network services found by port scans aren't listed here — they aren't installed programs. See them in <Link to="/findings">Findings</Link> and <Link to="/misconfigurations">Misconfigurations</Link>.
          </p>
        ) : null}
      </section>
    </div>
  );
}

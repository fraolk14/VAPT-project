import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import AssetConstellation from "../components/cc/AssetConstellation";
import { isExternal, isManaged, normalizeCrit, normalizeEnv } from "../components/cc/ccConstants";
import "../commandcenter.css";
import "../targets.css";

const CRITS = ["critical", "high", "medium", "low"];
const EMPTY_FORM = {
  hostname: "",
  ip_address: "",
  url: "",
  os_type: "",
  owner: "",
  environment: "Production",
  criticality: "Medium",
  risk_level: "Medium",
  classification: "Internal",
  asset_type: "OS",
  is_active: true,
};
const TYPE_OPTIONS = [
  { value: "OS", label: "Server / host" },
  { value: "Website", label: "Website / web app" },
  { value: "Network", label: "Network device" },
  { value: "Endpoint", label: "Endpoint" },
];

const titleCase = (v) => String(v || "").replace(/(^|[\s_-])(\w)/g, (_, sep, c) => `${sep === "_" ? " " : sep}${c.toUpperCase()}`);
const errorText = (err, fallback) => {
  if (err?.response?.status === 403) return "You don't have permission to do that. Ask an analyst or admin.";
  const detail = err?.response?.data?.detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return typeof detail === "string" ? detail : fallback;
};
const riskBand = (score) => (score >= 70 ? "high" : score >= 40 ? "medium" : "low");
const targetOf = (asset) => asset.hostname || asset.asset_name || asset.ip_address || asset.url || "unknown";

// ---------- detail drawer ----------

function DetailDrawer({ asset, canOperate, onClose, onEdit, onDelete }) {
  const [details, setDetails] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("findings");
  const closeRef = useRef(null);

  useEffect(() => {
    let ignore = false;
    api.get(`/assets/${asset.id}/details`)
      .then((res) => { if (!ignore) setDetails(res.data); })
      .catch(() => { if (!ignore) setError("Couldn't load details for this target."); });
    closeRef.current?.focus();
    const onKey = (event) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => {
      ignore = true;
      document.removeEventListener("keydown", onKey);
    };
  }, [asset.id, onClose]);

  const findings = [...(details?.other_findings || []), ...(details?.shadow_it || [])];
  const misconfigs = details?.misconfigurations || [];
  const software = details?.installed_software || [];
  const unauthorized = details?.unauthorized_software || [];
  const agent = details?.agent_device;
  const tabs = [
    { key: "findings", label: "Findings", count: findings.length },
    { key: "misconfig", label: "Misconfigurations", count: misconfigs.length },
    { key: "software", label: "Software", count: software.length + unauthorized.length },
    { key: "agent", label: "Agent", count: agent ? 1 : 0 },
  ];

  return (
    <div className="ti-drawer-backdrop" onClick={onClose}>
      <aside
        className="ti-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ti-drawer-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="ti-drawer__head">
          <div>
            <span className={`ti-crit ti-crit--${normalizeCrit(asset.criticality)}`}>{normalizeCrit(asset.criticality)}</span>
            <h2 id="ti-drawer-title">{targetOf(asset)}</h2>
            <p className="cc-mono cc-muted">{[asset.ip_address, asset.url].filter(Boolean).join(" · ")}</p>
          </div>
          <button ref={closeRef} type="button" className="cc-icon" aria-label="Close details" onClick={onClose}>×</button>
        </header>

        <dl className="ti-facts">
          <div><dt>Type</dt><dd>{titleCase(asset.asset_type)}</dd></div>
          <div><dt>Environment</dt><dd>{titleCase(normalizeEnv(asset.environment))}</dd></div>
          <div><dt>Exposure</dt><dd>{isExternal(asset) ? "External" : "Internal"}</dd></div>
          <div><dt>Risk score</dt><dd className="cc-mono">{Number(asset.risk_score || 0).toFixed(1)}</dd></div>
          <div><dt>Operating system</dt><dd>{asset.os_type || asset.os || "—"}</dd></div>
          <div><dt>Owner</dt><dd>{asset.owner || "Unassigned"}</dd></div>
        </dl>

        <div className="ti-drawer__actions">
          <Link className="cc-btn" to={`/findings?target=${encodeURIComponent(asset.url || asset.ip_address || asset.hostname)}`}>Open in Findings</Link>
          {canOperate && <button type="button" className="cc-btn" onClick={() => onEdit(asset)}>Edit</button>}
          {canOperate && <button type="button" className="cc-btn so-danger" onClick={() => onDelete(asset)}>Delete</button>}
        </div>

        <div className="cc-range ti-tabs" role="tablist" aria-label="Target details">
          {tabs.map((t) => (
            <button
              key={t.key}
              type="button"
              role="tab"
              aria-selected={tab === t.key}
              aria-pressed={tab === t.key}
              onClick={() => setTab(t.key)}
            >
              {t.label} <span className="cc-muted">{t.count}</span>
            </button>
          ))}
        </div>

        <div className="ti-drawer__body" role="tabpanel">
          {error && <p className="so-error">{error}</p>}
          {!details && !error && <p className="cc-empty">Loading…</p>}

          {details && tab === "findings" && (
            findings.length ? (
              <ul className="ti-items">
                {findings.map((f) => (
                  <li key={f.id}>
                    <span className={`nw-sev nw-sev--${String(f.severity || "info").toLowerCase()}`}>{f.severity || "info"}</span>
                    <div>
                      <Link to={`/findings/${f.id}`} className="ti-item__title">{f.title}</Link>
                      <div className="cc-muted">{f.source}{f.cve_id ? ` · ${f.cve_id}` : ""}{f.status ? ` · ${String(f.status).replace(/_/g, " ")}` : ""}</div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : <p className="cc-empty">No findings recorded for this target.</p>
          )}

          {details && tab === "misconfig" && (
            misconfigs.length ? (
              <ul className="ti-items">
                {misconfigs.map((m) => (
                  <li key={m.id}>
                    <span className={`nw-sev nw-sev--${String(m.severity || "info").toLowerCase()}`}>{m.severity}</span>
                    <div>
                      <span className="ti-item__title">{m.issue}</span>
                      <div className="cc-muted">{m.detected_by}{m.cve ? ` · ${m.cve}` : ""} · {m.status}</div>
                      {m.remediation && <p className="ti-item__fix">{m.remediation}</p>}
                    </div>
                  </li>
                ))}
              </ul>
            ) : <p className="cc-empty">No misconfigurations recorded.</p>
          )}

          {details && tab === "software" && (
            software.length || unauthorized.length ? (
              <ul className="ti-items">
                {unauthorized.map((s) => (
                  <li key={`u-${s.id}`}>
                    <span className="nw-sev nw-sev--high">Unauth.</span>
                    <div><span className="ti-item__title">{s.name}</span><div className="cc-muted">{[s.vendor, s.version].filter(Boolean).join(" · ")}</div></div>
                  </li>
                ))}
                {software.map((s) => (
                  <li key={`s-${s.id}`}>
                    <span className="nw-sev nw-sev--info">{s.status || "seen"}</span>
                    <div><span className="ti-item__title">{s.name}</span><div className="cc-muted">{[s.vendor, s.version].filter(Boolean).join(" · ")}</div></div>
                  </li>
                ))}
              </ul>
            ) : <p className="cc-empty">No software inventory. Install the endpoint agent to collect it.</p>
          )}

          {details && tab === "agent" && (
            agent ? (
              <dl className="ti-facts">
                <div><dt>Device</dt><dd className="cc-mono">{agent.device_id}</dd></div>
                <div><dt>Status</dt><dd>{agent.status}</dd></div>
                <div><dt>IP</dt><dd className="cc-mono">{agent.ip_address || "—"}</dd></div>
                <div><dt>OS</dt><dd>{agent.os_info || "—"}</dd></div>
                <div><dt>Last check-in</dt><dd>{agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "—"}</dd></div>
              </dl>
            ) : <p className="cc-empty">No endpoint agent on this target. <Link to="/agent-management">Deploy one</Link> to collect software and configuration data.</p>
          )}
        </div>
      </aside>
    </div>
  );
}

// ---------- create / edit form ----------

function TargetForm({ initial, mode, onCancel, onSaved }) {
  const [form, setForm] = useState(initial);
  const [authorized, setAuthorized] = useState(mode === "edit");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const set = (key) => (event) => setForm((f) => ({ ...f, [key]: event.target.type === "checkbox" ? event.target.checked : event.target.value }));

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const res = mode === "edit" ? await api.put(`/assets/${initial.id}`, form) : await api.post("/assets/", form);
      onSaved(res.data, mode);
    } catch (err) {
      setError(errorText(err, mode === "edit" ? "Couldn't save the target." : "Couldn't add the target."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="ti-drawer-backdrop" onClick={onCancel}>
      <form
        className="ti-drawer ti-form"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ti-form-title"
        onClick={(event) => event.stopPropagation()}
        onSubmit={submit}
      >
        <header className="ti-drawer__head">
          <h2 id="ti-form-title">{mode === "edit" ? "Edit target" : "Add a target"}</h2>
          <button type="button" className="cc-icon" aria-label="Close" onClick={onCancel}>×</button>
        </header>

        <div className="ti-form__grid">
          <label className="so-field">Hostname or name<input className="so-input" value={form.hostname} onChange={set("hostname")} required /></label>
          <label className="so-field">IP address<input className="so-input cc-mono" value={form.ip_address} onChange={set("ip_address")} placeholder="10.0.0.12" /></label>
          <label className="so-field ti-span">URL (web targets)<input className="so-input cc-mono" value={form.url || ""} onChange={set("url")} placeholder="https://app.example.com" /></label>
          <label className="so-field">Type
            <select className="so-input" value={form.asset_type} onChange={set("asset_type")}>
              {TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </label>
          <label className="so-field">Environment
            <select className="so-input" value={form.environment} onChange={set("environment")}>
              {["Production", "Staging", "Development", "Test"].map((v) => <option key={v}>{v}</option>)}
            </select>
          </label>
          <label className="so-field">Exposure
            <select className="so-input" value={form.classification} onChange={set("classification")}>
              <option value="Internal">Internal</option>
              <option value="External">External (internet-facing)</option>
            </select>
          </label>
          <label className="so-field">Business criticality
            <select className="so-input" value={form.criticality} onChange={set("criticality")}>
              {["Critical", "High", "Medium", "Low"].map((v) => <option key={v}>{v}</option>)}
            </select>
          </label>
          <label className="so-field">Operating system<input className="so-input" value={form.os_type || ""} onChange={set("os_type")} placeholder="Ubuntu 22.04" /></label>
          <label className="so-field">Owner (email)<input className="so-input" type="email" value={form.owner || ""} onChange={set("owner")} placeholder="owner@example.com" /></label>
        </div>

        {mode === "create" && (
          <label className="cc-check so-consent ti-consent">
            <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
            Adding a target starts a discovery scan against it right away. I'm authorized to test it.
          </label>
        )}
        {error && <p className="so-error" role="alert">{error}</p>}

        <div className="ti-drawer__actions">
          <button type="submit" className="so-launch-btn" disabled={saving || !authorized}>
            {saving ? "Saving…" : mode === "edit" ? "Save changes" : "Add target and scan"}
          </button>
          <button type="button" className="cc-btn" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </div>
  );
}

// ---------- page ----------

export default function Assets({ assets: propAssets = [], canOperate = true }) {
  const [assets, setAssets] = useState(propAssets);
  const [query, setQuery] = useState("");
  const [exposure, setExposure] = useState("all");
  const [type, setType] = useState("all");
  const [crit, setCrit] = useState("all");
  const [managedOnly, setManagedOnly] = useState(false);
  const [sort, setSort] = useState({ key: "risk", dir: "desc" });
  const [limit, setLimit] = useState(25);
  const [selected, setSelected] = useState(null);
  const [formState, setFormState] = useState(null);
  const [notice, setNotice] = useState(null);
  const closeDetails = useCallback(() => setSelected(null), []);

  useEffect(() => {
    if (propAssets.length) setAssets(propAssets);
  }, [propAssets]);

  const refresh = async () => {
    try {
      const res = await api.get("/assets/");
      setAssets(res.data || []);
    } catch {
      setNotice({ ok: false, text: "Couldn't refresh targets." });
    }
  };

  useEffect(() => {
    if (!propAssets.length) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stats = useMemo(() => ({
    total: assets.length,
    external: assets.filter(isExternal).length,
    managed: assets.filter(isManaged).length,
    critical: assets.filter((a) => normalizeCrit(a.criticality) === "critical").length,
    highRisk: assets.filter((a) => Number(a.risk_score || 0) >= 70).length,
  }), [assets]);

  const matrix = useMemo(() => {
    const cells = {};
    CRITS.forEach((c) => { cells[c] = { external: 0, internal: 0 }; });
    assets.forEach((a) => { cells[normalizeCrit(a.criticality)][isExternal(a) ? "external" : "internal"] += 1; });
    return cells;
  }, [assets]);

  const types = useMemo(() => [...new Set(assets.map((a) => a.asset_type).filter(Boolean))].sort(), [assets]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = assets.filter((a) => {
      if (exposure !== "all" && (exposure === "external") !== isExternal(a)) return false;
      if (type !== "all" && a.asset_type !== type) return false;
      if (crit !== "all" && normalizeCrit(a.criticality) !== crit) return false;
      if (managedOnly && !isManaged(a)) return false;
      if (!needle) return true;
      return `${a.hostname} ${a.asset_name} ${a.ip_address} ${a.url} ${a.owner} ${a.os_type} ${a.os}`.toLowerCase().includes(needle);
    });
    const critRank = { critical: 0, high: 1, medium: 2, low: 3 };
    const value = (a) => {
      if (sort.key === "risk") return Number(a.risk_score || 0);
      if (sort.key === "crit") return -critRank[normalizeCrit(a.criticality)];
      if (sort.key === "name") return targetOf(a).toLowerCase();
      if (sort.key === "env") return normalizeEnv(a.environment);
      return 0;
    };
    return filtered.sort((x, y) => {
      const a = value(x);
      const b = value(y);
      const cmp = a < b ? -1 : a > b ? 1 : 0;
      return sort.dir === "asc" ? cmp : -cmp;
    });
  }, [assets, query, exposure, type, crit, managedOnly, sort]);

  const toggleSort = (key) => setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "name" || key === "env" ? "asc" : "desc" }));
  const ariaSort = (key) => (sort.key === key ? (sort.dir === "asc" ? "ascending" : "descending") : "none");
  const sortBtn = (label, key) => (
    <button type="button" className="fx-sort" onClick={() => toggleSort(key)}>
      {label}<span aria-hidden="true">{sort.key === key ? (sort.dir === "asc" ? "↑" : "↓") : "↕"}</span>
    </button>
  );

  const handleDelete = async (asset) => {
    if (!window.confirm(`Delete target "${targetOf(asset)}"? Its scan history stays, but it leaves the inventory.`)) return;
    try {
      await api.delete(`/assets/${asset.id}`);
      setAssets((list) => list.filter((a) => a.id !== asset.id));
      setSelected(null);
      setNotice({ ok: true, text: `Deleted ${targetOf(asset)}.` });
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't delete the target.") });
    }
  };

  const handleSaved = (saved, mode) => {
    setAssets((list) => (mode === "edit" ? list.map((a) => (a.id === saved.id ? saved : a)) : [saved, ...list]));
    setFormState(null);
    setSelected(mode === "edit" ? saved : null);
    setNotice({ ok: true, text: mode === "edit" ? `Saved ${targetOf(saved)}.` : `Added ${targetOf(saved)}. A discovery scan has started — follow it on the Scans page.` });
  };

  return (
    <div className="cc ti">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Target Inventory</h1>
        </div>
        <div className="cc-top__tools">
          <button type="button" className="cc-btn" onClick={refresh}>Refresh</button>
          {canOperate && (
            <button type="button" className="cc-btn cc-btn--primary" onClick={() => setFormState({ mode: "create", initial: EMPTY_FORM })}>
              + Add target
            </button>
          )}
        </div>
      </header>

      <div className="cc-kpis">
        <div className="cc-kpi"><span>Targets</span><strong>{stats.total}</strong></div>
        <div className="cc-kpi cc-kpi--hot"><span>Internet-facing</span><strong>{stats.external}</strong></div>
        <div className="cc-kpi cc-kpi--live"><span>Agent-managed</span><strong>{stats.managed}</strong></div>
        <div className="cc-kpi"><span>Business-critical</span><strong>{stats.critical}</strong></div>
        <div className="cc-kpi cc-kpi--hot"><span>Risk score ≥ 70</span><strong>{stats.highRisk}</strong></div>
      </div>

      {notice && (
        <div className={`so-notice${notice.ok ? "" : " so-notice--error"}`} role="status">
          <span>{notice.text}</span>
          <button type="button" className="cc-icon" aria-label="Dismiss" onClick={() => setNotice(null)}>×</button>
        </div>
      )}

      <div className="cc-grid">
        <section className="cc-panel cc-col--center" aria-label="Target constellation">
          <header className="cc-panel__head">
            <h2>Target constellation</h2>
            <span className="cc-muted">rings by environment · size by risk · raised = internet-facing</span>
          </header>
          <div className="ti-constellation-wrap">
            <AssetConstellation assets={assets} />
            <ul className="cc-legend">
              {CRITS.map((c) => <li key={c}><span className={`cc-swatch cc-swatch--${c}`} />{c}</li>)}
            </ul>
          </div>
        </section>

        <section className="cc-panel cc-col--side" aria-label="Risk matrix">
          <header className="cc-panel__head">
            <h2>Risk matrix</h2>
            <span className="cc-muted">click a cell to filter</span>
          </header>
          <table className="ti-matrix">
            <thead>
              <tr><th scope="col"><span className="cc-sr">Criticality</span></th><th scope="col">Internet-facing</th><th scope="col">Internal</th></tr>
            </thead>
            <tbody>
              {CRITS.map((c) => (
                <tr key={c}>
                  <th scope="row"><span className={`ti-crit ti-crit--${c}`}>{c}</span></th>
                  {["external", "internal"].map((side) => {
                    const n = matrix[c][side];
                    const heat = c === "critical" || c === "high" ? (side === "external" ? 3 : 2) : side === "external" ? 2 : 1;
                    const active = crit === c && exposure === side;
                    return (
                      <td key={side}>
                        <button
                          type="button"
                          className={`ti-cell ti-cell--h${n ? heat : 0}${active ? " is-active" : ""}`}
                          aria-pressed={active}
                          aria-label={`${n} ${c} ${side === "external" ? "internet-facing" : "internal"} targets`}
                          onClick={() => {
                            if (active) { setCrit("all"); setExposure("all"); } else { setCrit(c); setExposure(side); }
                          }}
                        >
                          {n}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="cc-muted ti-matrix__note">Top-left is where an attacker looks first: business-critical and reachable from the internet.</p>
        </section>
      </div>

      <section className="cc-panel ti-inventory" aria-label="Inventory">
        <header className="cc-panel__head">
          <h2>Inventory</h2>
          <span className="cc-muted">{rows.length} of {assets.length}</span>
        </header>

        <div className="so-filters">
          <label className="so-search">
            <span className="cc-sr">Search targets</span>
            <input type="search" placeholder="Search name, IP, URL, owner or OS" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <div className="cc-range" role="group" aria-label="Exposure">
            {["all", "external", "internal"].map((k) => (
              <button key={k} type="button" aria-pressed={exposure === k} onClick={() => setExposure(k)}>
                {k === "all" ? "All" : k === "external" ? "Internet-facing" : "Internal"}
              </button>
            ))}
          </div>
          <label>
            <span className="cc-sr">Type</span>
            <select className="so-input ti-select" value={type} onChange={(e) => setType(e.target.value)}>
              <option value="all">Any type</option>
              {types.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}
            </select>
          </label>
          <label>
            <span className="cc-sr">Criticality</span>
            <select className="so-input ti-select" value={crit} onChange={(e) => setCrit(e.target.value)}>
              <option value="all">Any criticality</option>
              {CRITS.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
            </select>
          </label>
          <label className="cc-check">
            <input type="checkbox" checked={managedOnly} onChange={(e) => setManagedOnly(e.target.checked)} />
            Agent-managed only
          </label>
        </div>

        <div className="so-table-wrap">
          <table className="so-table">
            <thead>
              <tr>
                <th scope="col" aria-sort={ariaSort("name")}>{sortBtn("Target", "name")}</th>
                <th scope="col">Type</th>
                <th scope="col" aria-sort={ariaSort("env")}>{sortBtn("Environment", "env")}</th>
                <th scope="col">Exposure</th>
                <th scope="col" aria-sort={ariaSort("crit")}>{sortBtn("Criticality", "crit")}</th>
                <th scope="col" aria-sort={ariaSort("risk")}>{sortBtn("Risk", "risk")}</th>
                <th scope="col">Owner</th>
                <th scope="col"><span className="cc-sr">Details</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, limit).map((a) => {
                const score = Math.max(0, Math.min(100, Number(a.risk_score || 0)));
                return (
                  <tr key={a.id}>
                    <td>
                      <button type="button" className="ti-name" onClick={() => setSelected(a)}>{targetOf(a)}</button>
                      <div className="cc-mono so-sub">{[a.ip_address, a.url].filter(Boolean).join(" · ")}</div>
                      {isManaged(a) && <span className="ti-badge">agent</span>}
                    </td>
                    <td>{titleCase(a.asset_type)}</td>
                    <td>{titleCase(normalizeEnv(a.environment))}</td>
                    <td>{isExternal(a) ? <span className="ti-ext">Internet-facing</span> : <span className="cc-muted">Internal</span>}</td>
                    <td><span className={`ti-crit ti-crit--${normalizeCrit(a.criticality)}`}>{normalizeCrit(a.criticality)}</span></td>
                    <td>
                      <div className="ti-risk">
                        <div className="ti-risk__track" aria-hidden="true"><span className={`ti-risk__fill ti-risk__fill--${riskBand(score)}`} style={{ width: `${score}%` }} /></div>
                        <span className="cc-mono">{score.toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="so-sub">{a.owner || "Unassigned"}</td>
                    <td className="so-actions"><button type="button" className="cc-btn" aria-label={`Details for ${targetOf(a)}`} onClick={() => setSelected(a)}>Details</button></td>
                  </tr>
                );
              })}
              {!rows.length && (
                <tr><td colSpan={8} className="cc-empty so-empty">{assets.length ? "No targets match these filters." : "No targets yet. Add one, or run a scan to discover them."}</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {rows.length > limit && (
          <button type="button" className="cc-btn so-showmore" onClick={() => setLimit((n) => n + 50)}>Show more ({rows.length - limit} remaining)</button>
        )}
      </section>

      {selected && !formState && (
        <DetailDrawer
          asset={selected}
          canOperate={canOperate}
          onClose={closeDetails}
          onEdit={(asset) => setFormState({ mode: "edit", initial: { ...EMPTY_FORM, ...asset } })}
          onDelete={handleDelete}
        />
      )}
      {formState && (
        <TargetForm
          mode={formState.mode}
          initial={formState.initial}
          onCancel={() => setFormState(null)}
          onSaved={handleSaved}
        />
      )}
    </div>
  );
}

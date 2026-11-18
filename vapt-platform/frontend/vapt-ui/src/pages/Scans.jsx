import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import "../commandcenter.css";
import "../scans.css";

// Report downloads must go through the API client so the bearer token is sent.
async function downloadScanReport(scanId) {
  try {
    const res = await api.get(`/reports/v1/download/${scanId}`, {
      params: { format: "pdf", type: "executive" },
      responseType: "blob",
    });
    const url = window.URL.createObjectURL(res.data);
    const link = document.createElement("a");
    link.href = url;
    link.download = `VAPT_Report_${scanId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch {
    window.alert("Report download failed. Please try again.");
  }
}

// ---------- engines ----------

const ENGINES = {
  web: {
    name: "Web",
    engine: "ZAP",
    health: "zap",
    tools: ["zap"],
    endpoint: "/scans/web",
    targetLabel: "Website URL",
    placeholder: "https://app.example.com",
    help: "Spiders the site, then actively tests every page for SQL injection, XSS, SSRF and more.",
    duration: "Usually 5–20 minutes, longer for large sites.",
    phases: ["Queued", "Spider", "Active scan", "Ingest"],
  },
  network: {
    name: "Network",
    engine: "Nmap",
    health: null,
    tools: ["openvas", "nmap"],
    endpoint: "/scans/network",
    targetLabel: "IP address, domain or CIDR (max /24)",
    placeholder: "192.168.1.10 or 10.0.0.0/24",
    help: "Discovers open ports, fingerprints services and correlates versions with known CVEs.",
    duration: "About 2–5 minutes per host; a /24 can take 20+ minutes.",
    phases: ["Queued", "Discovery", "Service detection", "Correlation"],
  },
  mobile: {
    name: "Mobile",
    engine: "MobSF",
    health: "mobsf",
    tools: ["mobsf"],
    endpoint: "/scans/mobile",
    targetLabel: "App package (.apk, .aab or .ipa)",
    placeholder: "",
    help: "Static analysis of the app package: permissions, secrets, insecure transport, code issues.",
    duration: "Usually 1–5 minutes.",
    phases: ["Queued", "Upload", "Static analysis", "Ingest"],
  },
};

const ACTIVE = new Set(["running", "queued", "waiting"]);

const engineKeyOf = (scan) => {
  const tool = String(scan.tool || "").toLowerCase();
  if (tool === "zap" || scan.scan_type === "web") return "web";
  if (tool === "mobsf" || scan.scan_type === "mobile") return "mobile";
  return "network";
};

function phaseIndex(scan) {
  const status = String(scan.status || "").toLowerCase();
  const meta = scan.engine_metadata || {};
  const pct = Number(scan.progress) || 0;
  if (status === "waiting" || status === "queued") return 0;
  if (status === "completed") return 4;
  const kind = engineKeyOf(scan);
  if (kind === "web") {
    if (meta.phase === "spider") return 1;
    if (meta.phase === "active") return pct >= 99 ? 3 : 2;
    return 1;
  }
  if (pct >= 90) return 3;
  if (pct >= 40) return 2;
  return 1;
}

const fmtDuration = (startIso, endIso) => {
  const start = startIso ? new Date(startIso).getTime() : NaN;
  const end = endIso ? new Date(endIso).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return "—";
  const s = Math.round((end - start) / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
};

// "balanced · crawl 1m · active 3m · Nuclei 4m (alongside)" from engine_metadata.timings
const STAGE_LABELS = [["crawl_seconds", "crawl"], ["katana_seconds", "Katana"], ["active_seconds", "active"], ["nuclei_seconds", "Nuclei"], ["testssl_seconds", "TLS"]];
const fmtSecs = (s) => (s < 60 ? `${s}s` : `${Math.round(s / 60)}m`);
function stageSummary(scan) {
  const meta = scan.engine_metadata || {};
  const t = meta.timings || {};
  const parts = STAGE_LABELS.filter(([k]) => t[k] > 0).map(([k, label]) => `${label} ${fmtSecs(t[k])}`);
  if (!parts.length) return meta.pace_effective || "";
  return [meta.pace_effective, ...parts].filter(Boolean).join(" · ") + (meta.pipeline?.parallel ? " (Nuclei alongside ZAP)" : "");
}

const fmtWhen = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
    : d.toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
};

const errorText = (err, fallback) => {
  const detail = err?.response?.data?.detail;
  if (err?.response?.status === 403) return "You don't have permission to do that. Ask an analyst or admin.";
  if (err?.response?.status === 413 && typeof detail !== "string") return "The file is too large to upload. The limit is 200 MB.";
  if (err?.response?.status === 401) return "Your session ended. Sign in again and retry.";
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return typeof detail === "string" ? detail : fallback;
};

// ---------- page ----------

export default function Scans({ integrations = {}, canOperate = true }) {
  const [engineKey, setEngineKey] = useState("web");
  const [target, setTarget] = useState("");
  const [file, setFile] = useState(null);
  const [label, setLabel] = useState("");
  const [pace, setPace] = useState("auto");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState(null);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [kindFilter, setKindFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(15);
  const fileRef = useRef(null);

  const cfg = ENGINES[engineKey];

  const fetchScans = useCallback(async () => {
    try {
      const res = await api.get("/scans/");
      setScans(Array.isArray(res.data) ? res.data : []);
    } catch {
      // Keep the last list on a transient error.
    } finally {
      setLoading(false);
    }
  }, []);

  const hasActive = scans.some((s) => ACTIVE.has(String(s.status).toLowerCase()) || String(s.status).toLowerCase() === "paused");

  // Poll quickly only while something is running; otherwise every 30 seconds.
  useEffect(() => {
    const first = window.setTimeout(fetchScans, 0);
    const id = window.setInterval(() => {
      if (!document.hidden) fetchScans();
    }, hasActive ? 5000 : 30000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [fetchScans, hasActive]);

  const engineState = (key) => {
    const e = ENGINES[key];
    const running = scans.some((s) => ACTIVE.has(String(s.status).toLowerCase()) && e.tools.includes(String(s.tool).toLowerCase()));
    const healthy = e.health ? Boolean(integrations?.[e.health]?.healthy) : true;
    if (running) return "active";
    return healthy ? "healthy" : "down";
  };

  const pickEngine = (key) => {
    setEngineKey(key);
    setTarget("");
    setFile(null);
    setNotice(null);
  };

  const act = async (fn, okText, failText) => {
    try {
      await fn();
      setNotice({ ok: true, text: okText });
      fetchScans();
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, failText) });
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!authorized) {
      setNotice({ ok: false, text: "Confirm you are authorized to test this target." });
      return;
    }
    setSubmitting(true);
    setNotice(null);
    try {
      if (engineKey === "mobile") {
        if (!file) throw new Error("Choose an .apk, .aab or .ipa file.");
        const form = new FormData();
        form.append("file", file);
        if (label.trim()) form.append("label", label.trim());
        await api.post(cfg.endpoint, form);
        setNotice({ ok: true, text: `Mobile scan of ${file.name} queued.` });
      } else {
        const t = target.trim();
        if (!t) throw new Error("Enter a target.");
        await api.post(cfg.endpoint, { target: t, label: label.trim() || undefined, ...(engineKey === "web" ? { pace } : {}) });
        setNotice({ ok: true, text: `${cfg.name} scan of ${t} queued. ${cfg.duration}` });
      }
      setTarget("");
      setFile(null);
      setLabel("");
      setAuthorized(false);
      if (fileRef.current) fileRef.current.value = "";
      fetchScans();
    } catch (err) {
      setNotice({ ok: false, text: err?.response ? errorText(err, `Couldn't launch the ${cfg.name.toLowerCase()} scan.`) : err.message });
    } finally {
      setSubmitting(false);
    }
  };

  const visible = scans.filter((s) => String(s.status).toLowerCase() !== "cancelled");
  const live = visible.filter((s) => ACTIVE.has(String(s.status).toLowerCase()) || String(s.status).toLowerCase() === "paused");

  const counts = useMemo(() => {
    const dayAgo = Date.now() - 86400e3;
    const recent = (s) => new Date(s.finished_at || s.started_at || 0).getTime() >= dayAgo;
    return {
      running: visible.filter((s) => String(s.status).toLowerCase() === "running").length,
      queued: visible.filter((s) => ["queued", "waiting"].includes(String(s.status).toLowerCase())).length,
      done: visible.filter((s) => String(s.status).toLowerCase() === "completed" && recent(s)).length,
      failed: visible.filter((s) => String(s.status).toLowerCase() === "failed" && recent(s)).length,
    };
  }, [visible]);

  const history = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return visible
      .filter((s) => !ACTIVE.has(String(s.status).toLowerCase()) && String(s.status).toLowerCase() !== "paused")
      .filter((s) => kindFilter === "all" || engineKeyOf(s) === kindFilter)
      .filter((s) => statusFilter === "all" || String(s.status).toLowerCase() === statusFilter)
      .filter((s) => !needle || `${s.scan_name} ${s.target}`.toLowerCase().includes(needle))
      .sort((a, b) => new Date(b.finished_at || b.started_at || 0) - new Date(a.finished_at || a.started_at || 0));
  }, [visible, kindFilter, statusFilter, query]);

  return (
    <div className="cc so">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Scan Operations</h1>
        </div>
        <div className="cc-top__tools">
          <button type="button" className="cc-btn" onClick={fetchScans}>Refresh</button>
        </div>
      </header>

      <div className="cc-kpis">
        <div className="cc-kpi cc-kpi--live"><span>Running</span><strong>{counts.running}</strong></div>
        <div className="cc-kpi"><span>Queued</span><strong>{counts.queued}</strong></div>
        <div className="cc-kpi"><span>Completed · 24 hr</span><strong>{counts.done}</strong></div>
        <div className={`cc-kpi${counts.failed ? " cc-kpi--hot" : ""}`}><span>Failed · 24 hr</span><strong>{counts.failed}</strong></div>
      </div>

      {notice && (
        <div className={`so-notice${notice.ok ? "" : " so-notice--error"}`} role="status">
          <span>{notice.text}</span>
          <button type="button" className="cc-icon" aria-label="Dismiss" onClick={() => setNotice(null)}>×</button>
        </div>
      )}

      <div className="cc-grid">
        {/* ---------- Launch console ---------- */}
        <section className="cc-panel so-launch cc-col--side" aria-label="Launch a scan">
          <header className="cc-panel__head"><h2>Launch a scan</h2></header>

          <div className="so-engines" role="radiogroup" aria-label="Scan engine">
            {Object.entries(ENGINES).map(([key, e]) => {
              const state = engineState(key);
              return (
                <button
                  key={key}
                  type="button"
                  role="radio"
                  aria-checked={engineKey === key}
                  aria-label={`${e.name} scan with ${e.engine}, ${state === "active" ? "scanning" : state === "healthy" ? "ready" : "offline"}`}
                  className="so-engine"
                  onClick={() => pickEngine(key)}
                >
                  <span className="so-engine__name">{e.name}</span>
                  <span className="so-engine__tool">{e.engine}</span>
                  <span className={`so-engine__state cc-state--${state}`}>
                    <span className={`cc-dot cc-dot--${state}`} />
                    {state === "active" ? "Scanning" : state === "healthy" ? "Ready" : "Offline"}
                  </span>
                </button>
              );
            })}
          </div>

          <p className="so-help">{cfg.help}</p>

          {canOperate ? (
            <form className="so-form" onSubmit={handleSubmit}>
              {engineKey === "mobile" ? (
                <label className="so-field">
                  <span>{cfg.targetLabel}</span>
                  <input
                    ref={fileRef}
                    type="file"
                    aria-label={cfg.targetLabel}
                    accept=".apk,.aab,.ipa"
                    className="so-file"
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                  />
                </label>
              ) : (
                <label className="so-field">
                  <span>{cfg.targetLabel}</span>
                  <input
                    type="text"
                    aria-label={cfg.targetLabel}
                    className="so-input cc-mono"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={cfg.placeholder}
                    autoComplete="off"
                    spellCheck="false"
                    required
                  />
                </label>
              )}
              {engineKey === "web" && (
                <label className="so-field">
                  <span>Speed</span>
                  <select className="so-input" aria-label="Scan speed" value={pace} onChange={(e) => setPace(e.target.value)}>
                    <option value="auto">Auto: fast for internal hosts, balanced for public sites</option>
                    <option value="balanced">Balanced: public sites behind a CDN or hosting firewall</option>
                    <option value="polite">Polite: strict hosts that rate-limit or ban scanners</option>
                    <option value="fast">Fast: systems you own that won't block the scanner</option>
                  </select>
                </label>
              )}
              <label className="so-field">
                <span>Label <em>(optional)</em></span>
                <input type="text" aria-label="Scan label (optional)" className="so-input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Quarterly external test" />
              </label>
              <label className="cc-check so-consent">
                <input type="checkbox" aria-label="I'm authorized to test this target" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
                I'm authorized to test this target.
              </label>
              <p className="so-duration">{cfg.duration}</p>
              <button type="submit" className="so-launch-btn" disabled={submitting || !authorized}>
                {submitting ? "Queuing…" : `Launch ${cfg.name.toLowerCase()} scan`}
              </button>
            </form>
          ) : (
            <p className="cc-empty">Read-only access: an analyst or admin can launch scans.</p>
          )}
        </section>

        {/* ---------- Live operations ---------- */}
        <section className="cc-panel so-live cc-col--center" aria-label="Live operations">
          <header className="cc-panel__head">
            <h2>Live operations</h2>
            <span className="cc-muted">{live.length ? `${live.length} in progress · updates every 5s` : "Idle"}</span>
          </header>
          {live.length ? (
            <div className="so-live__list">
              {live.map((scan) => {
                const kind = engineKeyOf(scan);
                const e = ENGINES[kind];
                const status = String(scan.status).toLowerCase();
                const paused = status === "paused";
                const pct = Math.max(0, Math.min(100, Number(scan.progress) || 0));
                const step = phaseIndex(scan);
                return (
                  <article key={scan.id} className={`so-op${paused ? " is-paused" : ""}`}>
                    <div className="so-radar" aria-hidden="true"><span /></div>
                    <div className="so-op__body">
                      <div className="so-op__head">
                        <div>
                          <strong>{scan.scan_name || `${e.name} scan`}</strong>
                          <div className="cc-mono so-op__target">{scan.target}</div>
                        </div>
                        <span className="so-op__pct cc-mono">{paused ? "Paused" : `${pct}%`}</span>
                      </div>
                      <ol className="so-steps" aria-label="Scan phases">
                        {e.phases.map((p, i) => (
                          <li key={p} className={i < step ? "is-done" : i === step ? "is-now" : ""}>{p}</li>
                        ))}
                      </ol>
                      <div className="cc-progress" role="progressbar" aria-label={`Progress for ${scan.target}`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
                        <span style={{ width: `${pct}%` }} />
                      </div>
                      <div className="so-op__foot">
                        <span className="cc-muted">{e.engine} · running {fmtDuration(scan.started_at, null)}</span>
                        {canOperate && (
                          <span className="so-op__actions">
                            {status === "running" && (
                              <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/scans/${scan.id}/pause`), "Scan paused.", "Couldn't pause the scan.")}>Pause</button>
                            )}
                            {paused && (
                              <button type="button" className="cc-btn" onClick={() => act(() => api.post(`/scans/${scan.id}/resume`), "Scan resumed.", "Couldn't resume the scan.")}>Resume</button>
                            )}
                            <button
                              type="button"
                              className="cc-btn so-danger"
                              onClick={() => {
                                if (window.confirm(`Cancel the scan of ${scan.target}?`)) {
                                  act(() => api.post(`/scans/${scan.id}/cancel`), "Scan cancelled.", "Couldn't cancel the scan.");
                                }
                              }}
                            >
                              Cancel
                            </button>
                          </span>
                        )}
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="so-idle">
              <div className="so-radar so-radar--idle" aria-hidden="true"><span /></div>
              <p>{loading ? "Loading scans…" : "No scans running. Launch one to see it here in real time."}</p>
            </div>
          )}
        </section>
      </div>

      {/* ---------- History ---------- */}
      <section className="cc-panel so-history" aria-label="Scan history">
        <header className="cc-panel__head">
          <h2>Scan history</h2>
          <span className="cc-muted">{history.length} scans</span>
        </header>

        <div className="so-filters">
          <label className="so-search">
            <span className="cc-sr">Search scans</span>
            <input type="search" placeholder="Search name or target" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <div className="cc-range" role="group" aria-label="Engine">
            {["all", "web", "network", "mobile"].map((k) => (
              <button key={k} type="button" aria-pressed={kindFilter === k} onClick={() => setKindFilter(k)}>
                {k === "all" ? "All" : ENGINES[k].name}
              </button>
            ))}
          </div>
          <div className="cc-range" role="group" aria-label="Status">
            {["all", "completed", "failed"].map((k) => (
              <button key={k} type="button" aria-pressed={statusFilter === k} onClick={() => setStatusFilter(k)}>
                {k === "all" ? "Any status" : k[0].toUpperCase() + k.slice(1)}
              </button>
            ))}
          </div>
        </div>

        <div className="so-table-wrap">
          <table className="so-table">
            <thead>
              <tr>
                <th scope="col">Scan</th>
                <th scope="col">Engine</th>
                <th scope="col">Status</th>
                <th scope="col">Findings</th>
                <th scope="col">Duration</th>
                <th scope="col">Finished</th>
                <th scope="col"><span className="cc-sr">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {history.slice(0, limit).map((scan) => {
                const kind = engineKeyOf(scan);
                const status = String(scan.status).toLowerCase();
                const found = scan.result_summary?.finding_count;
                const tab = kind === "web" ? "zap" : kind === "mobile" ? "mobsf" : "openvas";
                return (
                  <tr key={scan.id}>
                    <td>
                      <strong className="so-name">{scan.scan_name || "Unnamed scan"}</strong>
                      <div className="cc-mono so-sub">{scan.target}</div>
                      {status === "failed" && scan.error_message ? <div className="so-error">{scan.error_message.slice(0, 160)}</div> : null}
                      {status === "completed" && scan.error_message ? <div className="so-warn">{scan.error_message.slice(0, 160)}</div> : null}
                    </td>
                    <td><span className="so-tag">{ENGINES[kind].engine}</span></td>
                    <td><span className={`so-status so-status--${status}`}>{status}</span></td>
                    <td className="cc-mono">{found ?? "—"}</td>
                    <td className="cc-mono so-sub">
                      {fmtDuration(scan.started_at, scan.finished_at)}
                      {stageSummary(scan) ? <div className="so-stages" title="Speed used and time per stage">{stageSummary(scan)}</div> : null}
                    </td>
                    <td className="cc-mono so-sub">{fmtWhen(scan.finished_at)}</td>
                    <td className="so-actions">
                      <Link className="cc-btn" to={`/findings?tab=${tab}&target=${encodeURIComponent(scan.target)}`}>Findings</Link>
                      <button type="button" className="cc-btn" onClick={() => downloadScanReport(scan.id)}>PDF</button>
                      {canOperate && (
                        <details className="so-more">
                          <summary className="cc-btn" aria-label={`More actions for ${scan.scan_name || scan.target}`}>More</summary>
                          <div className="so-more__menu">
                            <button type="button" onClick={() => act(() => api.post(`/scans/${scan.id}/rescan`), `Re-scan of ${scan.target} queued.`, "Couldn't start the re-scan.")}>Re-scan target</button>
                            <button type="button" onClick={() => act(() => api.post(`/scans/${scan.id}/reprocess`), "Results re-ingested.", "Couldn't re-ingest results.")}>Re-ingest results</button>
                            <button
                              type="button"
                              className="so-danger"
                              onClick={() => {
                                if (window.confirm(`Delete "${scan.scan_name || scan.target}" and its findings? This can't be undone.`)) {
                                  act(() => api.delete(`/scans/${scan.id}`), "Scan deleted.", "Couldn't delete the scan.");
                                }
                              }}
                            >
                              Delete scan
                            </button>
                          </div>
                        </details>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!history.length && (
                <tr><td colSpan={7} className="cc-empty so-empty">{loading ? "Loading…" : "No scans match these filters."}</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {history.length > limit && (
          <button type="button" className="cc-btn so-showmore" onClick={() => setLimit((n) => n + 25)}>
            Show more ({history.length - limit} remaining)
          </button>
        )}
      </section>
    </div>
  );
}

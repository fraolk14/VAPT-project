import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import { useEChart } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../targets.css";
import "../agents.css";

const CHECKIN_HOURS = 4; // agents check in every 4 hours (checkin_interval_sec = 14400)
const HEALTH = {
  online: { label: "Online", color: "#3ddc97" },
  stale: { label: "Late", color: "#f5d76e" },
  offline: { label: "Offline", color: "#ff6b6b" },
  revoked: { label: "Revoked", color: "#5b6b7d" },
};

function healthOf(device, now) {
  if (device.status === "revoked") return "revoked";
  const seen = device.last_seen ? new Date(device.last_seen).getTime() : 0;
  const hours = (now - seen) / 3600e3;
  if (hours <= CHECKIN_HOURS + 0.5) return "online";
  if (hours <= 24) return "stale";
  return "offline";
}

function ago(iso, now) {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

const errorText = (err, fallback) => {
  if (err?.response?.status === 403) return "Only administrators can manage endpoint agents.";
  const detail = err?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
};

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function Heartbeat({ devices, now }) {
  const ref = useRef(null);
  const option = useMemo(() => {
    const rows = devices.slice(0, 24);
    const windowStart = now - 48 * 3600e3;
    return {
      grid: { left: 120, right: 20, top: 16, bottom: 34 },
      tooltip: {
        trigger: "item",
        backgroundColor: "#0b1730",
        borderColor: "#1f3a63",
        textStyle: { color: "#e6edf3" },
        formatter: (p) => `${p.data.name}<br/>${p.data.health} · last check-in ${p.data.when}`,
      },
      xAxis: {
        type: "time",
        min: windowStart,
        max: now,
        axisLabel: { color: "#7f93ad", fontFamily: "IBM Plex Mono", fontSize: 11, hideOverlap: true },
        axisLine: { lineStyle: { color: "#1f3a63" } },
        splitLine: { lineStyle: { color: "rgba(92,225,255,0.06)" } },
      },
      yAxis: {
        type: "category",
        data: rows.map((d) => d.hostname),
        axisLabel: { color: "#c3ceda", fontFamily: "IBM Plex Mono", fontSize: 11, width: 108, overflow: "truncate" },
        axisLine: { lineStyle: { color: "#1f3a63" } },
      },
      series: [
        {
          type: "scatter",
          symbolSize: 13,
          data: rows.map((d) => {
            const seen = new Date(d.last_seen).getTime() || 0;
            const offScale = seen < windowStart;
            return {
              name: d.hostname,
              value: [offScale ? windowStart : seen, d.hostname],
              health: HEALTH[d.health].label,
              when: ago(d.last_seen, now),
              // Devices last seen before the 48 h window sit on the left edge as a left-pointing arrow.
              symbol: offScale ? "triangle" : "circle",
              symbolRotate: offScale ? 90 : 0,
              itemStyle: { color: HEALTH[d.health].color, shadowBlur: 12, shadowColor: HEALTH[d.health].color },
            };
          }),
          markArea: {
            silent: true,
            itemStyle: { color: "rgba(61,220,151,0.09)" },
            data: [[{ xAxis: now - CHECKIN_HOURS * 3600e3 }, { xAxis: now }]],
          },
        },
      ],
    };
  }, [devices, now]);
  useEChart(ref, option);
  return <div ref={ref} className="ag-heartbeat" role="img" aria-label="Last check-in time of each device over the past 48 hours" />;
}

export default function AgentManagement({ canAdmin = true }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [notice, setNotice] = useState(null);
  const [ttl, setTtl] = useState(72);
  const [token, setToken] = useState(null);
  const [method, setMethod] = useState("manual");
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [now, setNow] = useState(() => Date.now());

  const serverUrl = typeof window !== "undefined" ? window.location.origin : "";

  const fetchDevices = useCallback(async () => {
    try {
      const res = await api.get("/agent/devices");
      setDevices(Array.isArray(res.data) ? res.data : []);
      setForbidden(false);
    } catch (err) {
      if (err?.response?.status === 403) setForbidden(true);
    } finally {
      setLoading(false);
      setNow(Date.now());
    }
  }, []);

  useEffect(() => {
    if (!canAdmin) {
      const id = window.setTimeout(() => { setForbidden(true); setLoading(false); }, 0);
      return () => window.clearTimeout(id);
    }
    const first = window.setTimeout(fetchDevices, 0);
    const id = window.setInterval(() => { if (!document.hidden) fetchDevices(); }, 30000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [canAdmin, fetchDevices]);

  const fleet = useMemo(() => devices
    .map((d) => ({ ...d, health: healthOf(d, now) }))
    .sort((a, b) => new Date(b.last_seen || 0) - new Date(a.last_seen || 0)), [devices, now]);

  const counts = useMemo(() => {
    const c = { online: 0, stale: 0, offline: 0, revoked: 0 };
    fleet.forEach((d) => { c[d.health] += 1; });
    return c;
  }, [fleet]);

  const rows = fleet.filter((d) => (filter === "all" || d.health === filter)
    && (!query.trim() || `${d.hostname} ${d.device_id} ${d.ip_address} ${d.os_info}`.toLowerCase().includes(query.trim().toLowerCase())));

  const generateToken = async () => {
    try {
      const res = await api.post("/agent/tokens/generate", { ttl_hours: ttl });
      setToken(res.data);
      setNotice(null);
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't generate a token.") });
    }
  };

  const manualCommand = token
    ? `vap-agent.exe enroll --url "${serverUrl}" --token "${token.token}"\nvap-agent.exe install\nvap-agent.exe start`
    : "";
  const scriptHref = `/api/agent/installer-script?backend_url=${encodeURIComponent(serverUrl)}${token ? `&token=${encodeURIComponent(token.token)}` : ""}`;

  const copy = async (text, what) => {
    const ok = await copyText(text);
    setNotice({ ok, text: ok ? `${what} copied.` : "Copy failed — select the text and copy it manually." });
  };

  const revoke = async (device) => {
    if (!window.confirm(`Revoke ${device.hostname}? Its agent will be refused at the next check-in.`)) return;
    try {
      await api.post(`/agent/devices/${device.device_id}/revoke`);
      setNotice({ ok: true, text: `${device.hostname} revoked.` });
      fetchDevices();
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't revoke the device.") });
    }
  };

  const remove = async (device) => {
    if (!window.confirm(`Delete ${device.hostname}? It can then enroll again with a new token.`)) return;
    try {
      await api.delete(`/agent/devices/${device.device_id}`);
      setNotice({ ok: true, text: `${device.hostname} deleted.` });
      fetchDevices();
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't delete the device.") });
    }
  };

  return (
    <div className="cc ag">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Endpoint Fleet</h1>
        </div>
        {!forbidden && (
          <div className="cc-top__tools">
            <button type="button" className="cc-btn" onClick={fetchDevices}>Refresh</button>
          </div>
        )}
      </header>

      {forbidden ? (
        <section className="cc-panel ag-locked">
          <h2>Administrator access required</h2>
          <p>Enrolling, revoking and deleting endpoint agents is limited to administrators. Agent data still appears on each target in the <Link to="/assets">Targets</Link> page.</p>
        </section>
      ) : (
        <>
          <div className="cc-kpis">
            <div className="cc-kpi"><span>Enrolled</span><strong>{fleet.length}</strong></div>
            <div className="cc-kpi cc-kpi--live"><span>Online</span><strong>{counts.online}</strong></div>
            <div className={`cc-kpi${counts.stale ? " cc-kpi--hot" : ""}`}><span>Late check-in</span><strong>{counts.stale}</strong></div>
            <div className={`cc-kpi${counts.offline ? " cc-kpi--hot" : ""}`}><span>Offline &gt; 24 h</span><strong>{counts.offline}</strong></div>
            <div className="cc-kpi"><span>Revoked</span><strong>{counts.revoked}</strong></div>
          </div>

          {notice && (
            <div className={`so-notice${notice.ok ? "" : " so-notice--error"}`} role="status">
              <span>{notice.text}</span>
              <button type="button" className="cc-icon" aria-label="Dismiss" onClick={() => setNotice(null)}>×</button>
            </div>
          )}

          <div className="cc-grid">
            <section className="cc-panel cc-col--side ag-deploy" aria-label="Deploy agents">
              <header className="cc-panel__head"><h2>Deploy agents</h2></header>

              <ol className="ag-steps">
                <li>
                  <h3>1 · Create an enrollment token</h3>
                  <p className="cc-muted">Each token enrolls one device, once.</p>
                  <div className="ag-row">
                    <label>
                      <span className="cc-sr">Token lifetime</span>
                      <select className="so-input ti-select" value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
                        <option value={24}>Valid 24 hours</option>
                        <option value={72}>Valid 3 days</option>
                        <option value={168}>Valid 7 days</option>
                      </select>
                    </label>
                    <button type="button" className="cc-btn cc-btn--primary" onClick={generateToken}>
                      {token ? "New token" : "Generate token"}
                    </button>
                  </div>
                  {token && (
                    <div className="ag-token">
                      <code className="cc-mono">{token.token}</code>
                      <button type="button" className="cc-btn" onClick={() => copy(token.token, "Token")}>Copy</button>
                      <span className="cc-muted">Expires {new Date(token.expires_at).toLocaleString()}</span>
                    </div>
                  )}
                </li>

                <li>
                  <h3>2 · Install on the endpoint</h3>
                  <div className="cc-range" role="group" aria-label="Install method">
                    <button type="button" aria-pressed={method === "manual"} onClick={() => setMethod("manual")}>Manual</button>
                    <button type="button" aria-pressed={method === "script"} onClick={() => setMethod("script")}>Intune / GPO</button>
                  </div>

                  {method === "manual" ? (
                    <div className="ag-method">
                      <p>Download the agent, then run these in an elevated prompt on the endpoint:</p>
                      <a className="cc-btn" href="/api/agent/download" download>Download vap-agent.exe</a>
                      {token ? (
                        <div className="ag-code">
                          <pre className="cc-mono">{manualCommand}</pre>
                          <button type="button" className="cc-btn" onClick={() => copy(manualCommand, "Commands")}>Copy</button>
                        </div>
                      ) : <p className="cc-muted">Generate a token first to get the commands.</p>}
                    </div>
                  ) : (
                    <div className="ag-method">
                      <p>A PowerShell script with this server's address{token ? " and your token" : ""} already filled in, for Intune or a GPO startup script.</p>
                      <a className="cc-btn" href={scriptHref} download>Download install-agent.ps1</a>
                      {!token && <p className="cc-muted">Generate a token first, or paste one into the script later.</p>}
                    </div>
                  )}
                  <p className="cc-muted ag-server">Agents will report to <code className="cc-mono">{serverUrl}</code>. This address must be reachable from the endpoints.</p>
                </li>
              </ol>
            </section>

            <section className="cc-panel cc-col--center" aria-label="Fleet heartbeat">
              <header className="cc-panel__head">
                <h2>Fleet heartbeat</h2>
                <span className="cc-muted">last check-in per device · green band = expected check-in window · ◀ = over 48 h ago</span>
              </header>
              {fleet.length ? (
                <>
                  <Heartbeat devices={fleet} now={now} />
                  <ul className="cc-legend ag-legend">
                    {Object.entries(HEALTH).map(([key, h]) => (
                      <li key={key}><span className="cc-swatch" style={{ background: h.color }} />{h.label}</li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="cc-empty">{loading ? "Loading devices…" : "No agents enrolled yet. Generate a token and install the agent on an endpoint."}</p>
              )}
            </section>
          </div>

          <section className="cc-panel" aria-label="Devices">
            <header className="cc-panel__head">
              <h2>Devices</h2>
              <span className="cc-muted">{rows.length} of {fleet.length}</span>
            </header>
            <div className="so-filters">
              <label className="so-search">
                <span className="cc-sr">Search devices</span>
                <input type="search" placeholder="Search hostname, device ID, IP or OS" value={query} onChange={(e) => setQuery(e.target.value)} />
              </label>
              <div className="cc-range" role="group" aria-label="Health">
                {["all", "online", "stale", "offline", "revoked"].map((k) => (
                  <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}>
                    {k === "all" ? "All" : HEALTH[k].label}
                  </button>
                ))}
              </div>
            </div>
            <div className="so-table-wrap">
              <table className="so-table">
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">Health</th>
                    <th scope="col">IP address</th>
                    <th scope="col">Operating system</th>
                    <th scope="col">Last check-in</th>
                    <th scope="col">Enrolled</th>
                    <th scope="col"><span className="cc-sr">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <strong>{d.hostname}</strong>
                        <div className="cc-mono so-sub">{d.device_id}</div>
                      </td>
                      <td><span className="ag-health" style={{ "--h": HEALTH[d.health].color }}>{HEALTH[d.health].label}</span></td>
                      <td className="cc-mono">{d.ip_address || "—"}</td>
                      <td className="so-sub">{d.os_info || "—"}</td>
                      <td title={d.last_seen ? new Date(d.last_seen).toLocaleString() : ""}>{ago(d.last_seen, now)}</td>
                      <td className="so-sub">{d.first_seen ? new Date(d.first_seen).toLocaleDateString() : "—"}</td>
                      <td className="so-actions">
                        {d.status === "revoked" ? (
                          <button type="button" className="cc-btn so-danger" onClick={() => remove(d)} aria-label={`Delete ${d.hostname}`}>Delete</button>
                        ) : (
                          <button type="button" className="cc-btn so-danger" onClick={() => revoke(d)} aria-label={`Revoke ${d.hostname}`}>Revoke</button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {!rows.length && (
                    <tr><td colSpan={7} className="cc-empty so-empty">{loading ? "Loading…" : fleet.length ? "No devices match these filters." : "No agents enrolled yet."}</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

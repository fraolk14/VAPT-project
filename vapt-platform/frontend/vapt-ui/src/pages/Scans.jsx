import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api/client";

// ─── Engine definitions ───────────────────────────────────────────────────────
const ENGINES = {
  Web: {
    label: "Web Engine (ZAP)",
    endpoint: "/scans/web",
    payloadKey: "target",     // field name in POST body
    targetLabel: "Website URL",
    targetHelp: "ZAP spiders the site then runs a full active scan. Takes 5–30+ minutes depending on site size. Use an authorized https:// or http:// URL.",
    placeholder: "https://juice-shop.herokuapp.com",
    icon: "🌐",
    tool: "zap",
    tab: "zap",
    description: "OWASP ZAP: Spider Discovery → Active Vulnerability Scanning (SQLi, XSS, SSRF, CORS, Auth…)",
    buttonLabel: "Launch ZAP Web Scan",
  },
  Network: {
    label: "Network Engine (Nmap)",
    endpoint: "/scans/network",
    payloadKey: "target",
    targetLabel: "IP / CIDR / Domain",
    targetHelp: "Nmap + banner analysis probes every port. A single host takes ~2–5 min; a /24 block can take 20+ min.",
    placeholder: "192.168.1.0/24",
    icon: "🔌",
    tool: "openvas",
    tab: "openvas",
    description: "Nmap: Port Discovery → Service Version Detection → CVE Correlation → Exposure Analysis",
    buttonLabel: "Launch Network Scan",
  },
};

// ─── helpers ─────────────────────────────────────────────────────────────────
const statusColor = (s) => {
  if (!s) return "#94a3b8";
  const l = s.toLowerCase();
  if (l === "completed") return "#34d399";
  if (l === "running")   return "#38bdf8";
  if (l === "waiting" || l === "queued") return "#fbbf24";
  if (l === "failed")    return "#fb7185";
  if (l === "cancelled") return "#94a3b8";
  return "#94a3b8";
};

const toolLabel = (tool) => {
  if (tool === "zap")     return { label: "ZAP",    tab: "zap"    };
  if (tool === "openvas") return { label: "Nmap",   tab: "openvas" };
  if (tool === "mobsf")   return { label: "MobSF",  tab: "mobsf"  };
  return                         { label: "Scan",   tab: "all"    };
};

const progressLabel = (scan) => {
  const phase = scan.engine_metadata?.phase;
  const pct   = parseInt(scan.progress || "0", 10);
  if (phase === "spider") return `🕷️ Spidering… ${pct}%`;
  if (phase === "active") return `⚡ Active scan… ${pct}%`;
  if (scan.status === "waiting" || scan.status === "queued") return "⏳ Waiting for scanner…";
  if (scan.status === "running") return `🔍 Scanning… ${pct}%`;
  if (scan.status === "completed") return "✅ Completed";
  if (scan.status === "failed") return "❌ Failed";
  return `${pct}%`;
};

const fmtTime = (t) => {
  if (!t) return "—";
  const d = new Date(t);
  return isNaN(d) ? t : d.toLocaleString();
};

// ─── Component ────────────────────────────────────────────────────────────────
export default function Scans() {
  const [engine, setEngine]       = useState("Web");
  const [target, setTarget]       = useState("");
  const [label, setLabel]         = useState("");
  const [submitting, setSubmit]   = useState(false);
  const [message, setMessage]     = useState({ type: "", text: "" });
  const [scans, setScans]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const pollRef = useRef(null);

  const cfg = ENGINES[engine];

  // ── Fetch scan list ────────────────────────────────────────────────────────
  const fetchScans = async () => {
    try {
      const res = await api.get("/scans/");
      setScans(res.data || []);
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  // ── Polling: refresh every 5 seconds while any scan is running/waiting ─────
  useEffect(() => {
    fetchScans();
    pollRef.current = setInterval(() => {
      fetchScans();
    }, 5000);
    return () => clearInterval(pollRef.current);
  }, []);

  // ── Submit form ────────────────────────────────────────────────────────────
  const handleSubmit = async (e) => {
    e.preventDefault();
    const t = target.trim();
    if (!t) {
      setMessage({ type: "error", text: "Please enter a target." });
      return;
    }

    setSubmit(true);
    setMessage({ type: "", text: "" });

    const body = {
      [cfg.payloadKey]: t,
      label: label.trim() || `${engine} scan – ${t}`,
    };

    try {
      await api.post(cfg.endpoint, body);
      setMessage({
        type: "success",
        text: `${engine} scan queued for ${t}. The scanner is now running in the background — this will take several minutes.`,
      });
      setTarget("");
      setLabel("");
      fetchScans();
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setMessage({
        type: "error",
        text: detail || `Failed to launch ${engine} scan. Check the target and try again.`,
      });
    } finally {
      setSubmit(false);
    }
  };

  // ── Cancel a scan ──────────────────────────────────────────────────────────
  const handleCancel = async (scanId) => {
    try {
      await api.post(`/scans/${scanId}/cancel`);
      fetchScans();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to cancel scan.");
    }
  };

  // ── Reprocess (re-ingest results for scan) ─────────────────────────────────
  const handleReprocess = async (scanId) => {
    try {
      await api.post(`/scans/${scanId}/reprocess`);
      setMessage({
        type: "success",
        text: "Scan results re-ingested successfully.",
      });
      fetchScans();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to reprocess scan results.");
    }
  };

  // ── Rescan (re-trigger scan for target) ────────────────────────────────────
  const handleRescan = async (scanId, scanName) => {
    try {
      await api.post(`/scans/${scanId}/rescan`);
      setMessage({
        type: "success",
        text: `Re-scan queued for ${scanName || "target"}. Scanner is running in background.`,
      });
      fetchScans();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to trigger re-scan.");
    }
  };

  // ── Delete a scan record ────────────────────────────────────────────────────
  const handleDelete = async (scanId, scanName) => {
    if (!window.confirm(`Are you sure you want to delete scan record "${scanName}"? This will also remove associated findings.`)) {
      return;
    }
    try {
      await api.delete(`/scans/${scanId}`);
      fetchScans();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to delete scan record.");
    }
  };

  const color = statusColor;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "28px" }}>

      {/* ── Launch form ─────────────────────────────────────────────────── */}
      <section style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "14px", padding: "28px" }}>
        <div style={{ marginBottom: "20px" }}>
          <p style={{ color: "#38bdf8", textTransform: "uppercase", fontSize: "0.72rem", letterSpacing: "1.5px", margin: "0 0 4px 0" }}>
            VAPT Scan Orchestration Engine
          </p>
          <h2 style={{ color: "#f8fafc", margin: "0 0 6px 0", fontSize: "1.5rem" }}>Launch a Scan</h2>
          <p style={{ color: "#64748b", fontSize: "0.875rem", margin: 0 }}>{cfg.description}</p>
        </div>

        {/* Engine toggle */}
        <div style={{ display: "flex", gap: "10px", marginBottom: "24px" }}>
          {Object.entries(ENGINES).map(([key, e]) => (
            <button
              key={key}
              type="button"
              onClick={() => { setEngine(key); setTarget(""); setLabel(""); setMessage({ type: "", text: "" }); }}
              style={{
                padding: "10px 20px",
                borderRadius: "8px",
                border: engine === key ? "2px solid #38bdf8" : "2px solid #334155",
                background: engine === key ? "#0284c722" : "#1e293b",
                color: engine === key ? "#38bdf8" : "#94a3b8",
                fontWeight: 700,
                cursor: "pointer",
                fontSize: "0.875rem",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                transition: "all 0.15s",
              }}
            >
              {e.icon} {e.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          {/* Target */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>
              {cfg.targetLabel} <span style={{ color: "#fb7185" }}>*</span>
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={cfg.placeholder}
              required
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 14px", borderRadius: "7px", fontSize: "0.95rem" }}
            />
            <span style={{ color: "#64748b", fontSize: "0.75rem" }}>{cfg.targetHelp}</span>
          </div>

          {/* Scan name / label */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Scan Label (optional)</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder={`e.g. Q3 ${engine} Assessment`}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 14px", borderRadius: "7px", fontSize: "0.95rem" }}
            />
          </div>

          {/* Info banner */}
          <div style={{ gridColumn: "1 / -1", background: "#0f2744", border: "1px solid #1d4ed8", borderRadius: "8px", padding: "14px 18px", color: "#93c5fd", fontSize: "0.82rem", lineHeight: 1.6 }}>
            <strong>⏱ Scan Duration Expectations:</strong><br />
            {engine === "Web"
              ? "ZAP spider + active scan typically takes 5–30 minutes. The scanner will discover all pages, then actively probe each for SQLi, XSS, SSRF, CSRF, auth bypass, and 100+ other vulnerability classes."
              : "Nmap deep port sweep + banner analysis typically takes 2–20 minutes per host. CIDR blocks with many hosts take longer. All open ports are service-fingerprinted and correlated against CVEs."}
          </div>

          {/* Submit */}
          <div style={{ gridColumn: "1 / -1" }}>
            <button
              type="submit"
              disabled={submitting}
              style={{
                background: submitting
                  ? "#1e293b"
                  : "linear-gradient(135deg, #0369a1 0%, #0284c7 100%)",
                color: "#fff",
                border: "none",
                padding: "12px 28px",
                borderRadius: "8px",
                fontWeight: 700,
                fontSize: "0.95rem",
                cursor: submitting ? "not-allowed" : "pointer",
                boxShadow: submitting ? "none" : "0 4px 14px #0284c744",
                transition: "all 0.2s",
              }}
            >
              {submitting ? `⏳ Queuing ${engine} Scan…` : `${cfg.icon} ${cfg.buttonLabel}`}
            </button>
          </div>
        </form>

        {message.text && (
          <div style={{
            marginTop: "16px",
            padding: "14px 16px",
            borderRadius: "8px",
            background: message.type === "error" ? "#450a0a" : "#052e16",
            color: message.type === "error" ? "#fca5a5" : "#86efac",
            border: `1px solid ${message.type === "error" ? "#7f1d1d" : "#166534"}`,
            fontSize: "0.875rem",
          }}>
            {message.text}
          </div>
        )}
      </section>

      {/* ── Scan list ───────────────────────────────────────────────────── */}
      <section style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "14px", padding: "28px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
          <div>
            <h3 style={{ color: "#f8fafc", margin: "0 0 4px 0", fontSize: "1.2rem" }}>Active &amp; Completed Scans</h3>
            <p style={{ color: "#64748b", margin: 0, fontSize: "0.82rem" }}>Auto-refreshes every 5 seconds • Real engine results only</p>
          </div>
          <button
            onClick={fetchScans}
            style={{ background: "#1e293b", color: "#38bdf8", border: "1px solid #334155", padding: "6px 16px", borderRadius: "6px", cursor: "pointer", fontSize: "0.82rem" }}
          >
            ↺ Refresh
          </button>
        </div>

        {loading ? (
          <div style={{ textAlign: "center", color: "#64748b", padding: "40px" }}>Loading scans…</div>
        ) : scans.length === 0 ? (
          <div style={{ textAlign: "center", color: "#64748b", padding: "40px" }}>
            No scans found. Launch a scan above to get started.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", color: "#cbd5e1", fontSize: "0.875rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #334155", textAlign: "left" }}>
                  {["Scan Name", "Tool", "Target", "Status", "Progress", "Finished", "Actions"].map((h) => (
                    <th key={h} style={{ padding: "10px 12px", color: "#64748b", fontWeight: 600, whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const c = statusColor(scan.status);
                  const { tab } = toolLabel(scan.tool);
                  const pct = parseInt(scan.progress || "0", 10);
                  const isActive = ["running", "waiting", "queued"].includes((scan.status || "").toLowerCase());

                  return (
                    <tr key={scan.id} style={{ borderBottom: "1px solid #1e293b" }}>
                      {/* Name */}
                      <td style={{ padding: "12px" }}>
                        <strong style={{ color: "#f8fafc" }}>{scan.scan_name || "Unnamed Scan"}</strong>
                        {scan.error_message && !isActive && (
                          <div style={{ color: "#fda4af", fontSize: "0.72rem", marginTop: "4px", maxWidth: "260px" }}>
                            {scan.error_message.slice(0, 120)}{scan.error_message.length > 120 ? "…" : ""}
                          </div>
                        )}
                      </td>

                      {/* Tool */}
                      <td style={{ padding: "12px" }}>
                        <span style={{ background: "#0284c722", color: "#38bdf8", border: "1px solid #0284c744", padding: "2px 8px", borderRadius: "10px", fontSize: "0.75rem", fontWeight: 700 }}>
                          {toolLabel(scan.tool).label}
                        </span>
                      </td>

                      {/* Target */}
                      <td style={{ padding: "12px", fontFamily: "monospace", fontSize: "0.82rem", color: "#e2e8f0", maxWidth: "200px", wordBreak: "break-all" }}>
                        {scan.target}
                      </td>

                      {/* Status */}
                      <td style={{ padding: "12px" }}>
                        <span style={{ color: c, fontWeight: 700, fontSize: "0.8rem", background: `${c}18`, border: `1px solid ${c}44`, padding: "3px 10px", borderRadius: "12px" }}>
                          {(scan.status || "unknown").toUpperCase()}
                        </span>
                      </td>

                      {/* Progress */}
                      <td style={{ padding: "12px", minWidth: "160px" }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <div style={{ flex: 1, background: "#1e293b", height: "6px", borderRadius: "3px", overflow: "hidden" }}>
                              <div style={{
                                width: `${Math.min(100, Math.max(0, pct))}%`,
                                background: isActive
                                  ? "linear-gradient(90deg, #38bdf8, #0284c7)"
                                  : c,
                                height: "100%",
                                transition: "width 1s ease",
                                boxShadow: isActive ? "0 0 6px #38bdf888" : "none",
                              }} />
                            </div>
                            <span style={{ fontSize: "0.75rem", color: "#94a3b8", minWidth: "32px" }}>{pct}%</span>
                          </div>
                          {isActive && (
                            <span style={{ fontSize: "0.7rem", color: "#38bdf8", fontStyle: "italic" }}>
                              {progressLabel(scan)}
                            </span>
                          )}
                          {scan.status?.toLowerCase() === "completed" && (
                            <span style={{ fontSize: "0.7rem", color: "#34d399" }}>✅ Done</span>
                          )}
                        </div>
                      </td>

                      {/* Finished */}
                      <td style={{ padding: "12px", fontSize: "0.78rem", color: "#64748b", whiteSpace: "nowrap" }}>
                        {fmtTime(scan.finished_at)}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: "12px" }}>
                        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                          {/* View Findings */}
                          <Link
                            to={`/findings?tab=${tab}&target=${encodeURIComponent(scan.target)}`}
                            style={{
                              background: "#10b98122",
                              color: "#34d399",
                              border: "1px solid #10b98144",
                              padding: "4px 10px",
                              borderRadius: "5px",
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              textDecoration: "none",
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            🔍 Findings
                          </Link>

                          {/* PDF report */}
                          <a
                            href={`/api/reports/v1/download/${scan.id}?format=pdf&type=executive`}
                            target="_blank"
                            rel="noreferrer"
                            download={`VAPT_Report_${scan.id}.pdf`}
                            style={{
                              background: "#0284c722",
                              color: "#38bdf8",
                              border: "1px solid #0284c744",
                              padding: "4px 10px",
                              borderRadius: "5px",
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              textDecoration: "none",
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            📥 PDF
                          </a>

                          {/* Rescan button */}
                          {!isActive && (
                            <button
                              onClick={() => handleRescan(scan.id, scan.scan_name || scan.target)}
                              title="Re-trigger security scan for this target"
                              style={{
                                background: "#0284c722",
                                color: "#38bdf8",
                                border: "1px solid #0284c744",
                                padding: "4px 10px",
                                borderRadius: "5px",
                                cursor: "pointer",
                                fontSize: "0.75rem",
                                fontWeight: 700,
                              }}
                            >
                              ⚡ Rescan
                            </button>
                          )}

                          {/* Re-ingest (reprocess results) */}
                          {!isActive && (
                            <button
                              onClick={() => handleReprocess(scan.id)}
                              title="Re-ingest and re-evaluate findings from scanner"
                              style={{
                                background: "#1e293b",
                                color: "#fbbf24",
                                border: "1px solid #fbbf2444",
                                padding: "4px 10px",
                                borderRadius: "5px",
                                cursor: "pointer",
                                fontSize: "0.75rem",
                                fontWeight: 600,
                              }}
                            >
                              🔄 Re-ingest
                            </button>
                          )}

                          {/* Cancel for active scans */}
                          {isActive && (
                            <button
                              onClick={() => handleCancel(scan.id)}
                              style={{
                                background: "#450a0a",
                                color: "#fca5a5",
                                border: "1px solid #7f1d1d",
                                padding: "4px 10px",
                                borderRadius: "5px",
                                cursor: "pointer",
                                fontSize: "0.75rem",
                              }}
                            >
                              ✕ Cancel
                            </button>
                          )}

                          {/* Delete button */}
                          {!isActive && (
                            <button
                              onClick={() => handleDelete(scan.id, scan.scan_name || scan.target)}
                              title="Delete scan record from history"
                              style={{
                                background: "#451a1a",
                                color: "#fca5a5",
                                border: "1px solid #7f1d1d",
                                padding: "4px 10px",
                                borderRadius: "5px",
                                cursor: "pointer",
                                fontSize: "0.75rem",
                                fontWeight: 600,
                              }}
                            >
                              🗑️ Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── Info panel ──────────────────────────────────────────────────── */}
      <section style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "14px", padding: "24px" }}>
        <h4 style={{ color: "#f8fafc", margin: "0 0 12px 0" }}>📡 Scanner Status</h4>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px" }}>
          {[
            { name: "OWASP ZAP", desc: "Web vulnerability scanner", status: "Running", color: "#34d399" },
            { name: "Nmap", desc: "Network port scanner + CVE correlation", status: "Running", color: "#34d399" },
            { name: "MobSF", desc: "Mobile binary static analysis", status: "Running", color: "#fbbf24" },
          ].map((s) => (
            <div key={s.name} style={{ background: "#1e293b", borderRadius: "8px", padding: "14px", border: "1px solid #334155" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: s.color, display: "inline-block" }} />
                <strong style={{ color: "#f8fafc", fontSize: "0.875rem" }}>{s.name}</strong>
              </div>
              <p style={{ color: "#64748b", fontSize: "0.75rem", margin: 0 }}>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

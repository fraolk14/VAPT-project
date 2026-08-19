import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";

const ENGINE_OPTIONS = {
  Network: {
    label: "Network Engine",
    targetKind: "Network Target",
    targetHelp: "Enter an IP address, Domain, or CIDR block (e.g. 192.168.1.1, example.com, 10.0.0.0/24).",
    description: "Executes deep network discovery, port scanning, service version detection, and vulnerability correlation.",
    buttonLabel: "Launch Network Scan",
    defaultType: "IP",
    placeholder: "192.168.1.1",
  },
  Web: {
    label: "Web Engine",
    targetKind: "Web Target",
    targetHelp: "Enter a Web URL or Domain (e.g. https://example.com, app.internal.local).",
    description: "Performs web vulnerability scans, web spidering, CORS audits, and HTTP security header checks.",
    buttonLabel: "Launch Web Scan",
    defaultType: "URL",
    placeholder: "https://example.com",
  },
  Mobile: {
    label: "Mobile Engine",
    targetKind: "Mobile Target",
    targetHelp: "Enter APK/IPA package name or URL (e.g. com.example.app, https://store.local/app.apk).",
    description: "Performs static binary analysis, permission audits, secret leakage detection, and mobile package risk scoring.",
    buttonLabel: "Launch Mobile Scan",
    defaultType: "APK",
    placeholder: "com.example.secureapp",
  },
};

export default function Scans({ scans: legacyScans, assets: initialAssets, onScanQueued, onScanUpdated }) {
  const navigate = useNavigate();
  const [engine, setEngine] = useState("Network");
  const [targetType, setTargetType] = useState("IP");
  const [target, setTarget] = useState("");
  const [scanName, setScanName] = useState("");
  const [scheduleInterval, setScheduleInterval] = useState("Immediate");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [scanDepth, setScanDepth] = useState("deep");
  
  const [scanJobs, setScanJobs] = useState([]);
  const [assetList, setAssetList] = useState(initialAssets || []);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState({ type: "", text: "" });

  // Keep assetList synced with initialAssets prop if passed from parent App
  useEffect(() => {
    if (initialAssets && initialAssets.length > 0) {
      setAssetList(initialAssets);
    }
  }, [initialAssets]);

  // Fetch Real Assets from GET /assets/
  const fetchAssets = async () => {
    try {
      const res = await api.get("/assets/");
      if (res.data && res.data.length > 0) {
        setAssetList(res.data);
        return;
      }
    } catch {
      // Fallback endpoints
    }
    try {
      const res2 = await api.get("/assets");
      if (res2.data && res2.data.length > 0) {
        setAssetList(res2.data);
        return;
      }
    } catch {
      // Fallback v1
    }
    try {
      const resV1 = await api.get("/api/v1/assets");
      if (resV1.data) setAssetList(resV1.data);
    } catch {
      // Keep existing list
    }
  };

  // Fetch Real Scan Jobs from GET /scans/v1/jobs
  const fetchScanJobs = async () => {
    try {
      const res = await api.get("/scans/v1/jobs");
      setScanJobs(res.data || []);
    } catch {
      try {
        const resLegacy = await api.get("/scans/");
        setScanJobs(
          (resLegacy.data || []).map((s) => ({
            id: s.id,
            name: s.scan_name || "Scan",
            engine: s.tool === "openvas" ? "Network" : s.tool === "zap" ? "Web" : "Mobile",
            target: s.target,
            target_type: "IP",
            status: (s.status || "PENDING").toUpperCase(),
            progress: parseInt(s.progress || "0", 10),
            created_at: s.created_at,
          }))
        );
      } catch {
        setScanJobs([]);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
    fetchScanJobs();
  }, []);

  // Real-time 2-Second Polling for Progress Updates
  useEffect(() => {
    const interval = setInterval(() => {
      fetchScanJobs();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Update target type when engine changes
  const handleEngineChange = (newEngine) => {
    setEngine(newEngine);
    setTargetType(ENGINE_OPTIONS[newEngine].defaultType);
    setTarget("");
    setSelectedAssetId("");
  };

  // Asset dropdown selection handler
  const handleAssetSelect = (assetId) => {
    setSelectedAssetId(assetId);
    if (!assetId) return;
    const asset = assetList.find((a) => String(a.id) === String(assetId));
    if (asset) {
      const bestTarget = asset.ip_address || asset.hostname || asset.url || asset.asset_name || "";
      setTarget(bestTarget);
      if (!scanName) {
        setScanName(`${engine} Assessment - ${asset.asset_name || asset.hostname || bestTarget}`);
      }
    }
  };

  // Launch New Scan
  const handleCreateScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setMessage({ type: "error", text: "Scan target is required." });
      return;
    }

    setSubmitting(true);
    setMessage({ type: "", text: "" });

    const payload = {
      name: scanName.trim() || `${engine} Assessment ${target.trim()}`,
      engine,
      target: target.trim(),
      target_type: targetType,
      schedule_interval: scheduleInterval === "Immediate" ? null : scheduleInterval,
      asset_id: selectedAssetId || null,
    };

    try {
      const res = await api.post("/scans/v1/jobs", payload);
      setMessage({ type: "success", text: `Scan "${res.data.name}" queued and actively scanning target in background!` });
      setTarget("");
      setScanName("");
      setSelectedAssetId("");
      fetchScanJobs();
    } catch (err) {
      setMessage({
        type: "error",
        text: err?.response?.data?.detail || "Failed to create scan job.",
      });
    } finally {
      setSubmitting(false);
    }
  };

  // Trigger Rescan for an Existing Job
  const handleRescan = async (jobId) => {
    try {
      const res = await api.post(`/scans/v1/jobs/${jobId}/rescan`);
      setMessage({ type: "success", text: `Rescan job "${res.data.name}" launched successfully!` });
      fetchScanJobs();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to launch rescan.");
    }
  };

  // Cancel Scan Job
  const handleCancelScan = async (jobId) => {
    try {
      await api.post(`/scans/v1/jobs/${jobId}/cancel`);
      fetchScanJobs();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to cancel scan.");
    }
  };

  // Delete Scan Job
  const handleDeleteScan = async (jobId) => {
    if (!window.confirm("Are you sure you want to delete this scan job record?")) return;
    try {
      await api.delete(`/scans/v1/jobs/${jobId}`);
      fetchScanJobs();
    } catch (err) {
      alert(err?.response?.data?.detail || "Failed to delete scan job.");
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Launch Scan Header & Panel */}
      <section className="panel" style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
        <div style={{ marginBottom: "20px" }}>
          <p className="eyebrow" style={{ color: "#38bdf8", textTransform: "uppercase", fontSize: "0.75rem", letterSpacing: "1px" }}>
            VAPT Orchestration Engine
          </p>
          <h2 style={{ color: "#f8fafc", margin: "4px 0 0 0", fontSize: "1.5rem" }}>Scan Center & Target Selection</h2>
          <p style={{ color: "#64748b", margin: "4px 0 0 0", fontSize: "0.875rem" }}>
            {ENGINE_OPTIONS[engine].description}
          </p>
        </div>

        <form onSubmit={handleCreateScan} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
          {/* Engine Selection */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Scanning Engine</label>
            <select
              value={engine}
              onChange={(e) => handleEngineChange(e.target.value)}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            >
              <option value="Network">Network Engine</option>
              <option value="Web">Web Engine</option>
              <option value="Mobile">Mobile Engine</option>
            </select>
          </div>

          {/* Target Selection from Real Asset Inventory */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>
              Pick Target from Asset Inventory ({assetList.length} assets found)
            </label>
            <select
              value={selectedAssetId}
              onChange={(e) => handleAssetSelect(e.target.value)}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            >
              <option value="">
                {assetList.length > 0 ? `-- Select from ${assetList.length} Real Assets --` : "No assets available"}
              </option>
              {assetList.map((asset) => {
                const displayName = asset.asset_name || asset.hostname || asset.ip_address || "Unnamed Asset";
                const details = [asset.ip_address, asset.hostname, asset.environment].filter(Boolean).join(" | ");
                return (
                  <option key={asset.id} value={asset.id}>
                    {displayName} ({details})
                  </option>
                );
              })}
            </select>
          </div>

          {/* Target Type */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Target Type</label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            >
              <option value="IP">IP Address</option>
              <option value="Domain">Domain Name</option>
              <option value="CIDR">CIDR Range</option>
              <option value="URL">URL</option>
              <option value="APK">APK / Package</option>
            </select>
          </div>

          {/* Manual Target Input */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Target Address / URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={ENGINE_OPTIONS[engine].placeholder}
              required
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            />
          </div>

          {/* Scan Name */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Scan Campaign Name</label>
            <input
              type="text"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              placeholder={`e.g. ${engine} Assessment`}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            />
          </div>

          {/* Schedule Interval */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <label style={{ color: "#94a3b8", fontSize: "0.875rem", fontWeight: 600 }}>Execution Schedule</label>
            <select
              value={scheduleInterval}
              onChange={(e) => setScheduleInterval(e.target.value)}
              style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "10px 12px", borderRadius: "6px" }}
            >
              <option value="Immediate">Run Immediately</option>
              <option value="Daily">Daily Schedule</option>
              <option value="Weekly">Weekly Schedule</option>
              <option value="Monthly">Monthly Schedule</option>
            </select>
          </div>

          {/* Scan Depth Mode */}
          <div style={{ display: "flex", flexDirection: "column", gap: "6px", gridColumn: "1 / -1", background: "#0284c711", border: "1px solid #0284c733", padding: "16px", borderRadius: "8px", marginTop: "8px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <label style={{ color: "#38bdf8", fontSize: "0.95rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "8px" }}>
                🛡️ Assessment Engine Profile & Scan Depth
              </label>
              <span style={{ fontSize: "0.75rem", background: "#0284c722", color: "#38bdf8", padding: "2px 8px", borderRadius: "12px", border: "1px solid #0284c744" }}>
                {scanDepth === "deep" ? "ADVANCED DEEP MODE ENABLED" : "STANDARD FAST SWEEP"}
              </span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <button
                type="button"
                onClick={() => setScanDepth("deep")}
                style={{
                  background: scanDepth === "deep" ? "linear-gradient(135deg, #0284c722 0%, #0369a133 100%)" : "#1e293b",
                  border: `2px solid ${scanDepth === "deep" ? "#38bdf8" : "#334155"}`,
                  borderRadius: "6px",
                  padding: "12px",
                  color: "#f8fafc",
                  textAlign: "left",
                  cursor: "pointer",
                }}
              >
                <div style={{ fontWeight: 700, color: scanDepth === "deep" ? "#38bdf8" : "#94a3b8" }}>🛡️ Advanced Deep Pentest Mode (Recommended)</div>
                <div style={{ fontSize: "0.75rem", color: "#64748b", marginTop: "4px" }}>
                  25+ Sensitive Endpoint Probes, Active XSS/SQLi/CORS/GraphQL Injection Probes, Cookie Flag Audits, Extended Port Sweep & CVE Correlation.
                </div>
              </button>
              <button
                type="button"
                onClick={() => setScanDepth("standard")}
                style={{
                  background: scanDepth === "standard" ? "linear-gradient(135deg, #0284c722 0%, #0369a133 100%)" : "#1e293b",
                  border: `2px solid ${scanDepth === "standard" ? "#38bdf8" : "#334155"}`,
                  borderRadius: "6px",
                  padding: "12px",
                  color: "#f8fafc",
                  textAlign: "left",
                  cursor: "pointer",
                }}
              >
                <div style={{ fontWeight: 700, color: scanDepth === "standard" ? "#38bdf8" : "#94a3b8" }}>⚡ Standard Surface Sweep</div>
                <div style={{ fontSize: "0.75rem", color: "#64748b", marginTop: "4px" }}>
                  Fast surface port discovery and basic HTTP header security policy checks.
                </div>
              </button>
            </div>
          </div>

          {/* Submit Button */}
          <div style={{ display: "flex", alignItems: "flex-end", gridColumn: "1 / -1", marginTop: "8px" }}>
            <button
              type="submit"
              disabled={submitting}
              style={{
                background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
                color: "#ffffff",
                border: "none",
                padding: "12px 24px",
                borderRadius: "6px",
                fontWeight: 600,
                cursor: submitting ? "not-allowed" : "pointer",
                transition: "opacity 0.2s",
              }}
            >
              {submitting ? "Queuing & Starting Deep Pentest Engine..." : scanDepth === "deep" ? "🛡️ Launch Advanced Deep Pentest" : ENGINE_OPTIONS[engine].buttonLabel}
            </button>
          </div>
        </form>

        {message.text && (
          <div
            style={{
              marginTop: "16px",
              padding: "12px",
              borderRadius: "6px",
              background: message.type === "error" ? "#451a1a" : "#14532d",
              color: message.type === "error" ? "#fca5a5" : "#86efac",
              border: `1px solid ${message.type === "error" ? "#7f1d1d" : "#166534"}`,
            }}
          >
            {message.text}
          </div>
        )}
      </section>

      {/* Active & Historical Scan Jobs List */}
      <section className="panel" style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
          <div>
            <h3 style={{ color: "#f8fafc", margin: 0, fontSize: "1.25rem" }}>Scan Jobs & Real-Time Telemetry</h3>
            <p style={{ color: "#64748b", margin: "4px 0 0 0", fontSize: "0.875rem" }}>
              Live 2-second progress polling against PostgreSQL database
            </p>
          </div>
          <button
            onClick={fetchScanJobs}
            style={{ background: "#1e293b", color: "#38bdf8", border: "1px solid #334155", padding: "6px 16px", borderRadius: "6px", cursor: "pointer" }}
          >
            Refresh List
          </button>
        </div>

        <div className="table-wrap" style={{ overflowX: "auto" }}>
          <table className="table" style={{ width: "100%", borderCollapse: "collapse", color: "#cbd5e1" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #334155", textAlign: "left" }}>
                <th style={{ padding: "12px" }}>Scan Name</th>
                <th style={{ padding: "12px" }}>Engine</th>
                <th style={{ padding: "12px" }}>Target</th>
                <th style={{ padding: "12px" }}>Target Type</th>
                <th style={{ padding: "12px" }}>Status</th>
                <th style={{ padding: "12px", width: "180px" }}>Progress</th>
                <th style={{ padding: "12px" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scanJobs.map((job) => {
                const statusColor =
                  job.status === "COMPLETED"
                    ? "#22c55e"
                    : job.status === "RUNNING"
                    ? "#38bdf8"
                    : job.status === "FAILED"
                    ? "#ef4444"
                    : "#eab308";

                return (
                  <tr key={job.id} style={{ borderBottom: "1px solid #1e293b" }}>
                    <td style={{ padding: "12px", fontWeight: 600, color: "#f8fafc" }}>{job.name}</td>
                    <td style={{ padding: "12px" }}>
                      <span style={{ background: "#1e293b", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem", color: "#38bdf8" }}>
                        {job.engine}
                      </span>
                    </td>
                    <td style={{ padding: "12px", fontFamily: "monospace" }}>{job.target}</td>
                    <td style={{ padding: "12px" }}>{job.target_type}</td>
                    <td style={{ padding: "12px" }}>
                      <span
                        style={{
                          background: `${statusColor}22`,
                          color: statusColor,
                          border: `1px solid ${statusColor}44`,
                          padding: "2px 8px",
                          borderRadius: "12px",
                          fontSize: "0.75rem",
                          fontWeight: 700,
                        }}
                      >
                        {job.status}
                      </span>
                    </td>
                    <td style={{ padding: "12px" }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <div style={{ flex: 1, background: "#1e293b", height: "8px", borderRadius: "4px", overflow: "hidden" }}>
                            <div
                              style={{
                                width: `${Math.min(100, Math.max(0, job.progress || 0))}%`,
                                background: job.status === "RUNNING"
                                  ? "linear-gradient(90deg, #38bdf8 0%, #0284c7 100%)"
                                  : statusColor,
                                height: "100%",
                                transition: "width 0.5s ease-in-out",
                                boxShadow: job.status === "RUNNING" ? "0 0 8px #38bdf888" : "none",
                              }}
                            />
                          </div>
                          <span style={{ fontSize: "0.8rem", color: "#94a3b8", fontWeight: 700, width: "36px" }}>{job.progress || 0}%</span>
                        </div>
                        {job.status === "RUNNING" && (
                          <span style={{ fontSize: "0.7rem", color: "#38bdf8", fontStyle: "italic" }}>
                            {job.progress >= 70 ? "Correlating CVEs & saving findings..." : "Active port discovery & probing..."}
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ padding: "12px" }}>
                      <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                        <button
                          onClick={() => {
                            const tabKey = job.engine === "Network" ? "openvas" : (job.engine === "Web" ? "zap" : (job.engine === "Mobile" ? "mobsf" : "all"));
                            const targetQuery = job.target ? `&search=${encodeURIComponent(job.target)}` : "";
                            navigate(`/findings?tab=${tabKey}${targetQuery}`);
                          }}
                          style={{
                            background: "linear-gradient(135deg, #10b98122 0%, #05966922 100%)",
                            color: "#34d399",
                            border: "1px solid #10b98144",
                            padding: "4px 10px",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "0.75rem",
                            fontWeight: 700,
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                          title="View findings discovered by this scan"
                        >
                          🔍 View Findings
                        </button>
                        <button
                          onClick={() => handleRescan(job.id)}
                          style={{ background: "#0284c722", color: "#38bdf8", border: "1px solid #0284c744", padding: "4px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem", fontWeight: 600 }}
                        >
                          Rescan
                        </button>
                        {["PENDING", "RUNNING"].includes(job.status) && (
                          <button
                            onClick={() => handleCancelScan(job.id)}
                            style={{ background: "#451a1a", color: "#fca5a5", border: "1px solid #7f1d1d", padding: "4px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}
                          >
                            Cancel
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteScan(job.id)}
                          style={{ background: "#1e293b", color: "#64748b", border: "1px solid #334155", padding: "4px 10px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}

              {!loading && scanJobs.length === 0 && (
                <tr>
                  <td colSpan="7" style={{ textAlign: "center", padding: "32px", color: "#64748b" }}>
                    No scans found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

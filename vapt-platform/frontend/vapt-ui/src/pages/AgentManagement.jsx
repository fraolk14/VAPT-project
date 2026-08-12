import { useEffect, useState } from "react";
import api from "../api/client";

export default function AgentManagement() {
  const [devices, setDevices] = useState([]);
  const [feedback, setFeedback] = useState("");
  const [tokenModal, setTokenModal] = useState(false);
  const [generatedToken, setGeneratedToken] = useState("");

  const fetchDevices = () => {
    api.get("/agent/devices")
      .then((res) => setDevices(res.data))
      .catch(() => setDevices([]));
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleGenerateToken = async () => {
    try {
      const res = await api.post("/agent/tokens/generate", { created_by: "admin", ttl_hours: 72 });
      setGeneratedToken(res.data.token);
      setTokenModal(true);
      setFeedback("Single-use enrollment token generated.");
    } catch (error) {
      setFeedback("Failed to generate enrollment token.");
    }
  };

  const handleRevokeDevice = async (deviceId, hostname) => {
    if (!window.confirm(`Are you sure you want to revoke credentials for '${hostname}'? Revoked agents will immediately fail checkin.`)) {
      return;
    }
    try {
      await api.post(`/agent/devices/${deviceId}/revoke`);
      setFeedback(`Device '${hostname}' credential has been revoked.`);
      fetchDevices();
    } catch (error) {
      setFeedback("Failed to revoke agent device.");
    }
  };

  const activeCount = devices.filter((d) => d.status === "active").length;
  const revokedCount = devices.filter((d) => d.status === "revoked").length;

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Windows Endpoint Management</p>
            <h2>VAP Agent Fleet & Deployment</h2>
          </div>
          <div className="table-controls">
            <button type="button" className="scan-action scan-action--resume" onClick={handleGenerateToken}>
              Generate Enrollment Token
            </button>
            <a href="/api/agent/download" className="scan-action scan-action--view" download>
              Download Windows Agent (.exe)
            </a>
            <a href={`/api/agent/installer-script${generatedToken ? `?token=${generatedToken}` : ""}`} className="scan-action scan-action--view" download>
              Download Intune / GPO Script (.ps1)
            </a>
          </div>
        </div>
        <div className="metrics-grid">
          <article className="metric-card"><span>Total Registered Devices</span><strong>{devices.length}</strong><small>PostgreSQL agent_devices</small></article>
          <article className="metric-card"><span>Active Managed Agents</span><strong>{activeCount}</strong><small>Active check-in credentials</small></article>
          <article className="metric-card"><span>Revoked Devices</span><strong>{revokedCount}</strong><small>Blocked check-in credentials</small></article>
          <article className="metric-card"><span>Service Architecture</span><strong>Go Native</strong><small>Scoped Windows Service</small></article>
        </div>
      </div>

      {feedback ? <p className="scan-feedback scan-feedback--success">{feedback}</p> : null}

      {/* Generated Token Modal */}
      {tokenModal ? (
        <div className="panel" style={{ border: "1px solid var(--accent, #4fd1c5)", background: "rgba(15, 23, 42, 0.95)" }}>
          <div className="panel__header">
            <div>
              <p className="eyebrow">Single-Use Enrollment Token</p>
              <h2>Deployment Credential Token</h2>
            </div>
            <button type="button" className="scan-action scan-action--pause" onClick={() => setTokenModal(false)}>Close</button>
          </div>
          <p className="empty-copy">Use this single-use enrollment token during GPO, Intune, or manual agent deployment:</p>
          <div style={{ background: "#0f172a", padding: "12px", borderRadius: "6px", fontFamily: "monospace", fontSize: "1.1rem", color: "#4fd1c5", wordBreak: "break-all" }}>
            {generatedToken}
          </div>
          <div style={{ marginTop: "12px" }}>
            <p className="empty-copy">Command-line enrollment example:</p>
            <code style={{ display: "block", background: "#1e293b", padding: "10px", borderRadius: "4px", color: "#e2e8f0" }}>
              vap-agent.exe enroll --url "http://localhost:18080" --token "{generatedToken}"
            </code>
          </div>
        </div>
      ) : null}

      {/* Devices Inventory Table */}
      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Registered Endpoint Fleet</p>
            <h2>Managed Agent Devices ({devices.length})</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Device ID</th>
                <th>Status</th>
                <th>IP Address</th>
                <th>OS Info</th>
                <th>First Seen</th>
                <th>Last Check-in</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr key={device.id}>
                  <td data-label="Hostname"><strong>{device.hostname}</strong></td>
                  <td data-label="Device ID"><code>{device.device_id}</code></td>
                  <td data-label="Status">
                    <span className={`pill pill--${device.status === "active" ? "low" : "critical"}`}>
                      {device.status.toUpperCase()}
                    </span>
                  </td>
                  <td data-label="IP Address"><code>{device.ip_address || "127.0.0.1"}</code></td>
                  <td data-label="OS Info">{device.os_info || "Windows Endpoint"}</td>
                  <td data-label="First Seen">{new Date(device.first_seen).toLocaleString()}</td>
                  <td data-label="Last Check-in">{new Date(device.last_seen).toLocaleString()}</td>
                  <td data-label="Action">
                    {device.status === "active" ? (
                      <button
                        type="button"
                        className="scan-action scan-action--pause"
                        onClick={() => handleRevokeDevice(device.device_id, device.hostname)}
                      >
                        Revoke Credential
                      </button>
                    ) : (
                      <span className="pill pill--info">REVOKED</span>
                    )}
                  </td>
                </tr>
              ))}
              {!devices.length ? (
                <tr>
                  <td colSpan="8">
                    <p className="empty-copy">No agent devices registered in PostgreSQL database yet. Generate an enrollment token above to deploy agents.</p>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

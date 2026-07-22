import { useEffect, useMemo, useState } from "react";

import api from "../api/client";

function severityWeight(severity) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] || 0;
}

export default function UnauthorizedSoftware({ summary, assets = [] }) {
  const [riskFilter, setRiskFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [inventory, setInventory] = useState([]);
  const [ingestForm, setIngestForm] = useState({
    endpoint_name: "",
    hostname: "",
    ip_address: "",
    os_name: "",
    installed_apps: "",
    approved_baseline: "",
  });
  const [feedback, setFeedback] = useState("");

  useEffect(() => {
    api.get("/posture/unauthorized-software/inventory").then((response) => setInventory(response.data)).catch(() => {});
  }, []);

  const rows = useMemo(() => {
    return [...(summary?.detected_apps || [])]
      .filter((item) => riskFilter === "all" || item.severity === riskFilter)
      .filter((item) => `${item.label} ${item.value} ${item.metadata?.hostname || ""} ${item.metadata?.reason || ""}`.toLowerCase().includes(query.trim().toLowerCase()))
      .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
  }, [summary?.detected_apps, riskFilter, query]);

  const selected = useMemo(() => rows.find((item) => `${item.label}-${item.value}` === selectedKey) || rows[0] || null, [rows, selectedKey]);
  const recommendedActions = useMemo(() => {
    if (!selected) return [];
    const actions = [];
    if (severityWeight(selected.severity) >= 3) actions.push("Contain the endpoint or remove the software before returning the host to normal operations.");
    if (selected.metadata?.baseline_status === "not_in_baseline" || selected.metadata?.baseline_status === "not_approved") {
      actions.push("Compare the detected software against the approved baseline and document an explicit approval or removal decision.");
    }
    if (selected.metadata?.source === "manual-agent-import") {
      actions.push("Re-run endpoint inventory after remediation to confirm the application is no longer present.");
    }
    actions.push(selected.metadata?.recommended_action || "Validate ownership and close the software drift through approval or removal.");
    return [...new Set(actions)];
  }, [selected]);

  const relatedAsset = useMemo(() => {
    if (!selected) return null;
    const needle = `${selected.value} ${selected.metadata?.hostname || ""}`.toLowerCase();
    return (assets || []).find((asset) => `${asset.asset_name} ${asset.hostname || ""} ${asset.ip_address || ""}`.toLowerCase().includes(needle) || needle.includes(`${asset.hostname || asset.ip_address || ""}`.toLowerCase())) || null;
  }, [assets, selected]);

  const ingestInventory = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/posture/unauthorized-software/ingest", {
        endpoint_name: ingestForm.endpoint_name,
        hostname: ingestForm.hostname || null,
        ip_address: ingestForm.ip_address || null,
        os_name: ingestForm.os_name || null,
        source: "manual-agent-import",
        installed_apps: ingestForm.installed_apps.split("\n").map((item) => item.trim()).filter(Boolean),
        approved_baseline: ingestForm.approved_baseline.split("\n").map((item) => item.trim()).filter(Boolean),
      });
      setInventory((current) => [response.data, ...current]);
      setIngestForm({ endpoint_name: "", hostname: "", ip_address: "", os_name: "", installed_apps: "", approved_baseline: "" });
      setFeedback(`Inventory analyzed for ${response.data.endpoint_name}.`);
    } catch (error) {
      setFeedback(error?.response?.data?.detail || "Unable to ingest endpoint inventory right now.");
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Unauthorized software governance</p>
            <h2>Application and endpoint review</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <article className="metric-card"><span>Managed endpoints</span><strong>{summary?.managed_endpoints || 0}</strong><small>Endpoints with inventory context</small></article>
          <article className="metric-card"><span>Unauthorized apps</span><strong>{summary?.unauthorized_apps || 0}</strong><small>Software outside the approved baseline</small></article>
          <article className="metric-card"><span>High-risk tools</span><strong>{summary?.high_risk_apps || 0}</strong><small>Remote access or offensive tooling</small></article>
          <article className="metric-card"><span>Baseline coverage</span><strong>{summary?.baseline_coverage || 0}</strong><small>Endpoints with approved software lists</small></article>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Detection queue</p>
            <h2>Detected software</h2>
          </div>
          <div className="table-controls">
            <input className="scan-input" placeholder="Search application, endpoint, reason" value={query} onChange={(event) => setQuery(event.target.value)} />
            <select className="scan-select" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
              <option value="all">All risk levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Application</th>
                <th>Endpoint</th>
                <th>Severity</th>
                <th>Baseline</th>
                <th>Reason</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={`${item.label}-${item.value}`} className={selected?.label === item.label && selected?.value === item.value ? "finding-row--selected" : ""} onClick={() => setSelectedKey(`${item.label}-${item.value}`)} style={{ cursor: "pointer" }}>
                  <td data-label="Application"><strong>{item.label}</strong></td>
                  <td data-label="Endpoint">{item.value}</td>
                  <td data-label="Severity"><span className={`pill pill--${item.severity}`}>{item.severity}</span></td>
                  <td data-label="Baseline">{item.metadata?.baseline_status || "review_required"}</td>
                  <td data-label="Reason">{item.metadata?.reason || "Baseline drift or risky software detected."}</td>
                  <td data-label="Source">{item.metadata?.source || "Asset tag / scan telemetry"}</td>
                </tr>
              ))}
              {!rows.length ? <tr><td colSpan="6"><p className="empty-copy">No unauthorized software matched the current filter.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Selected application</p>
            <h2>{selected?.label || "No application selected"}</h2>
          </div>
        </div>
        {selected ? (
          <div className="finding-detail-grid finding-detail-grid--single">
            <article className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Application</span><strong>{selected.label}</strong></div>
                <div className="coverage-row"><span>Endpoint</span><strong>{selected.value}</strong></div>
                <div className="coverage-row"><span>Severity</span><strong>{selected.severity}</strong></div>
                <div className="coverage-row"><span>Baseline status</span><strong>{selected.metadata?.baseline_status || "review_required"}</strong></div>
                <div className="coverage-row"><span>Hostname</span><strong>{selected.metadata?.hostname || relatedAsset?.hostname || "n/a"}</strong></div>
                <div className="coverage-row"><span>Owner</span><strong>{selected.metadata?.owner || relatedAsset?.owner || "Unassigned"}</strong></div>
                <div className="coverage-row"><span>Reason</span><strong>{selected.metadata?.reason || "Baseline drift detected"}</strong></div>
              </div>
            </article>
            <article className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Endpoint asset</span><strong>{relatedAsset?.asset_name || "No matching asset"}</strong></div>
                <div className="coverage-row"><span>Asset address</span><strong>{relatedAsset?.hostname || relatedAsset?.ip_address || "n/a"}</strong></div>
                <div className="coverage-row"><span>Criticality</span><strong>{relatedAsset?.criticality || "n/a"}</strong></div>
              </div>
              <p className="eyebrow" style={{ marginTop: "16px" }}>Recommended actions</p>
              <div className="coverage-list">
                {recommendedActions.map((action) => (
                  <div className="coverage-row" key={action}>
                    <span>{action}</span>
                    <strong>Action</strong>
                  </div>
                ))}
              </div>
            </article>
          </div>
        ) : <p className="empty-copy">Select a software finding to review its endpoint context and response action.</p>}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Agent or manual intake</p>
            <h2>Submit endpoint inventory</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={ingestInventory}>
          <input className="scan-input" placeholder="Endpoint name" value={ingestForm.endpoint_name} onChange={(event) => setIngestForm((current) => ({ ...current, endpoint_name: event.target.value }))} required />
          <input className="scan-input" placeholder="Hostname" value={ingestForm.hostname} onChange={(event) => setIngestForm((current) => ({ ...current, hostname: event.target.value }))} />
          <input className="scan-input" placeholder="IP address" value={ingestForm.ip_address} onChange={(event) => setIngestForm((current) => ({ ...current, ip_address: event.target.value }))} />
          <input className="scan-input" placeholder="Operating system" value={ingestForm.os_name} onChange={(event) => setIngestForm((current) => ({ ...current, os_name: event.target.value }))} />
          <textarea className="scan-input" rows="5" placeholder="Installed applications, one per line" value={ingestForm.installed_apps} onChange={(event) => setIngestForm((current) => ({ ...current, installed_apps: event.target.value }))} required />
          <textarea className="scan-input" rows="5" placeholder="Approved baseline, one per line" value={ingestForm.approved_baseline} onChange={(event) => setIngestForm((current) => ({ ...current, approved_baseline: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Analyze Inventory</button>
        </form>
        {feedback ? <p className="scan-feedback scan-feedback--success">{feedback}</p> : null}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Recent submissions</p>
            <h2>Endpoint inventories</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>OS</th>
                <th>Installed apps</th>
                <th>Flagged apps</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {inventory.slice(0, 12).map((entry) => (
                <tr key={entry.id}>
                  <td data-label="Endpoint"><strong>{entry.endpoint_name}</strong><p>{entry.hostname || entry.ip_address || "n/a"}</p></td>
                  <td data-label="OS">{entry.os_name || "n/a"}</td>
                  <td data-label="Installed apps">{entry.installed_apps?.length || 0}</td>
                  <td data-label="Flagged apps">{entry.detected_apps?.length || 0}</td>
                  <td data-label="Status">{entry.status}</td>
                </tr>
              ))}
              {!inventory.length ? <tr><td colSpan="5"><p className="empty-copy">Endpoint inventories will appear here after submission.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

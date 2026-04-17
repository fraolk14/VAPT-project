import { useEffect, useMemo, useState } from "react";

import api from "../api/client";
import Card from "../components/Card";

function severityWeight(severity) {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}

export default function UnauthorizedSoftware({ summary, assets, groups, users }) {
  const [riskFilter, setRiskFilter] = useState("all");
  const [selectedAppKey, setSelectedAppKey] = useState("");
  const [ownershipState, setOwnershipState] = useState({});
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

  const filteredApps = useMemo(() => {
    const items = [...(summary?.detected_apps || [])].sort(
      (left, right) => severityWeight(right.severity) - severityWeight(left.severity)
    );
    return riskFilter === "all" ? items : items.filter((item) => item.severity === riskFilter);
  }, [summary?.detected_apps, riskFilter]);

  const selectedApp = useMemo(() => {
    return filteredApps.find((item) => `${item.label}-${item.value}` === selectedAppKey) || filteredApps[0] || null;
  }, [filteredApps, selectedAppKey]);

  const relatedEndpoint = useMemo(() => {
    if (!selectedApp) return null;
    return (assets || []).find((asset) => {
      const blob = `${asset.asset_name} ${asset.hostname || ""} ${asset.ip_address || ""}`.toLowerCase();
      return blob.includes(String(selectedApp.value || "").toLowerCase());
    }) || null;
  }, [assets, selectedApp]);

  const ownerSelectionKey = selectedApp ? `${selectedApp.label}-${selectedApp.value}` : "";

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
      setFeedback(`Inventory received for ${response.data.endpoint_name}. ${response.data.detected_apps.length} application(s) require review.`);
    } catch (error) {
      setFeedback(error?.response?.data?.detail || "Unable to ingest endpoint inventory right now.");
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Endpoint governance</p>
            <h2>Unauthorized software</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Managed Endpoints" value={summary?.managed_endpoints || 0} trend="Potential agent coverage targets" />
          <Card title="Unauthorized Apps" value={summary?.unauthorized_apps || 0} trend="Baseline drift across managed inventory" />
          <Card title="High Risk Software" value={summary?.high_risk_apps || 0} trend="Remote access and offensive tools prioritized" />
          <Card title="Baseline Coverage" value={summary?.baseline_coverage || 0} trend="Endpoints with approved software context" />
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Lightweight agent intake</p>
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

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Detection queue</p>
            <h2>Applications</h2>
          </div>
          <select className="scan-select" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
            <option value="all">All risk levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="attack-path-layout">
          <div className="coverage-list">
            {filteredApps.length ? filteredApps.map((item) => {
              const key = `${item.label}-${item.value}`;
              return (
                <button
                  key={key}
                  type="button"
                  className={selectedAppKey === key || (!selectedAppKey && selectedApp?.label === item.label && selectedApp?.value === item.value)
                    ? "coverage-row coverage-row--button is-active"
                    : "coverage-row coverage-row--button"}
                  onClick={() => setSelectedAppKey(key)}
                >
                  <span>
                    {item.label}
                    <p>{item.value}</p>
                  </span>
                  <strong><span className={`pill pill--${item.severity}`}>{item.severity}</span></strong>
                </button>
              );
            }) : <p className="empty-copy">No unauthorized software has been detected for this filter.</p>}
          </div>

          <div className="panel panel--embedded attack-path-detail">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Containment detail</p>
                <h2>{selectedApp?.label || "Select an application"}</h2>
              </div>
            </div>
            {selectedApp ? (
              <div className="attack-path-nodes">
                <article className="attack-path-node">
                  <span className={`pill pill--${selectedApp.severity}`}>{selectedApp.severity}</span>
                  <strong>{selectedApp.value}</strong>
                  <p>{selectedApp.metadata?.owner || "Owner pending"} / {selectedApp.metadata?.classification || "Baseline drift"}</p>
                  <div className="coverage-list">
                    <div className="coverage-row"><span>Assigned user</span>
                      <strong>
                        <select
                          className="scan-select"
                          value={ownershipState[ownerSelectionKey]?.assigned_to || ""}
                          onChange={(event) => setOwnershipState((current) => ({
                            ...current,
                            [ownerSelectionKey]: { ...current[ownerSelectionKey], assigned_to: event.target.value },
                          }))}
                        >
                          <option value="">Unassigned</option>
                          {(users || []).map((entry) => <option key={entry.id} value={entry.username}>{entry.username}</option>)}
                        </select>
                      </strong>
                    </div>
                    <div className="coverage-row"><span>Owning group</span>
                      <strong>
                        <select
                          className="scan-select"
                          value={ownershipState[ownerSelectionKey]?.group_name || ""}
                          onChange={(event) => setOwnershipState((current) => ({
                            ...current,
                            [ownerSelectionKey]: { ...current[ownerSelectionKey], group_name: event.target.value },
                          }))}
                        >
                          <option value="">No group</option>
                          {(groups || []).map((group) => <option key={group.id} value={group.name}>{group.name}</option>)}
                        </select>
                      </strong>
                    </div>
                    <div className="coverage-row"><span>Recommended action</span><strong>{severityWeight(selectedApp.severity) >= 3 ? "Remove / isolate" : "Review baseline"}</strong></div>
                  </div>
                </article>
              </div>
            ) : (
              <p className="empty-copy">Select a detected application to review ownership and containment guidance.</p>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Endpoint context</p>
            <h2>Matched endpoint</h2>
          </div>
        </div>
        <div className="coverage-list">
          {relatedEndpoint ? (
            <>
              <div className="coverage-row"><span>Endpoint</span><strong>{relatedEndpoint.asset_name}</strong></div>
              <div className="coverage-row"><span>Address</span><strong>{relatedEndpoint.hostname || relatedEndpoint.ip_address || "n/a"}</strong></div>
              <div className="coverage-row"><span>Exposure</span><strong>{relatedEndpoint.exposure}</strong></div>
              <div className="coverage-row"><span>Criticality</span><strong>{relatedEndpoint.criticality}</strong></div>
            </>
          ) : (
            <p className="empty-copy">No endpoint record matched the selected application automatically.</p>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Containment tasks</p>
            <h2>Action queue</h2>
          </div>
        </div>
        <div className="coverage-list">
          <div className="coverage-row"><span>Review remote access and admin tooling on managed endpoints</span><strong>Pending</strong></div>
          <div className="coverage-row"><span>Compare installed software against approved baseline</span><strong>Pending</strong></div>
          <div className="coverage-row"><span>Escalate high-risk tools for isolation and removal</span><strong>Pending</strong></div>
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Agent submissions</p>
            <h2>Recent endpoint inventories</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Host</th>
                <th>Apps</th>
                <th>Flags</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {inventory.slice(0, 10).map((entry) => (
                <tr key={entry.id}>
                  <td data-label="Endpoint"><strong>{entry.endpoint_name}</strong><p>{entry.os_name || "OS unknown"}</p></td>
                  <td data-label="Host">{entry.hostname || entry.ip_address || "n/a"}</td>
                  <td data-label="Apps">{entry.installed_apps?.length || 0}</td>
                  <td data-label="Flags">{entry.detected_apps?.length || 0}</td>
                  <td data-label="Status">{entry.status}</td>
                </tr>
              ))}
              {!inventory.length ? <tr><td colSpan="5"><p className="empty-copy">Endpoint agent submissions will appear here after inventory intake.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

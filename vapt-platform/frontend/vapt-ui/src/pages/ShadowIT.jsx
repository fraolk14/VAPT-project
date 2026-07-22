import { useMemo, useState } from "react";

export default function ShadowIT({ summary, assets = [], incidents = [], monitoringEvents = [] }) {
  const [query, setQuery] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const services = useMemo(() => {
    return (summary?.suspicious_services || [])
      .filter((item) => severityFilter === "all" || item.severity === severityFilter)
      .filter((item) => {
        const blob = `${item.label} ${item.value} ${item.metadata?.owner || ""} ${item.metadata?.business_unit || ""} ${(item.metadata?.tags || []).join(" ")} ${item.metadata?.classification || ""}`.toLowerCase();
        return blob.includes(query.trim().toLowerCase());
      })
      .sort((a, b) => {
        const weight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        return (weight[b.severity] || 0) - (weight[a.severity] || 0);
      });
  }, [summary?.suspicious_services, query, severityFilter]);

  const selected = useMemo(() => services.find((item) => `${item.label}-${item.value}` === selectedKey) || services[0] || null, [services, selectedKey]);

  const relatedAssets = useMemo(() => {
    if (!selected) return [];
    const target = `${selected.label} ${selected.value}`.toLowerCase();
    return (assets || []).filter((asset) => `${asset.asset_name} ${asset.hostname || ""} ${asset.ip_address || ""} ${asset.url || ""} ${(asset.tags || []).join(" ")}`.toLowerCase().includes(target) || target.includes(`${asset.hostname || asset.ip_address || asset.url || ""}`.toLowerCase()));
  }, [assets, selected]);

  const relatedSignals = useMemo(() => {
    if (!selected) return [];
    const target = `${selected.label} ${selected.value}`.toLowerCase();
    const signalRows = [
      ...(incidents || []).map((incident) => ({ type: "incident", id: incident.id, title: incident.title, target: incident.target, status: incident.status, severity: incident.severity })),
      ...(monitoringEvents || []).map((event) => ({ type: "event", id: event.id, title: event.event_type, target: event.target, status: event.status, severity: event.severity })),
    ];
    return signalRows.filter((row) => `${row.title} ${row.target}`.toLowerCase().includes(target)).slice(0, 10);
  }, [incidents, monitoringEvents, selected]);

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Shadow IT discovery</p>
            <h2>Unsanctioned services and SaaS exposure</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <article className="metric-card"><span>Unknown services</span><strong>{summary?.unknown_services || 0}</strong><small>Assets or services without clear ownership</small></article>
          <article className="metric-card"><span>External assets</span><strong>{summary?.external_assets || 0}</strong><small>Internet-facing assets under observation</small></article>
          <article className="metric-card"><span>Cloud-connected assets</span><strong>{summary?.cloud_assets || 0}</strong><small>SaaS and cloud surface in inventory</small></article>
          <article className="metric-card"><span>Reviewed services</span><strong>{summary?.reviewed_services || 0}</strong><small>Items already triaged by operators</small></article>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Service inventory</p>
            <h2>Discovery queue</h2>
          </div>
          <div className="table-controls">
            <input className="scan-input" placeholder="Search service, owner, business unit, tag" value={query} onChange={(event) => setQuery(event.target.value)} />
            <select className="scan-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All severities</option>
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
                <th>Service</th>
                <th>Location</th>
                <th>Severity</th>
                <th>Classification</th>
                <th>Owner</th>
                <th>Business Unit</th>
                <th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {services.map((item) => (
                <tr key={`${item.label}-${item.value}`} className={selected?.label === item.label && selected?.value === item.value ? "finding-row--selected" : ""} onClick={() => setSelectedKey(`${item.label}-${item.value}`)} style={{ cursor: "pointer" }}>
                  <td data-label="Service"><strong>{item.label}</strong><p>{(item.metadata?.tags || []).join(", ") || "No tags"}</p></td>
                  <td data-label="Location">{item.value}</td>
                  <td data-label="Severity"><span className={`pill pill--${item.severity}`}>{item.severity}</span></td>
                  <td data-label="Classification">{item.metadata?.classification || "review_required"}</td>
                  <td data-label="Owner">{item.metadata?.owner || "Unassigned"}</td>
                  <td data-label="Business Unit">{item.metadata?.business_unit || "Unknown"}</td>
                  <td data-label="Signals">{item.metadata?.source || "Discovery telemetry"}</td>
                </tr>
              ))}
              {!services.length ? <tr><td colSpan="7"><p className="empty-copy">No shadow IT items matched the current filter.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Selected service</p>
            <h2>{selected?.label || "No service selected"}</h2>
          </div>
        </div>
        {selected ? (
          <div className="finding-detail-grid finding-detail-grid--single">
            <article className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Service</span><strong>{selected.label}</strong></div>
                <div className="coverage-row"><span>Location</span><strong>{selected.value}</strong></div>
                <div className="coverage-row"><span>Severity</span><strong>{selected.severity}</strong></div>
                <div className="coverage-row"><span>Classification</span><strong>{selected.metadata?.classification || "review_required"}</strong></div>
                <div className="coverage-row"><span>Owner</span><strong>{selected.metadata?.owner || "Unassigned"}</strong></div>
                <div className="coverage-row"><span>Business unit</span><strong>{selected.metadata?.business_unit || "Unknown"}</strong></div>
                <div className="coverage-row"><span>Tags</span><strong>{(selected.metadata?.tags || []).join(", ") || "n/a"}</strong></div>
              </div>
            </article>
            <article className="panel panel--embedded">
              <p className="eyebrow">Control gaps</p>
              <div className="coverage-list">
                {selected.metadata?.control_gap?.length ? selected.metadata.control_gap.map((gap) => (
                  <div className="coverage-row" key={gap}>
                    <span>{gap}</span>
                    <strong>Open</strong>
                  </div>
                )) : <div className="coverage-row"><span>No explicit control gap was recorded</span><strong>Review</strong></div>}
                <div className="coverage-row"><span>Recommended action</span><strong>{selected.metadata?.recommended_action || "Validate ownership and decide whether the service should be approved, governed, or removed."}</strong></div>
              </div>
            </article>
          </div>
        ) : <p className="empty-copy">Select a shadow IT item to inspect its current ownership and response actions.</p>}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Matched inventory</p>
            <h2>Related assets and telemetry</h2>
          </div>
        </div>
        <div className="finding-detail-grid">
          <article className="panel panel--embedded">
            <div className="table-wrap">
              <table className="table table--dense">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Address</th>
                    <th>Exposure</th>
                    <th>Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {relatedAssets.map((asset) => (
                    <tr key={asset.id}>
                      <td data-label="Asset">{asset.asset_name}</td>
                      <td data-label="Address">{asset.url || asset.hostname || asset.ip_address || "n/a"}</td>
                      <td data-label="Exposure">{asset.exposure}</td>
                      <td data-label="Owner">{asset.owner || "Unassigned"}</td>
                    </tr>
                  ))}
                  {!relatedAssets.length ? <tr><td colSpan="4"><p className="empty-copy">No related assets were matched for this service.</p></td></tr> : null}
                </tbody>
              </table>
            </div>
          </article>
          <article className="panel panel--embedded">
            <div className="table-wrap">
              <table className="table table--dense">
                <thead>
                  <tr>
                    <th>Signal</th>
                    <th>Target</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {relatedSignals.map((signal) => (
                    <tr key={`${signal.type}-${signal.id}`}>
                      <td data-label="Signal">{signal.title}</td>
                      <td data-label="Target">{signal.target}</td>
                      <td data-label="Severity">{signal.severity}</td>
                      <td data-label="Status">{signal.status}</td>
                    </tr>
                  ))}
                  {!relatedSignals.length ? <tr><td colSpan="4"><p className="empty-copy">No related incidents or monitoring events were matched.</p></td></tr> : null}
                </tbody>
              </table>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
}

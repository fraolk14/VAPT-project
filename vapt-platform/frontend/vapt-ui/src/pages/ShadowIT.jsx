import { useMemo, useState } from "react";

import Card from "../components/Card";

function severityWeight(severity) {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}

export default function ShadowIT({ summary, assets, incidents, monitoringEvents }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedServiceKey, setSelectedServiceKey] = useState("");
  const [triageState, setTriageState] = useState({});
  const [serviceNotes, setServiceNotes] = useState({});

  const suspiciousServices = useMemo(() => {
    const items = [...(summary?.suspicious_services || [])].sort(
      (left, right) => severityWeight(right.severity) - severityWeight(left.severity)
    );
    return severityFilter === "all" ? items : items.filter((item) => item.severity === severityFilter);
  }, [summary?.suspicious_services, severityFilter]);

  const selectedService = useMemo(() => {
    return suspiciousServices.find((item) => `${item.label}-${item.value}` === selectedServiceKey) || suspiciousServices[0] || null;
  }, [selectedServiceKey, suspiciousServices]);

  const relatedAssets = useMemo(() => {
    if (!selectedService) return [];
    const fingerprint = `${selectedService.label} ${selectedService.value} ${selectedService.metadata?.tags?.join(" ") || ""}`.toLowerCase();
    return (assets || []).filter((asset) => {
      const blob = `${asset.asset_name} ${asset.hostname || ""} ${asset.ip_address || ""} ${asset.url || ""} ${asset.tags?.join(" ") || ""}`.toLowerCase();
      return blob.includes((selectedService.value || "").toLowerCase()) || blob.includes((selectedService.label || "").toLowerCase()) || selectedService.metadata?.tags?.some((tag) => blob.includes(String(tag).toLowerCase())) || fingerprint.includes(blob);
    });
  }, [assets, selectedService]);

  const relatedIncidents = useMemo(() => {
    if (!selectedService) return [];
    return (incidents || []).filter((incident) => {
      const blob = `${incident.title} ${incident.target} ${incident.summary || ""}`.toLowerCase();
      return blob.includes((selectedService.value || "").toLowerCase()) || blob.includes((selectedService.label || "").toLowerCase());
    }).slice(0, 5);
  }, [incidents, selectedService]);

  const relatedEvents = useMemo(() => {
    if (!selectedService) return [];
    return (monitoringEvents || []).filter((event) => {
      const blob = `${event.target} ${event.event_type} ${event.source}`.toLowerCase();
      return blob.includes((selectedService.value || "").toLowerCase()) || blob.includes((selectedService.label || "").toLowerCase());
    }).slice(0, 6);
  }, [monitoringEvents, selectedService]);

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Discovery posture</p>
            <h2>Shadow IT</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="External Assets" value={summary?.external_assets || 0} trend="Internet-facing footprint under watch" />
          <Card title="Cloud Footprint" value={summary?.cloud_assets || 0} trend="Cloud-connected inventory observed" />
          <Card title="Unknown Services" value={summary?.unknown_services || 0} trend="Unowned or unsanctioned services detected" />
          <Card title="Reviewed Services" value={summary?.reviewed_services || 0} trend="Discovery items triaged by operators" />
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Discovery findings</p>
            <h2>Suspicious services</h2>
          </div>
          <select className="scan-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="attack-path-layout">
          <div className="coverage-list">
            {suspiciousServices.length ? suspiciousServices.map((item) => {
              const key = `${item.label}-${item.value}`;
              return (
                <button
                  key={key}
                  type="button"
                  className={selectedServiceKey === key || (!selectedServiceKey && selectedService?.label === item.label && selectedService?.value === item.value)
                    ? "coverage-row coverage-row--button is-active"
                    : "coverage-row coverage-row--button"}
                  onClick={() => setSelectedServiceKey(key)}
                >
                  <span>
                    {item.label}
                    <p>{item.value}</p>
                  </span>
                  <strong><span className={`pill pill--${item.severity}`}>{item.severity}</span></strong>
                </button>
              );
            }) : <p className="empty-copy">No suspicious services detected yet.</p>}
          </div>

          <div className="panel panel--embedded attack-path-detail">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Service drill-down</p>
                <h2>{selectedService?.label || "Select a service"}</h2>
              </div>
            </div>
            {selectedService ? (
              <div className="attack-path-nodes">
                <article className="attack-path-node">
                  <span className={`pill pill--${selectedService.severity}`}>{selectedService.severity}</span>
                  <strong>{selectedService.value}</strong>
                  <p>{selectedService.metadata?.business_unit || selectedService.metadata?.tags?.join(", ") || "Discovery context pending"}</p>
                  <div className="coverage-list">
                    <div className="coverage-row"><span>Triage</span>
                      <strong>
                        <select
                          className="scan-select"
                          value={triageState[`${selectedService.label}-${selectedService.value}`] || "new"}
                          onChange={(event) => setTriageState((current) => ({ ...current, [`${selectedService.label}-${selectedService.value}`]: event.target.value }))}
                        >
                          <option value="new">New</option>
                          <option value="reviewing">Reviewing</option>
                          <option value="approved">Approved SaaS</option>
                          <option value="contain">Contain / block</option>
                        </select>
                      </strong>
                    </div>
                    <div className="coverage-row"><span>Connector hint</span><strong>{Object.keys(summary?.connector_status || {}).filter((name) => String(summary.connector_status[name]).toLowerCase() !== "planned").slice(0, 2).join(", ") || "Heuristic only"}</strong></div>
                  </div>
                  <textarea
                    className="scan-input ai-textarea"
                    placeholder="Record ownership validation, business justification, or offboarding notes"
                    value={serviceNotes[`${selectedService.label}-${selectedService.value}`] || ""}
                    onChange={(event) => setServiceNotes((current) => ({ ...current, [`${selectedService.label}-${selectedService.value}`]: event.target.value }))}
                  />
                </article>
              </div>
            ) : (
              <p className="empty-copy">Choose a suspicious service to inspect related assets, events, and triage notes.</p>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Mapped assets</p>
            <h2>Related inventory</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Address</th>
                <th>Exposure</th>
                <th>Criticality</th>
              </tr>
            </thead>
            <tbody>
              {relatedAssets.map((asset) => (
                <tr key={asset.id}>
                  <td data-label="Asset"><strong>{asset.asset_name}</strong></td>
                  <td data-label="Address">{asset.url || asset.hostname || asset.ip_address || "n/a"}</td>
                  <td data-label="Exposure">{asset.exposure}</td>
                  <td data-label="Criticality">{asset.criticality}</td>
                </tr>
              ))}
              {!relatedAssets.length ? <tr><td colSpan="4"><p className="empty-copy">No directly related assets were matched for the selected service.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Operational signals</p>
            <h2>Incidents and events</h2>
          </div>
        </div>
        <div className="coverage-list">
          {relatedIncidents.map((incident) => (
            <div className="coverage-row" key={incident.id}>
              <span>{incident.title}<p>{incident.target}</p></span>
              <strong>{incident.severity} / {incident.status}</strong>
            </div>
          ))}
          {relatedEvents.map((event) => (
            <div className="coverage-row" key={event.id}>
              <span>{event.event_type}<p>{event.target}</p></span>
              <strong>{event.source} / {event.status}</strong>
            </div>
          ))}
          {!relatedIncidents.length && !relatedEvents.length ? <p className="empty-copy">No correlated incidents or monitoring events matched the selected service yet.</p> : null}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Connector posture</p>
            <h2>Discovery coverage</h2>
          </div>
        </div>
        <div className="coverage-list">
          {Object.entries(summary?.connector_status || {}).map(([label, value]) => (
            <div className="coverage-row" key={label}>
              <span>{label.replaceAll("_", " ")}</span>
              <strong>{value}</strong>
            </div>
          ))}
          {!Object.keys(summary?.connector_status || {}).length ? <p className="empty-copy">Connector health will appear here as discovery sources are configured.</p> : null}
        </div>
      </div>
    </section>
  );
}

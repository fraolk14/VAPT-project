import { useMemo, useState } from "react";

import Card from "../components/Card";

function severityWeight(severity) {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

export default function Misconfigurations({ summary, findings, compliance }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedItemKey, setSelectedItemKey] = useState("");

  const filteredItems = useMemo(() => {
    const items = [...(summary?.top_items || [])].sort(
      (left, right) => severityWeight(right.severity) - severityWeight(left.severity)
    );
    return severityFilter === "all" ? items : items.filter((item) => item.severity === severityFilter);
  }, [summary?.top_items, severityFilter]);

  const selectedItem = useMemo(() => {
    return filteredItems.find((item) => `${item.label}-${item.value}` === selectedItemKey) || filteredItems[0] || null;
  }, [filteredItems, selectedItemKey]);

  const relatedFindings = useMemo(() => {
    if (!selectedItem) return [];
    const tokens = [
      String(selectedItem.label || "").toLowerCase(),
      String(selectedItem.value || "").toLowerCase(),
      ...(selectedItem.metadata?.compliance_map || []).map((entry) => String(entry).toLowerCase()),
    ].filter(Boolean);
    return (findings || []).filter((finding) => {
      const blob = `${finding.title} ${finding.cve_id || ""} ${finding.description || ""} ${JSON.stringify(finding.finding_metadata || {})}`.toLowerCase();
      return tokens.some((token) => blob.includes(token));
    }).slice(0, 12);
  }, [findings, selectedItem]);

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Configuration posture</p>
            <h2>Misconfigurations</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Weak TLS" value={summary?.weak_tls || 0} trend="Transport and cipher posture" />
          <Card title="Exposed Services" value={summary?.exposed_services || 0} trend="Ports, protocols, and exposure" />
          <Card title="Auth Signals" value={summary?.auth_issues || 0} trend="Authentication and session weaknesses" />
          <Card title="Cloud Findings" value={summary?.cloud_findings || 0} trend="Cloud configuration drift under watch" />
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Category watchlist</p>
            <h2>Configuration classes</h2>
          </div>
        </div>
        <div className="coverage-list">
          {Object.entries(summary?.categories || {}).map(([label, count]) => (
            <div className="coverage-row" key={label}>
              <span>{label.replaceAll("_", " ")}</span>
              <strong>{count}</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Priority items</p>
            <h2>Misconfiguration queue</h2>
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
            {filteredItems.length ? filteredItems.map((item) => {
              const key = `${item.label}-${item.value}`;
              return (
                <button
                  key={key}
                  type="button"
                  className={selectedItemKey === key || (!selectedItemKey && selectedItem?.label === item.label && selectedItem?.value === item.value)
                    ? "coverage-row coverage-row--button is-active"
                    : "coverage-row coverage-row--button"}
                  onClick={() => setSelectedItemKey(key)}
                >
                  <span>
                    {item.label}
                    <p>{item.value}</p>
                  </span>
                  <strong><span className={`pill pill--${item.severity}`}>{item.severity}</span></strong>
                </button>
              );
            }) : <p className="empty-copy">No misconfiguration findings are available for this filter.</p>}
          </div>

          <div className="panel panel--embedded attack-path-detail">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Hardening detail</p>
                <h2>{selectedItem?.label || "Select a misconfiguration"}</h2>
              </div>
            </div>
            {selectedItem ? (
              <div className="attack-path-nodes">
                <article className="attack-path-node">
                  <span className={`pill pill--${selectedItem.severity}`}>{selectedItem.severity}</span>
                  <strong>{selectedItem.value}</strong>
                  <p>{selectedItem.metadata?.compliance_map?.join(", ") || "Compliance mapping pending"}</p>
                  <div className="coverage-list">
                    <div className="coverage-row"><span>Remediation task</span><strong>{severityWeight(selectedItem.severity) >= 3 ? "Escalate and validate" : "Schedule hardening"}</strong></div>
                    <div className="coverage-row"><span>Frameworks</span><strong>{selectedItem.metadata?.compliance_map?.length || 0} linked</strong></div>
                  </div>
                </article>
              </div>
            ) : (
              <p className="empty-copy">Choose a configuration issue to inspect mappings and related findings.</p>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Mapped findings</p>
            <h2>Normalized findings</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {relatedFindings.map((finding) => (
                <tr key={finding.id}>
                  <td data-label="Finding"><strong>{finding.title}</strong><p>{finding.cve_id || "No CVE"}</p></td>
                  <td data-label="Source">{finding.source}</td>
                  <td data-label="Severity"><span className={`pill pill--${finding.severity || "info"}`}>{finding.severity || "info"}</span></td>
                  <td data-label="Status">{finding.status}</td>
                </tr>
              ))}
              {!relatedFindings.length ? <tr><td colSpan="4"><p className="empty-copy">No normalized findings matched the selected configuration issue yet.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Compliance automation</p>
            <h2>Framework coverage</h2>
          </div>
        </div>
        <div className="coverage-list">
          {Object.entries(compliance?.frameworks || {}).map(([framework, count]) => (
            <div className="coverage-row" key={framework}>
              <span>{framework}</span>
              <strong>{count}</strong>
            </div>
          ))}
          {!Object.keys(compliance?.frameworks || {}).length ? <p className="empty-copy">Framework coverage appears here as compliance assessments are mapped.</p> : null}
        </div>
      </div>
    </section>
  );
}

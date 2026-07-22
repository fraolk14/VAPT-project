import { useMemo, useState } from "react";

import { resolveAssetForTarget, resolveOsLabel, targetOf } from "../utils/targetIntel";

function formatWhen(value) {
  if (!value) return "n/a";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "n/a" : parsed.toLocaleString();
}

function isMisconfigurationFinding(finding) {
  const metadata = finding.finding_metadata || {};
  const category = String(finding.category || "").toLowerCase();
  return Boolean(
    metadata.cis_benchmark ||
    metadata.hardening_recommendation ||
    category === "network" ||
    category === "web"
  );
}

export default function Misconfigurations({ findings = [], assets = [] }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState("");

  const rows = useMemo(() => {
    const filtered = (findings || [])
      .filter(isMisconfigurationFinding)
      .filter((finding) => severityFilter === "all" || (finding.severity || "info") === severityFilter)
      .filter((finding) => {
        const blob = [
          finding.title,
          finding.source,
          targetOf(finding),
          finding.finding_metadata?.os_family,
          finding.finding_metadata?.cis_benchmark,
          finding.cve_id,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return blob.includes(search.trim().toLowerCase());
      })
      .sort((left, right) => {
        const rightTime = new Date(right.detected_at || right.last_seen || 0).getTime();
        const leftTime = new Date(left.detected_at || left.last_seen || 0).getTime();
        return rightTime - leftTime;
      });
    return filtered;
  }, [findings, severityFilter, search]);

  const selected = useMemo(() => {
    return rows.find((finding) => finding.id === selectedId) || rows[0] || null;
  }, [rows, selectedId]);

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Verified configuration issues</p>
            <h2>Misconfigurations</h2>
          </div>
          <div className="table-controls">
            <input
              className="scan-input"
              placeholder="Search target, issue, CIS benchmark, CVE"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select className="scan-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Date</th>
                <th>Target</th>
                <th>Issue</th>
                <th>Scanner</th>
                <th>OS Type</th>
                <th>CIS Benchmark</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 30).map((finding) => (
                <tr
                  key={finding.id}
                  className={selected?.id === finding.id ? "finding-row--selected" : ""}
                  onClick={() => setSelectedId(finding.id)}
                  style={{ cursor: "pointer" }}
                >
                  <td data-label="Date">{formatWhen(finding.detected_at || finding.last_seen)}</td>
                  <td data-label="Target">{targetOf(finding)}</td>
                  <td data-label="Issue">
                    <strong>{finding.title}</strong>
                    <p>{finding.cve_id || "No CVE mapped"}</p>
                  </td>
                  <td data-label="Scanner">{finding.source}</td>
                  <td data-label="OS Type">{resolveOsLabel({ asset: resolveAssetForTarget(targetOf(finding), assets), finding, findings, assets, target: targetOf(finding) })}</td>
                  <td data-label="CIS Benchmark">{finding.finding_metadata?.cis_benchmark || "n/a"}</td>
                  <td data-label="Severity">
                    <span className={`pill pill--${finding.severity || "info"}`}>{finding.severity || "info"}</span>
                  </td>
                </tr>
              ))}
              {!rows.length ? (
                <tr>
                  <td colSpan="7">
                    <p className="empty-copy">No concrete misconfiguration findings matched the current filter.</p>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Selected issue</p>
            <h2>{selected?.title || "No issue selected"}</h2>
          </div>
        </div>
        {selected ? (
          <div className="finding-detail-grid finding-detail-grid--single">
            <div className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Target</span><strong>{targetOf(selected)}</strong></div>
                <div className="coverage-row"><span>Scanner</span><strong>{selected.source}</strong></div>
                <div className="coverage-row"><span>OS Type</span><strong>{resolveOsLabel({ asset: resolveAssetForTarget(targetOf(selected), assets), finding: selected, findings, assets, target: targetOf(selected) })}</strong></div>
                <div className="coverage-row"><span>CIS Benchmark</span><strong>{selected.finding_metadata?.cis_benchmark || "n/a"}</strong></div>
                <div className="coverage-row"><span>CVE</span><strong>{selected.cve_id || "n/a"}</strong></div>
                <div className="coverage-row"><span>Severity</span><strong>{selected.severity || "info"}</strong></div>
                <div className="coverage-row"><span>Status</span><strong>{selected.status}</strong></div>
                <div className="coverage-row"><span>Detected</span><strong>{formatWhen(selected.detected_at || selected.last_seen)}</strong></div>
              </div>
            </div>

            <div className="panel panel--embedded">
              <p className="eyebrow">Hardening steps</p>
              <div className="developer-code developer-code--block">
                {selected.finding_metadata?.hardening_recommendation || selected.remediation || "n/a"}
              </div>

              <p className="eyebrow" style={{ marginTop: "16px" }}>Evidence</p>
              <p className="finding-detail-body">{selected.evidence || "n/a"}</p>

              {(selected.finding_metadata?.references || []).length ? (
                <>
                  <p className="eyebrow" style={{ marginTop: "16px" }}>References</p>
                  <div className="coverage-list">
                    {selected.finding_metadata.references.slice(0, 6).map((reference) => (
                      <a key={reference} href={reference} target="_blank" rel="noreferrer" className="coverage-row coverage-row--link">
                        <span>{reference}</span>
                        <strong>Open</strong>
                      </a>
                    ))}
                  </div>
                </>
              ) : null}
            </div>
          </div>
        ) : (
          <p className="empty-copy">Select a misconfiguration row to inspect its exact details and hardening steps.</p>
        )}
      </div>
    </section>
  );
}

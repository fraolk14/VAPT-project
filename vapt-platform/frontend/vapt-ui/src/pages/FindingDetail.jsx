import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import api from "../api/client";

function formatDate(value) {
  if (!value) return "n/a";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return String(value);
  }
}

function targetLabel(finding) {
  if (!finding) return "n/a";
  if (finding.source === "zap") return finding.finding_metadata?.url || finding.finding_metadata?.host || "n/a";
  if (finding.source === "openvas" || finding.source === "network-db") return finding.finding_metadata?.host || `${finding.port}/${finding.protocol}`;
  return finding.finding_metadata?.file || "n/a";
}

function correlationReferences(finding) {
  const references = [];
  const metadata = finding?.finding_metadata || {};
  const correlation = metadata.correlation || {};
  for (const ref of correlation.references || []) {
    if (ref) references.push(ref);
  }
  for (const ref of metadata.reference_links || []) {
    if (ref) references.push(ref);
  }
  return [...new Set(references)];
}

export default function FindingDetail({ findings }) {
  const { findingId } = useParams();
  const [state, setState] = useState({ status: "loading", finding: null });

  useEffect(() => {
    const localMatch = (findings || []).find((item) => item.id === findingId);
    if (localMatch) {
      setState({ status: "ready", finding: localMatch });
      return;
    }

    api
      .get(`/findings/${findingId}`)
      .then((response) => setState({ status: "ready", finding: response.data }))
      .catch(() => setState({ status: "error", finding: null }));
  }, [findingId, findings]);

  const finding = state.finding;
  const correlation = finding?.finding_metadata?.correlation || {};
  const references = useMemo(() => correlationReferences(finding), [finding]);

  if (state.status === "loading") {
    return (
      <section className="panel">
        <p className="empty-copy">Loading vulnerability details...</p>
      </section>
    );
  }

  if (!finding) {
    return (
      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Vulnerability details</p>
            <h2>Finding not available</h2>
          </div>
        </div>
        <p className="empty-copy">The requested finding could not be loaded.</p>
        <Link className="scan-action scan-action--resume" to="/findings">
          Back to Findings
        </Link>
      </section>
    );
  }

  return (
    <section className="section-grid">
      <section className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Vulnerability details</p>
            <h2>{finding.title}</h2>
          </div>
          <Link className="scan-action scan-action--resume" to="/findings">
            Back to Findings
          </Link>
        </div>
        <div className="metrics-grid">
          <article className="metric-card">
            <span>Severity</span>
            <strong>{finding.severity || "info"}</strong>
            <small>Status: {finding.status}</small>
          </article>
          <article className="metric-card">
            <span>CVE</span>
            <strong>{finding.cve_id || "n/a"}</strong>
            <small>CVSS: {finding.cvss_score || "n/a"}</small>
          </article>
          <article className="metric-card">
            <span>Target</span>
            <strong>{targetLabel(finding)}</strong>
            <small>{finding.port}/{finding.protocol}</small>
          </article>
          <article className="metric-card">
            <span>Detected</span>
            <strong>{formatDate(finding.detected_at)}</strong>
            <small>Scan finished: {formatDate(finding.scan_finished_at)}</small>
          </article>
        </div>
      </section>

      <section className="panel finding-detail-page">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Assessment summary</p>
            <h2>Context and remediation</h2>
          </div>
        </div>
        <div className="finding-detail-grid">
          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Evidence</p>
                <h2>Observed details</h2>
              </div>
            </div>
            <p className="finding-detail-body">{finding.evidence || correlation.correlation_summary || "No direct evidence stored."}</p>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Remediation</p>
                <h2>Recommended fix</h2>
              </div>
            </div>
            <p className="finding-detail-body">{finding.remediation || "No remediation steps were stored for this finding yet."}</p>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Correlation</p>
                <h2>Database matches</h2>
              </div>
            </div>
            <div className="coverage-list">
              <div className="coverage-row"><span>Matched CVEs</span><strong>{(correlation.matched_cves || []).join(", ") || finding.cve_id || "n/a"}</strong></div>
              <div className="coverage-row"><span>Sources</span><strong>{(correlation.sources || []).join(", ") || "n/a"}</strong></div>
              <div className="coverage-row"><span>Weaknesses</span><strong>{(correlation.weaknesses || []).join(", ") || "n/a"}</strong></div>
              <div className="coverage-row"><span>Known exploitation</span><strong>{correlation.has_known_exploitation ? "Yes" : "No"}</strong></div>
            </div>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Workflow</p>
                <h2>Ownership and verification</h2>
              </div>
            </div>
            <div className="coverage-list">
              <div className="coverage-row"><span>Assigned user</span><strong>{finding.assigned_to || "Unassigned"}</strong></div>
              <div className="coverage-row"><span>Group</span><strong>{finding.team_name || "No group"}</strong></div>
              <div className="coverage-row"><span>Verification</span><strong>{finding.verification_state || "pending"}</strong></div>
              <div className="coverage-row"><span>Duplicate count</span><strong>{finding.duplicate_count || 1}</strong></div>
            </div>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Reference intelligence</p>
            <h2>Links and raw metadata</h2>
          </div>
        </div>
        <div className="finding-detail-grid finding-detail-grid--single">
          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">References</p>
                <h2>Source material</h2>
              </div>
            </div>
            <div className="coverage-list">
              {references.length ? references.map((reference) => (
                <a key={reference} className="coverage-row coverage-row--link" href={reference} target="_blank" rel="noreferrer">
                  <span>{reference}</span>
                  <strong>Open source</strong>
                </a>
              )) : <p className="empty-copy">No external references were stored for this finding.</p>}
            </div>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Raw metadata</p>
                <h2>Structured finding payload</h2>
              </div>
            </div>
            <pre className="code-block code-block--json">{JSON.stringify(finding.finding_metadata || {}, null, 2)}</pre>
          </article>
        </div>
      </section>
    </section>
  );
}

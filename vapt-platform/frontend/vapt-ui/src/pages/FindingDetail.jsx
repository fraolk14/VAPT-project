import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import api from "../api/client";
import { humanSource, resolveOsLabel, targetOf } from "../utils/targetIntel";

function formatDate(value) {
  if (!value) return "n/a";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "n/a" : parsed.toLocaleString();
}

function referenceList(finding) {
  const metadata = finding?.finding_metadata || {};
  const correlation = metadata.correlation || {};
  const refs = [
    ...(correlation.references || []),
    ...(metadata.references || []),
    ...(metadata.reference_links || []),
  ].filter(Boolean);
  if (finding?.cve_id) {
    refs.unshift(`https://www.cve.org/CVERecord?id=${encodeURIComponent(finding.cve_id)}`);
    refs.unshift(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.cve_id)}`);
  }
  return [...new Set(refs)];
}

export default function FindingDetail({ findings = [], assets = [] }) {
  const { findingId } = useParams();
  const [state, setState] = useState({ status: "loading", finding: null, error: "" });

  useEffect(() => {
    const localMatch = (findings || []).find((item) => String(item.id) === String(findingId));
    if (localMatch) {
      setState({ status: "ready", finding: localMatch, error: "" });
    }

    api
      .get(`/findings/${findingId}`)
      .then((response) => setState({ status: "ready", finding: response.data, error: "" }))
      .catch((error) => setState({ status: "error", finding: null, error: error?.response?.data?.detail || "The requested finding could not be loaded." }));
  }, [findingId, findings]);

  const finding = state.finding;
  const references = useMemo(() => referenceList(finding), [finding]);
  const metadata = finding?.finding_metadata || {};
  const correlation = metadata.correlation || {};
  const relatedAsset = useMemo(() => {
    const target = targetOf(finding);
    return (assets || []).find((asset) => [asset.asset_name, asset.hostname, asset.ip_address, asset.url].filter(Boolean).some((value) => String(value).toLowerCase() === String(target).toLowerCase() || String(value).toLowerCase().includes(String(target).toLowerCase()) || String(target).toLowerCase().includes(String(value).toLowerCase())));
  }, [assets, finding]);

  if (state.status === "loading") {
    return <section className="panel"><p className="empty-copy">Loading finding details...</p></section>;
  }

  if (!finding) {
    return (
      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Finding detail</p>
            <h2>Unable to load finding</h2>
          </div>
          <Link className="scan-action scan-action--resume" to="/findings">Back to Findings</Link>
        </div>
        <p className="empty-copy">{state.error}</p>
      </section>
    );
  }

  return (
    <section className="section-grid">
      <section className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Finding detail</p>
            <h2>{finding.title}</h2>
          </div>
          <Link className="scan-action scan-action--resume" to="/findings">Back to Findings</Link>
        </div>
        <div className="metrics-grid">
          <article className="metric-card">
            <span>Severity</span>
            <strong>{finding.severity || "info"}</strong>
            <small>Status: {finding.status}</small>
          </article>
          <article className="metric-card">
            <span>CVE / CVSS</span>
            <strong>{finding.cve_id || "No CVE"}</strong>
            <small>CVSS: {finding.cvss_score || "n/a"}</small>
          </article>
          <article className="metric-card">
            <span>Target</span>
            <strong>{targetOf(finding)}</strong>
            <small>{humanSource(finding.source)} / {finding.port || "n/a"} {finding.protocol || ""}</small>
          </article>
          <article className="metric-card">
            <span>Detected</span>
            <strong>{formatDate(finding.detected_at)}</strong>
            <small>Resolved: {formatDate(finding.resolved_at)}</small>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Target context</p>
            <h2>Asset and platform</h2>
          </div>
        </div>
        <div className="finding-detail-grid">
          <article className="panel panel--embedded">
            <div className="coverage-list">
              <div className="coverage-row"><span>Target</span><strong>{targetOf(finding)}</strong></div>
              <div className="coverage-row"><span>Asset name</span><strong>{finding.asset_name || relatedAsset?.asset_name || "n/a"}</strong></div>
              <div className="coverage-row"><span>Hostname</span><strong>{finding.target_details?.hostname || relatedAsset?.hostname || metadata.hostname || "n/a"}</strong></div>
              <div className="coverage-row"><span>Host IP</span><strong>{finding.target_details?.host || relatedAsset?.ip_address || metadata.host || metadata.ip_address || "n/a"}</strong></div>
              <div className="coverage-row"><span>URL</span><strong>{finding.target_details?.url || relatedAsset?.url || metadata.url || "n/a"}</strong></div>
              <div className="coverage-row"><span>OS type</span><strong>{resolveOsLabel({ asset: relatedAsset, finding, assets, target: targetOf(finding) })}</strong></div>
              <div className="coverage-row"><span>Service</span><strong>{finding.service || "n/a"}</strong></div>
              <div className="coverage-row"><span>Protocol</span><strong>{finding.protocol || "n/a"}</strong></div>
            </div>
          </article>

          <article className="panel panel--embedded">
            <div className="coverage-list">
              <div className="coverage-row"><span>Scanner</span><strong>{humanSource(finding.source)}</strong></div>
              <div className="coverage-row"><span>Verification</span><strong>{finding.verification_state || "pending"}</strong></div>
              <div className="coverage-row"><span>Assigned to</span><strong>{finding.assigned_to || "Unassigned"}</strong></div>
              <div className="coverage-row"><span>Group</span><strong>{finding.team_name || "n/a"}</strong></div>
              <div className="coverage-row"><span>Resolved by</span><strong>{finding.resolved_by || finding.assigned_to || "n/a"}</strong></div>
              <div className="coverage-row"><span>CIS benchmark</span><strong>{metadata.cis_benchmark || "n/a"}</strong></div>
              <div className="coverage-row"><span>Confidence</span><strong>{finding.confidence || "n/a"}</strong></div>
              <div className="coverage-row"><span>Duplicate count</span><strong>{finding.duplicate_count || 1}</strong></div>
            </div>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Proof and recommendation</p>
            <h2>Validation detail</h2>
          </div>
        </div>
        <div className="finding-detail-grid">
          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Proof</p>
                <h2>Why this finding is true</h2>
              </div>
            </div>
            <p className="finding-detail-body">{finding.evidence || correlation.correlation_summary || "No explicit proof text was stored."}</p>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Recommendation</p>
                <h2>Remediation guidance</h2>
              </div>
            </div>
            <p className="finding-detail-body">{finding.remediation || metadata.hardening_recommendation || "No remediation guidance was stored yet."}</p>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Correlation and raw detail</p>
            <h2>Supporting context</h2>
          </div>
        </div>
        <div className="finding-detail-grid finding-detail-grid--single">
          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">References</p>
                <h2>External source material</h2>
              </div>
            </div>
            <div className="coverage-list">
              {references.length ? references.map((reference) => (
                <a key={reference} className="coverage-row coverage-row--link" href={reference} target="_blank" rel="noreferrer">
                  <span>{reference}</span>
                  <strong>Open</strong>
                </a>
              )) : <p className="empty-copy">No external references were stored for this finding.</p>}
            </div>
          </article>

          <article className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Structured payload</p>
                <h2>Raw metadata</h2>
              </div>
            </div>
            <pre className="code-block code-block--json">{JSON.stringify({ correlation, metadata, target_details: finding.target_details || {} }, null, 2)}</pre>
          </article>
        </div>
      </section>
    </section>
  );
}

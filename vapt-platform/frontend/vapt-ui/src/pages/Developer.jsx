import { useEffect, useMemo, useState } from "react";

import api from "../api/client";
import Card from "../components/Card";

function sourceLabel(source) {
  if (source === "openvas") return "Network Engine";
  if (source === "zap") return "Web Engine";
  if (source === "mobsf") return "Mobile Engine";
  return source;
}

const emptyDebug = {
  scan_name: "",
  tool: "",
  status: "",
  target: "",
  progress: "0",
  error_message: null,
  engine_metadata: {},
  result_summary: {},
  related_findings: [],
  audit_trail: [],
};

export default function Developer({ scans, findings, users, groups, auditLogs = [] }) {
  const [filters, setFilters] = useState({
    scanner: "all",
    severity: "all",
    status: "all",
    verification: "all",
    target: "",
  });
  const [selectedScanId, setSelectedScanId] = useState("");
  const [debugRecord, setDebugRecord] = useState(emptyDebug);
  const [actionMessage, setActionMessage] = useState("");
  const [busy, setBusy] = useState({});
  const [localFindings, setLocalFindings] = useState(findings);
  const [falsePositiveRules, setFalsePositiveRules] = useState([]);
  const [pageSize, setPageSize] = useState(10);
  const [pageIndex, setPageIndex] = useState(0);

  useEffect(() => {
    setLocalFindings(findings);
  }, [findings]);

  useEffect(() => {
    api.get("/findings/false-positive-rules").then((response) => setFalsePositiveRules(response.data)).catch(() => {});
  }, []);

  const filteredFindings = useMemo(() => {
    return localFindings.filter((finding) => {
      const scannerMatch = filters.scanner === "all" || finding.source === filters.scanner;
      const severityMatch = filters.severity === "all" || (finding.severity || "info") === filters.severity;
      const statusMatch = filters.status === "all" || finding.status === filters.status;
      const verificationMatch = filters.verification === "all" || (finding.verification_state || "pending") === filters.verification;
      const targetText = `${finding.finding_metadata?.host || ""} ${finding.finding_metadata?.url || ""} ${finding.finding_metadata?.file || ""} ${finding.title}`.toLowerCase();
      const targetMatch = !filters.target.trim() || targetText.includes(filters.target.trim().toLowerCase());
      return scannerMatch && severityMatch && statusMatch && verificationMatch && targetMatch;
    });
  }, [filters, localFindings]);

  useEffect(() => {
    setPageIndex(0);
  }, [filters, pageSize]);

  const pagedFindings = filteredFindings.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize);
  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
  const failedScans = scans.filter((scan) => scan.status === "failed" || scan.status === "cancelled");

  const loadDebug = async (scanId) => {
    setSelectedScanId(scanId);
    try {
      const response = await api.get(`/scans/${scanId}/debug`);
      setDebugRecord(response.data);
    } catch (error) {
      setActionMessage(error?.response?.data?.detail || "Unable to load raw scan data.");
    }
  };

  const runScanAction = async (scanId, action) => {
    setBusy((current) => ({ ...current, [scanId]: action }));
    try {
      await api.post(`/scans/${scanId}/${action}`);
      setActionMessage(action === "reprocess" ? "Scan findings reprocessed." : "Scan action completed.");
      if (selectedScanId === scanId) await loadDebug(scanId);
    } catch (error) {
      setActionMessage(error?.response?.data?.detail || `Unable to ${action} this scan.`);
    } finally {
      setBusy((current) => {
        const next = { ...current };
        delete next[scanId];
        return next;
      });
    }
  };

  const updateFinding = async (findingId, payload) => {
    setBusy((current) => ({ ...current, [findingId]: "triage" }));
    try {
      const response = await api.patch(`/findings/${findingId}`, payload);
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
      setActionMessage("Finding triage updated.");
    } catch (error) {
      setActionMessage(error?.response?.data?.detail || "Unable to update finding triage.");
    } finally {
      setBusy((current) => {
        const next = { ...current };
        delete next[findingId];
        return next;
      });
    }
  };

  const suppressGlobally = async (findingId) => {
    setBusy((current) => ({ ...current, [findingId]: "suppress" }));
    try {
      const targetFinding = localFindings.find((entry) => entry.id === findingId);
      const response = await api.post(`/findings/${findingId}/suppress-global`);
      setFalsePositiveRules((current) => [response.data, ...current]);
      setLocalFindings((current) => current.map((item) => (
        item.id === findingId || (item.title === targetFinding?.title && item.source === targetFinding?.source)
          ? { ...item, status: "false_positive" }
          : item
      )));
      setActionMessage("Global false-positive rule created.");
    } catch (error) {
      setActionMessage(error?.response?.data?.detail || "Unable to create global false-positive rule.");
    } finally {
      setBusy((current) => {
        const next = { ...current };
        delete next[findingId];
        return next;
      });
    }
  };

  const validateFix = async (findingId) => {
    setBusy((current) => ({ ...current, [findingId]: "validate" }));
    try {
      await api.post(`/findings/${findingId}/validate-fix`);
      setLocalFindings((current) => current.map((item) => (
        item.id === findingId ? { ...item, verification_state: "scheduled" } : item
      )));
      setActionMessage("Validation scan queued.");
    } catch (error) {
      setActionMessage(error?.response?.data?.detail || "Unable to queue validation scan.");
    } finally {
      setBusy((current) => {
        const next = { ...current };
        delete next[findingId];
        return next;
      });
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Hidden operator tooling</p>
            <h2>Developer console</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Tracked Scans" value={scans.length} trend="Raw orchestration visibility" />
          <Card title="Failed / Cancelled" value={failedScans.length} trend="Needs operator inspection" />
          <Card title="Normalized Findings" value={localFindings.length} trend="Available for parser validation" />
          <Card title="Filtered Findings" value={filteredFindings.length} trend="Current developer filter scope" />
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Filters and triage</p>
            <h2>Developer findings workbench</h2>
          </div>
          <div className="table-controls">
            <select className="scan-select" value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))}>
              <option value={10}>10 per page</option>
              <option value={20}>20 per page</option>
            </select>
          </div>
        </div>
        <div className="dashboard-toolbar">
          <select className="scan-select" value={filters.scanner} onChange={(event) => setFilters((current) => ({ ...current, scanner: event.target.value }))}>
            <option value="all">All scanners</option>
            <option value="openvas">Network Engine</option>
            <option value="zap">Web Engine</option>
            <option value="mobsf">Mobile Engine</option>
          </select>
          <select className="scan-select" value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select className="scan-select" value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}>
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="false_positive">False positive</option>
            <option value="resolved">Resolved</option>
          </select>
          <select className="scan-select" value={filters.verification} onChange={(event) => setFilters((current) => ({ ...current, verification: event.target.value }))}>
            <option value="all">All verification states</option>
            <option value="pending">Pending</option>
            <option value="in_review">In Review</option>
            <option value="scheduled">Scheduled</option>
            <option value="verified">Verified</option>
          </select>
          <input className="scan-input" value={filters.target} onChange={(event) => setFilters((current) => ({ ...current, target: event.target.value }))} placeholder="Filter by asset, URL, host, file, or finding title" />
        </div>
        {actionMessage ? <p className="scan-feedback scan-feedback--success">{actionMessage}</p> : null}
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Scanner</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Asset</th>
                <th>Assignment</th>
                <th>Verification</th>
                <th>Controls</th>
              </tr>
            </thead>
            <tbody>
              {pagedFindings.map((finding) => (
                <tr key={finding.id}>
                  <td data-label="Finding">
                    <strong>{finding.title}</strong>
                    <p>{finding.cve_id || finding.display_id || "No CVE mapped"}</p>
                  </td>
                  <td data-label="Scanner">{sourceLabel(finding.source)}</td>
                  <td data-label="Severity"><span className={`pill pill--${finding.severity || "info"}`}>{finding.severity || "info"}</span></td>
                  <td data-label="Status">{finding.status}</td>
                  <td data-label="Asset">{finding.finding_metadata?.host || finding.finding_metadata?.url || finding.finding_metadata?.file || "n/a"}</td>
                  <td data-label="Assignment">{finding.assigned_to || "Unassigned"} / {finding.team_name || "No group"}</td>
                  <td data-label="Verification">{finding.verification_state || "pending"}</td>
                  <td data-label="Controls">
                    <div className="scan-actions">
                      <button type="button" className="scan-action scan-action--cancel" disabled={busy[finding.id] === "triage"} onClick={() => updateFinding(finding.id, { mark_false_positive: true })}>
                        False Positive
                      </button>
                      <button type="button" className="scan-action scan-action--resume" disabled={busy[finding.id] === "triage"} onClick={() => updateFinding(finding.id, { severity: "high", assigned_to: users?.[0]?.username || null, team_name: groups?.[0]?.name || null, verification_state: "in_review" })}>
                        Escalate
                      </button>
                      <button type="button" className="scan-action" disabled={busy[finding.id] === "suppress"} onClick={() => suppressGlobally(finding.id)}>
                        Global Suppress
                      </button>
                      <button type="button" className="scan-action scan-action--resume" disabled={busy[finding.id] === "validate"} onClick={() => validateFix(finding.id)}>
                        Validate Fix
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {!pagedFindings.length ? (
                <tr>
                  <td colSpan="8"><p className="empty-copy">No findings match the current developer filters.</p></td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="pagination-bar">
          <span>Showing {pagedFindings.length ? pageIndex * pageSize + 1 : 0}-{Math.min((pageIndex + 1) * pageSize, filteredFindings.length)} of {filteredFindings.length}</span>
          <div className="scan-actions">
            <button type="button" className="scan-action" disabled={pageIndex === 0} onClick={() => setPageIndex((current) => Math.max(current - 1, 0))}>Previous</button>
            <span className="pagination-page">Page {pageIndex + 1} of {totalPages}</span>
            <button type="button" className="scan-action" disabled={pageIndex >= totalPages - 1} onClick={() => setPageIndex((current) => Math.min(current + 1, totalPages - 1))}>Next</button>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Global suppression</p>
            <h2>False-positive rules</h2>
          </div>
        </div>
        <div className="coverage-list">
          {falsePositiveRules.length ? falsePositiveRules.slice(0, 8).map((rule) => (
            <div className="coverage-row" key={rule.id}>
              <span>{rule.title_pattern}</span>
              <strong>{rule.source || "all"} / {rule.enabled ? "enabled" : "disabled"}</strong>
            </div>
          )) : <p className="empty-copy">Global false-positive rules will appear here after suppression is promoted.</p>}
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Platform auditability</p>
            <h2>Recent audit stream</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.slice(0, 12).map((entry) => (
                <tr key={entry.id}>
                  <td data-label="Time">{new Date(entry.created_at).toLocaleString()}</td>
                  <td data-label="Actor">{entry.actor}</td>
                  <td data-label="Action"><strong>{entry.action}</strong></td>
                  <td data-label="Resource">{entry.resource_type} / {entry.resource_id}</td>
                  <td data-label="Outcome">{entry.outcome}</td>
                </tr>
              ))}
              {!auditLogs.length ? (
                <tr>
                  <td colSpan="5"><p className="empty-copy">Audit events will appear here as operators create users, update findings, and manage scans.</p></td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Raw scan visibility</p>
            <h2>Scan debug inspector</h2>
          </div>
        </div>
        <div className="dashboard-toolbar">
          <select className="scan-select" value={selectedScanId} onChange={(event) => loadDebug(event.target.value)}>
            <option value="">Select a scan record</option>
            {scans.slice(0, 30).map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.scan_name} ({sourceLabel(scan.tool)})
              </option>
            ))}
          </select>
          <button type="button" className="scan-action scan-action--resume" disabled={!selectedScanId || busy[selectedScanId] === "reprocess"} onClick={() => runScanAction(selectedScanId, "reprocess")}>
            {busy[selectedScanId] === "reprocess" ? "Reprocessing..." : "Reprocess Findings"}
          </button>
        </div>
        {selectedScanId ? (
          <div className="developer-grid">
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Raw engine metadata</p>
                  <h2>{debugRecord.scan_name || "Selected scan"}</h2>
                </div>
              </div>
              <code className="developer-code developer-code--block">{JSON.stringify(debugRecord.engine_metadata || {}, null, 2)}</code>
            </div>
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Ingestion summary</p>
                  <h2>{debugRecord.status || "Unknown status"}</h2>
                </div>
              </div>
              <code className="developer-code developer-code--block">{JSON.stringify(debugRecord.result_summary || {}, null, 2)}</code>
              <p className="empty-copy">{debugRecord.error_message || "No parser or API error recorded."}</p>
            </div>
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Normalized findings</p>
                  <h2>Parsed output</h2>
                </div>
              </div>
              <code className="developer-code developer-code--block">{JSON.stringify(debugRecord.related_findings || [], null, 2)}</code>
            </div>
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Audit trail</p>
                  <h2>Operator and engine events</h2>
                </div>
              </div>
              <code className="developer-code developer-code--block">{JSON.stringify(debugRecord.audit_trail || [], null, 2)}</code>
            </div>
          </div>
        ) : (
          <p className="empty-copy">Select a scan to inspect raw metadata, normalized findings, and ingestion state.</p>
        )}
      </div>
    </section>
  );
}

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import api from "../api/client";
import Card from "../components/Card";

function buildDownloadUrl(path) {
  const baseURL = api.defaults.baseURL || "/api";
  if (/^https?:\/\//i.test(path)) return path;
  if (baseURL.endsWith("/") && path.startsWith("/")) return `${baseURL.slice(0, -1)}${path}`;
  if (!baseURL.endsWith("/") && !path.startsWith("/")) return `${baseURL}/${path}`;
  return `${baseURL}${path}`;
}

async function fetchBlob(path, { method = "GET", body, fallbackMimeType } = {}) {
  const token = window.localStorage.getItem("vapt_token");
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  if (!(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(buildDownloadUrl(path), {
    method,
    headers,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    let detail = `Download failed with status ${response.status}.`;
    try {
      const text = await response.text();
      if (text) detail = text;
    } catch {
      // ignore parse issues
    }
    throw new Error(detail);
  }
  const buffer = await response.arrayBuffer();
  return new Blob([buffer], { type: response.headers.get("content-type") || fallbackMimeType || "application/octet-stream" });
}

async function fetchJson(path, { method = "GET", body } = {}) {
  const token = window.localStorage.getItem("vapt_token");
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (!(body instanceof FormData)) headers["Content-Type"] = "application/json";
  const response = await fetch(buildDownloadUrl(path), {
    method,
    headers,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}.`);
  }
  return response.json();
}

function saveBlobDownload(blob, filename) {
  if (window.navigator?.msSaveOrOpenBlob) {
    window.navigator.msSaveOrOpenBlob(blob, filename);
    return;
  }
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 60000);
}

export default function Reports({ findings, scans, compliance, incidents, alertRules, alertEvents }) {
  const completedScans = scans.filter((scan) => scan.status === "completed").length;
  const openFindings = findings.filter((finding) => finding.status === "open").length;
  const [summary, setSummary] = useState({
    total_findings: 0,
    open_findings: 0,
    severity_counts: {},
    source_counts: {},
    compliance_counts: {},
    top_findings: [],
  });
  const [reportType, setReportType] = useState("executive");
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [downloadState, setDownloadState] = useState("idle");
  const [localAssessments, setLocalAssessments] = useState(compliance?.assessments || []);
  const [localIncidents, setLocalIncidents] = useState(incidents || []);
  const [assessmentDetail, setAssessmentDetail] = useState(null);
  const [actionFeedback, setActionFeedback] = useState("");
  const [reportTargets, setReportTargets] = useState([]);
  const [selectedTargets, setSelectedTargets] = useState([]);
  const [targetFilter, setTargetFilter] = useState("");
  const [preview, setPreview] = useState(null);
  const [previewPdfUrl, setPreviewPdfUrl] = useState(null);
  const [companyName, setCompanyName] = useState("VAPTICOM");
  const [logoFile, setLogoFile] = useState(null);
  const [branding, setBranding] = useState({ logo_name: null, logo_uploaded: false, updated_at: null });
  const [reportTitle, setReportTitle] = useState("VAPTICOM Security Assessment Report");

  useEffect(() => {
    api.get("/reports/summary").then((response) => setSummary(response.data)).catch(() => {});
    api.get("/reports/targets").then((response) => setReportTargets(response.data || [])).catch(() => {});
    api.get("/reports/branding").then((response) => {
      setBranding(response.data || {});
      setCompanyName(response.data?.company_name || "VAPTICOM");
      setReportTitle(`${response.data?.company_name || "VAPTICOM"} Security Assessment Report`);
    }).catch(() => {});
  }, []);

  useEffect(() => setLocalAssessments(compliance?.assessments || []), [compliance?.assessments]);
  useEffect(() => setLocalIncidents(incidents || []), [incidents]);
  useEffect(() => {
    return () => {
      if (previewPdfUrl) {
        window.URL.revokeObjectURL(previewPdfUrl);
      }
    };
  }, [previewPdfUrl]);

  useEffect(() => {
    if (!selectedAssessment?.id) {
      setAssessmentDetail(null);
      return;
    }
    api.get(`/operations/compliance/assessments/${selectedAssessment.id}`).then((response) => setAssessmentDetail(response.data)).catch(() => setAssessmentDetail(null));
  }, [selectedAssessment]);

  const strongestSeverity = useMemo(() => {
    if ((summary.severity_counts?.critical || 0) > 0) return "critical";
    if ((summary.severity_counts?.high || 0) > 0) return "high";
    if ((summary.severity_counts?.medium || 0) > 0) return "medium";
    return "low";
  }, [summary.severity_counts]);

  const stakeholderNarrative = useMemo(() => {
    if (reportType === "technical") return "Technical reporting keeps evidence, CVEs, finding detail, and remediation state ready for engineering teams.";
    if (reportType === "compliance") return "Compliance reporting emphasizes mapped controls, assessment scorecards, and exportable evidence packs for audits.";
    return "Executive reporting emphasizes top risk, affected targets, business impact, and remediation priorities.";
  }, [reportType]);

  const visibleTargets = useMemo(() => {
    const query = targetFilter.trim().toLowerCase();
    if (!query) return reportTargets;
    return reportTargets.filter((item) =>
      [item.target, item.asset_name, item.hostname, item.ip_address, item.url, item.os_family]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }, [reportTargets, targetFilter]);

  const requestPayload = useMemo(
    () => ({
      mode: reportType,
      selected_targets: selectedTargets,
      report_title: reportTitle,
    }),
    [reportType, selectedTargets, reportTitle]
  );

  const toggleTarget = (target) => {
    setSelectedTargets((current) => (current.includes(target) ? current.filter((item) => item !== target) : [...current, target]));
  };

  const previewReport = async () => {
    setDownloadState("preview");
    try {
      const [response, pdfBlob] = await Promise.all([
        fetchJson("/reports/preview", { method: "POST", body: requestPayload }),
        fetchBlob("/reports/findings.pdf", { method: "POST", body: requestPayload, fallbackMimeType: "application/pdf" }),
      ]);
      setPreview(response);
      if (previewPdfUrl) {
        window.URL.revokeObjectURL(previewPdfUrl);
      }
      const pdfUrl = window.URL.createObjectURL(pdfBlob);
      setPreviewPdfUrl(pdfUrl);
      setActionFeedback("PDF preview refreshed in the browser.");
    } catch (error) {
      setActionFeedback(error?.message || "Unable to build the preview right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const downloadPdf = async () => {
    setDownloadState("pdf");
    try {
      const blob = await fetchBlob("/reports/findings.pdf", { method: "POST", body: requestPayload, fallbackMimeType: "application/pdf" });
      if (!blob.size) {
        throw new Error("The generated report is empty.");
      }
      saveBlobDownload(blob, "findings-report.pdf");
      setActionFeedback("PDF download started in the browser.");
    } catch (error) {
      setActionFeedback(error?.message || "Unable to download the PDF report right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const downloadDocx = async () => {
    setDownloadState("docx");
    try {
      const blob = await fetchBlob("/reports/findings.docx", { method: "POST", body: requestPayload, fallbackMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });
      if (!blob.size) {
        throw new Error("The generated report is empty.");
      }
      saveBlobDownload(blob, "findings-report.docx");
      setActionFeedback("DOCX download started in the browser.");
    } catch (error) {
      setActionFeedback(error?.message || "Unable to download the DOCX report right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const downloadReport = async (path, filename, mimeType) => {
    setDownloadState(path);
    try {
      const blob = await fetchBlob(path, { fallbackMimeType: mimeType });
      if (!blob.size) throw new Error("The generated report is empty.");
      saveBlobDownload(blob, filename);
      setActionFeedback(`Downloaded ${filename}.`);
    } catch (error) {
      setActionFeedback(error?.message || "Unable to download the report right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const uploadLogo = async () => {
    if (!logoFile) {
      setActionFeedback("Choose a PNG or JPG logo first.");
      return;
    }
    setDownloadState("branding");
    try {
      const form = new FormData();
      form.append("company_name", companyName);
      form.append("file", logoFile);
      const response = await fetchJson("/reports/branding/logo", { method: "POST", body: form });
      setBranding(response);
      if (response?.company_name) {
        setCompanyName(response.company_name);
      }
      setActionFeedback("Report branding updated.");
    } catch (error) {
      setActionFeedback(error?.message || "Unable to upload the logo right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const downloadAssessment = async (assessment) => {
    setDownloadState(`assessment-${assessment.id}`);
    try {
      const blob = await fetchBlob(`/operations/compliance/assessments/${assessment.id}/download`, { fallbackMimeType: "application/json" });
      if (!blob.size) throw new Error("The generated scorecard is empty.");
      saveBlobDownload(blob, `${assessment.name.replace(/\s+/g, "-").toLowerCase()}-scorecard.json`);
      setActionFeedback(`Downloaded ${assessment.name} scorecard.`);
    } catch (error) {
      setActionFeedback(error?.message || "Unable to download the scorecard right now.");
    } finally {
      setDownloadState("idle");
    }
  };

  const refreshAssessments = async () => {
    try {
      const response = await api.post("/operations/compliance/refresh");
      setLocalAssessments(response.data.assessments || []);
      setActionFeedback("Compliance scorecards refreshed.");
    } catch {
      setActionFeedback("Unable to refresh compliance scorecards right now.");
    }
  };

  const updateIncidentStatus = async (incidentId, status) => {
    try {
      const current = localIncidents.find((incident) => incident.id === incidentId);
      const response = await api.post(`/operations/incidents/${incidentId}/status`, {
        status,
        summary: current?.summary || null,
      });
      setLocalIncidents((items) => items.map((incident) => (incident.id === incidentId ? response.data : incident)));
    } catch {
      setActionFeedback("Unable to update incident status right now.");
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Reporting center</p>
            <h2>Reports</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Completed Scans" value={completedScans} trend="Ready for evidence packaging" />
          <Card title="Open Findings" value={openFindings} trend="Current remediation reporting scope" />
          <Card title="Alert Rules" value={alertRules?.length || 0} trend="Email and webhook delivery automation" />
          <Card title="Compliance Packs" value={compliance?.templates?.length || Object.keys(summary.compliance_counts || {}).length || 0} trend="Mapped frameworks and evidence sets" />
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Custom report workspace</p>
            <h2>Build and preview</h2>
          </div>
          <select className="scan-select" value={reportType} onChange={(event) => setReportType(event.target.value)}>
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
            <option value="compliance">Compliance</option>
          </select>
        </div>
        <div className="threat-grid">
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Branding</p>
                <h2>Company identity</h2>
              </div>
            </div>
            <label className="scan-target-label">Company name</label>
            <input className="scan-input" value={companyName} onChange={(event) => setCompanyName(event.target.value)} />
            <label className="scan-target-label">Report title</label>
            <input className="scan-input" value={reportTitle} onChange={(event) => setReportTitle(event.target.value)} />
            <label className="scan-target-label">Upload logo</label>
            <input type="file" accept=".png,.jpg,.jpeg" onChange={(event) => setLogoFile(event.target.files?.[0] || null)} />
            <p className="scan-target-hint">
              Current logo: <strong>{branding?.logo_uploaded ? branding.logo_name : "No custom logo uploaded"}</strong>
            </p>
            <div className="scan-actions">
              <button type="button" className="scan-action" onClick={uploadLogo}>
                {downloadState === "branding" ? "Uploading..." : "Upload logo"}
              </button>
            </div>
          </div>

          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Scope</p>
                <h2>Select targets</h2>
              </div>
            </div>
            <input
              className="scan-input"
              placeholder="Filter targets by IP, hostname, URL, asset, or OS"
              value={targetFilter}
              onChange={(event) => setTargetFilter(event.target.value)}
            />
            <div className="scan-actions" style={{ marginTop: "10px" }}>
              <button type="button" className="scan-action" onClick={() => setSelectedTargets(visibleTargets.map((item) => item.target))}>Select visible</button>
              <button type="button" className="scan-action" onClick={() => setSelectedTargets([])}>Clear selection</button>
            </div>
            <div className="coverage-list" style={{ maxHeight: "260px", overflowY: "auto", marginTop: "12px" }}>
              {visibleTargets.map((item) => (
                <label key={item.target} className="coverage-row" style={{ gap: "12px", alignItems: "flex-start" }}>
                  <input type="checkbox" checked={selectedTargets.includes(item.target)} onChange={() => toggleTarget(item.target)} />
                  <span>
                    {item.target}
                    <p>{item.asset_name || item.hostname || item.ip_address || item.url || "Target"}</p>
                    <p>{item.os_family || "OS not fingerprinted"} • {item.finding_count} finding(s) • {(item.highest_severity || "info").toUpperCase()}</p>
                  </span>
                </label>
              ))}
              {!visibleTargets.length ? <p className="empty-copy">No targets available yet. Complete scans first so report scope can be selected.</p> : null}
            </div>
          </div>
        </div>
        <div className="risk-hero" style={{ marginTop: "16px" }}>
          <div className="risk-hero__badge">
            <span>Primary report mode</span>
            <strong>{reportType}</strong>
          </div>
          <div>
            <p className="hero__lede">{stakeholderNarrative}</p>
            <p className="scan-target-hint"><strong>Selected targets:</strong> {selectedTargets.length || "All targets"}</p>
            <div className="scan-actions">
              <button type="button" className="scan-action" onClick={previewReport}>
                {downloadState === "preview" ? "Building preview..." : "Preview report"}
              </button>
              <button type="button" className="scan-action scan-action--resume" onClick={downloadPdf}>
                {downloadState === "pdf" ? "Preparing PDF..." : "Download PDF"}
              </button>
              <button type="button" className="scan-action" onClick={downloadDocx}>
                {downloadState === "docx" ? "Preparing DOCX..." : "Download DOCX (editable)"}
              </button>
              <button type="button" className="scan-action" onClick={() => downloadReport("/reports/findings.csv", "findings-report.csv", "text/csv")}>
                {downloadState === "/reports/findings.csv" ? "Preparing CSV..." : "Export CSV"}
              </button>
              <button type="button" className="scan-action" onClick={() => downloadReport("/reports/findings.json", "findings-report.json", "application/json")}>
                {downloadState === "/reports/findings.json" ? "Preparing JSON..." : "Export JSON"}
              </button>
            </div>
            <p className="scan-target-hint"><strong>Highest active severity:</strong> {strongestSeverity}</p>
          </div>
        </div>
        {actionFeedback ? <p className="scan-target-hint">{actionFeedback}</p> : null}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Preview</p>
            <h2>Before download</h2>
          </div>
        </div>
        {preview ? (
          <div className="threat-grid">
            <div className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Report title</span><strong>{preview.report_title}</strong></div>
                <div className="coverage-row"><span>Company</span><strong>{preview.company_name}</strong></div>
                <div className="coverage-row"><span>Targets in scope</span><strong>{preview.targets?.length || 0}</strong></div>
                <div className="coverage-row"><span>Total findings</span><strong>{preview.summary?.total_findings || 0}</strong></div>
                <div className="coverage-row"><span>Open findings</span><strong>{preview.summary?.open_findings || 0}</strong></div>
                <div className="coverage-row"><span>Logo</span><strong>{preview.logo_name || "Default text branding"}</strong></div>
              </div>
              {preview.executive_summary?.summary_text ? (
                <div className="coverage-list" style={{ marginTop: "12px" }}>
                  <div className="coverage-row"><span>Executive summary</span><strong>{preview.executive_summary.summary_text}</strong></div>
                  {(preview.recommendations || []).slice(0, 3).map((recommendation, index) => (
                    <div className="coverage-row" key={`recommendation-${index}`}>
                      <span>Action {index + 1}</span>
                      <strong>{recommendation}</strong>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
            <div className="panel panel--embedded" style={{ minHeight: "720px" }}>
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Browser PDF preview</p>
                  <h2>Executive report</h2>
                </div>
              </div>
              {previewPdfUrl ? (
                <iframe
                  title="Executive report preview"
                  src={previewPdfUrl}
                  style={{ width: "100%", minHeight: "640px", border: "none", borderRadius: "8px" }}
                />
              ) : (
                <p className="empty-copy">The PDF preview will appear here after you click Preview report.</p>
              )}
            </div>
          </div>
        ) : (
          <p className="empty-copy">Choose one or more targets, then use Preview report to inspect the report scope before downloading.</p>
        )}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Compliance automation</p>
            <h2>Assessment scorecards</h2>
          </div>
        </div>
        <div className="coverage-list">
          {localAssessments.map((assessment) => (
            <button type="button" className={`coverage-row coverage-row--button ${selectedAssessment?.id === assessment.id ? "is-active" : ""}`} key={assessment.id} onClick={() => setSelectedAssessment(assessment)}>
              <span>{assessment.name}</span>
              <strong>{assessment.score}% / {assessment.status}</strong>
            </button>
          ))}
          {!localAssessments.length ? <p className="empty-copy">Continuous compliance assessments will appear here after data refresh.</p> : null}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Assessment workspace</p>
            <h2>{selectedAssessment?.name || "Select a scorecard"}</h2>
          </div>
          {selectedAssessment ? (
            <div className="scan-actions">
              <button type="button" className="scan-action scan-action--resume" onClick={() => downloadAssessment(selectedAssessment)}>
                {downloadState === `assessment-${selectedAssessment.id}` ? "Preparing..." : "Download scorecard"}
              </button>
            </div>
          ) : null}
        </div>
        {selectedAssessment ? (
          <div className="threat-grid">
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Assessment status</p>
                  <h2>{selectedAssessment.status}</h2>
                </div>
              </div>
              <div className="coverage-list">
                <div className="coverage-row"><span>Score</span><strong>{selectedAssessment.score}%</strong></div>
                <div className="coverage-row"><span>ID</span><strong>{selectedAssessment.id}</strong></div>
                <div className="coverage-row"><span>Framework</span><strong>{assessmentDetail?.framework || "Loading..."}</strong></div>
              </div>
            </div>
            <div className="panel panel--embedded">
              <div className="panel__header">
                <div>
                  <p className="eyebrow">Scorecard detail</p>
                  <h2>Summary</h2>
                </div>
              </div>
              <div className="developer-code developer-code--block">
                {JSON.stringify(assessmentDetail || selectedAssessment.summary || {}, null, 2)}
              </div>
            </div>
          </div>
        ) : (
          <p className="empty-copy">Choose an assessment scorecard to inspect its detail or download the scorecard.</p>
        )}
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Framework coverage</p>
            <h2>Compliance mapping</h2>
          </div>
        </div>
        <div className="coverage-list">
          {Object.entries(summary.compliance_counts || {}).map(([label, count]) => (
            <div className="coverage-row" key={label}>
              <span>{label}</span>
              <strong>{count}</strong>
            </div>
          ))}
          {!Object.keys(summary.compliance_counts || {}).length ? <p className="empty-copy">Compliance mappings appear here as normalized findings are enriched.</p> : null}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Alerting</p>
            <h2>Delivery automation</h2>
          </div>
        </div>
        <div className="coverage-list">
          {(alertRules || []).map((rule) => (
            <div className="coverage-row" key={rule.id}>
              <span>{rule.name}<p>{rule.channel} → {rule.destination}</p></span>
              <strong>{rule.min_severity} / {rule.enabled ? "enabled" : "disabled"}</strong>
            </div>
          ))}
          {!alertRules?.length ? <p className="empty-copy">Create alert rules in Integrations to automate report delivery triggers.</p> : null}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Incident reporting</p>
            <h2>Correlated incidents</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {localIncidents.map((incident) => (
                <tr key={incident.id}>
                  <td data-label="Title"><strong>{incident.title}</strong><p>{incident.target}</p></td>
                  <td data-label="Source">{incident.source}</td>
                  <td data-label="Severity">{incident.severity}</td>
                  <td data-label="Status">
                    <div className="table-action-stack">
                      <strong>{incident.status}</strong>
                      <div className="scan-actions">
                        <button type="button" className="scan-action" onClick={() => updateIncidentStatus(incident.id, "investigating")}>Investigate</button>
                        <button type="button" className="scan-action" onClick={() => updateIncidentStatus(incident.id, "contained")}>Contain</button>
                        <button type="button" className="scan-action" onClick={() => updateIncidentStatus(incident.id, "resolved")}>Resolve</button>
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
              {!localIncidents.length ? <tr><td colSpan="4"><p className="empty-copy">Correlated incidents will appear here after monitoring events are ingested.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Alert activity</p>
            <h2>Recent alert events</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Destination</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {(alertEvents || []).slice(0, 10).map((event) => (
                <tr key={event.id}>
                  <td data-label="Rule"><strong>{event.rule_name}</strong><p>{event.channel}</p></td>
                  <td data-label="Destination">{event.destination}</td>
                  <td data-label="Status">{event.status}</td>
                  <td data-label="Created">{new Date(event.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {!alertEvents?.length ? <tr><td colSpan="4"><p className="empty-copy">No alert events have fired yet.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Priority findings</p>
            <h2>Top report items</h2>
          </div>
        </div>
        <div className="table-wrap table-wrap--full">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Severity</th>
                <th>Source</th>
                <th>CVE</th>
                <th>Open</th>
              </tr>
            </thead>
            <tbody>
              {summary.top_findings?.map((finding) => (
                <tr key={finding.id}>
                  <td data-label="Finding"><strong>{finding.title}</strong></td>
                  <td data-label="Severity">{finding.severity || "info"}</td>
                  <td data-label="Source">{finding.source}</td>
                  <td data-label="CVE">{finding.cve_id || "No CVE"}</td>
                  <td data-label="Open"><Link className="target-link" to="/findings">Review</Link></td>
                </tr>
              ))}
              {!summary.top_findings?.length ? <tr><td colSpan="5"><p className="empty-copy">Report-ready priority findings will appear here.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

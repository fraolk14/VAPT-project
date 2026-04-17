import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import api from "../api/client";

const TAB_OPTIONS = [
  { key: "openvas", label: "Network Findings" },
  { key: "zap", label: "Web Findings" },
  { key: "mobsf", label: "Mobile Findings" },
];

const TAB_SOURCE_MAP = {
  openvas: ["openvas", "network-db"],
  zap: ["zap"],
  mobsf: ["mobsf"],
};

const DEFAULT_COLUMN_WIDTHS = {
  date: 132,
  severity: 92,
  title: 210,
  details: 300,
  target: 220,
  cve: 110,
  count: 72,
  cvss: 78,
  owner: 250,
  verification: 150,
  recommendation: 270,
  status: 96,
};

const COLUMN_DEFS = [
  { key: "date", label: "Date", sortable: true },
  { key: "severity", label: "Severity", sortable: true },
  { key: "title", label: "Title", sortable: true },
  { key: "details", label: "Details", sortable: false },
  { key: "target", label: "Target", sortable: true },
  { key: "cve", label: "CVE", sortable: true },
  { key: "count", label: "Count", sortable: true },
  { key: "cvss", label: "CVSS", sortable: true },
  { key: "owner", label: "Owner / Group", sortable: true },
  { key: "verification", label: "Verification", sortable: false },
  { key: "recommendation", label: "AI Recommendation", sortable: true },
  { key: "status", label: "Status", sortable: false },
];

function severityLabel(value) {
  return value || "info";
}

function targetLabel(finding) {
  if (finding.source === "zap") return finding.finding_metadata?.url || "n/a";
  if (finding.source === "openvas" || finding.source === "network-db") return finding.finding_metadata?.host || `${finding.port}/${finding.protocol}`;
  return finding.finding_metadata?.file || "n/a";
}

function targetSummary(finding) {
  if (finding.source === "zap") {
    const rawUrl = finding.finding_metadata?.url || "";
    try {
      const parsed = new URL(rawUrl);
      return {
        primary: parsed.hostname || rawUrl || "n/a",
        secondary: `${parsed.protocol}//${parsed.host}${parsed.pathname || "/"}`,
      };
    } catch {
      return { primary: rawUrl || "n/a", secondary: "Web target" };
    }
  }

  if (finding.source === "openvas" || finding.source === "network-db") {
    return {
      primary: finding.finding_metadata?.host || "n/a",
      secondary: `${finding.port || 0}/${finding.protocol || "tcp"}`,
    };
  }

  return {
    primary: finding.finding_metadata?.file || "n/a",
    secondary: "Mobile artifact",
  };
}

function identifierLabel(finding) {
  return finding.display_id || finding.cve_id || (finding.finding_metadata?.cwe_id ? `CWE-${finding.finding_metadata.cwe_id}` : "n/a");
}

function cveValues(finding) {
  const raw = finding.cve_id || finding.display_id || "";
  const matches = raw.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map((item) => item.toUpperCase()))];
}

function aiRecommendation(finding) {
  const severity = (finding.severity || "info").toLowerCase();
  const title = (finding.title || "").toLowerCase();
  if (severity === "critical" || severity === "high") return "Patch immediately and validate fix with a re-scan.";
  if (title.includes("csp") || title.includes("header")) return "Harden the web security headers and re-test the exposed routes.";
  if (title.includes("secret") || title.includes("credential")) return "Rotate exposed secrets and move them into managed secret storage.";
  if (finding.source === "openvas" || finding.source === "network-db") return "Prioritize the exposed service, reduce attack surface, and confirm closure with validation.";
  return "Review impact, assign an owner, and schedule validation after remediation.";
}

function detailsSummary(finding) {
  const correlation = finding.finding_metadata?.correlation || {};
  return correlation.correlation_summary || finding.evidence || finding.remediation || "No additional detail captured.";
}

function findingMatchesTab(finding, tabKey) {
  return (TAB_SOURCE_MAP[tabKey] || [tabKey]).includes(finding.source);
}

function sortValue(finding, sortKey) {
  if (sortKey === "severity") {
    return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[(finding.severity || "info").toLowerCase()] || 0;
  }
  if (sortKey === "count") return finding.duplicate_count || 1;
  if (sortKey === "cvss") return finding.cvss_score || 0;
  if (sortKey === "title") return finding.title || "";
  if (sortKey === "cve") return finding.cve_id || "";
  if (sortKey === "reference") return identifierLabel(finding);
  if (sortKey === "owner") return `${finding.assigned_to || ""} ${finding.team_name || ""}`.trim();
  if (sortKey === "date") return finding.detected_at || "";
  if (sortKey === "recommendation") return aiRecommendation(finding);
  return targetLabel(finding);
}

function detectedLabel(finding) {
  if (!finding.detected_at) return "n/a";
  return new Date(finding.detected_at).toLocaleString();
}

function renderCveLinks(finding) {
  const cves = cveValues(finding);
  if (!cves.length) return "n/a";
  return (
    <div className="cve-link-list">
      {cves.map((cve) => (
        <a
          key={cve}
          className="cve-link"
          href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`}
          target="_blank"
          rel="noreferrer"
          title={`Open official CVE record for ${cve}`}
        >
          {cve}
        </a>
      ))}
    </div>
  );
}

export default function Findings({ findings, users, groups }) {
  const [searchParams] = useSearchParams();
  const resizeStateRef = useRef(null);
  const [localFindings, setLocalFindings] = useState(findings);
  const [activeTab, setActiveTab] = useState("openvas");
  const [pageSize, setPageSize] = useState(10);
  const [pageIndex, setPageIndex] = useState(0);
  const [assignmentState, setAssignmentState] = useState({});
  const [sortState, setSortState] = useState({ key: "date", direction: "desc" });
  const [aiRecommendations, setAiRecommendations] = useState({});
  const [aiProvider, setAiProvider] = useState("gemini");
  const [aiStatus, setAiStatus] = useState("loading");
  const [expandedRecommendations, setExpandedRecommendations] = useState({});
  const [expandedDetails, setExpandedDetails] = useState({});
  const [columnWidths, setColumnWidths] = useState(DEFAULT_COLUMN_WIDTHS);
  const selectedTarget = searchParams.get("target") || "";

  useEffect(() => {
    setLocalFindings(findings);
  }, [findings]);

  useEffect(() => {
    if (!localFindings.length) return;

    if (selectedTarget) {
      const matched = localFindings.find((finding) => targetLabel(finding) === selectedTarget);
      if (matched?.source) {
        const matchedTab = TAB_OPTIONS.find((tab) => findingMatchesTab(matched, tab.key));
        if (matchedTab) {
          setActiveTab(matchedTab.key);
          return;
        }
      }
    }

    const availableTab = TAB_OPTIONS.find((tab) => localFindings.some((finding) => findingMatchesTab(finding, tab.key)));
    if (availableTab && !localFindings.some((finding) => findingMatchesTab(finding, activeTab))) {
      setActiveTab(availableTab.key);
    }
  }, [localFindings, selectedTarget, activeTab]);

  useEffect(() => {
    setPageIndex(0);
  }, [activeTab, pageSize, sortState]);

  const tabFindings = useMemo(() => {
    const filtered = localFindings.filter((finding) => findingMatchesTab(finding, activeTab));
    const sorted = [...filtered].sort((left, right) => {
      const leftValue = sortValue(left, sortState.key);
      const rightValue = sortValue(right, sortState.key);
      if (leftValue < rightValue) return sortState.direction === "asc" ? -1 : 1;
      if (leftValue > rightValue) return sortState.direction === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [localFindings, activeTab, sortState]);

  const totalPages = Math.max(1, Math.ceil(tabFindings.length / pageSize));
  const visibleFindings = tabFindings.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize);

  useEffect(() => {
    if (!visibleFindings.length) return;
    const pendingIds = visibleFindings.map((finding) => finding.id).filter((id) => !aiRecommendations[id]);
    if (!pendingIds.length) return;
    api.post("/ai/finding-recommendations", { finding_ids: pendingIds }).then((response) => {
      setAiProvider(response.data.provider || "local-fallback");
      setAiStatus(response.data.provider === "gemini" ? "ready" : "fallback");
      setAiRecommendations((current) => {
        const next = { ...current };
        for (const item of response.data.items || []) {
          next[item.finding_id] = item.recommendation;
        }
        return next;
      });
    }).catch(() => {
      setAiStatus("error");
    });
  }, [visibleFindings, aiRecommendations]);

  const updateFinding = async (findingId) => {
    const payload = assignmentState[findingId];
    if (!payload) return;
    try {
      const response = await api.patch(`/findings/${findingId}`, {
        assigned_to: payload.assigned_to || null,
        team_name: payload.team_name || null,
        verification_state: payload.verification_state || null,
      });
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
    } catch {
      // quiet for now
    }
  };

  const markFalsePositive = async (findingId) => {
    try {
      const response = await api.patch(`/findings/${findingId}`, { mark_false_positive: true });
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
    } catch {
      // quiet for now
    }
  };

  useEffect(() => {
    if (!selectedTarget) return;
    const row = document.querySelector(".finding-row--selected");
    if (row) row.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [selectedTarget, visibleFindings]);

  const toggleSort = (key) => {
    setSortState((current) => (
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: key === "title" || key === "target" || key === "owner" || key === "recommendation" ? "asc" : "desc" }
    ));
  };

  const renderSortHeader = (label, key) => (
    <button type="button" className="table-sort" onClick={() => toggleSort(key)}>
      {label}
      <span>{sortState.key === key ? (sortState.direction === "asc" ? "↑" : "↓") : "↕"}</span>
    </button>
  );

  const recommendationPreview = (finding) => {
    const text = aiRecommendations[finding.id] || (aiStatus === "error" ? "Gemini recommendation unavailable right now." : "Analyzing with Gemini...");
    const expanded = expandedRecommendations[finding.id];
    if (expanded || text.length <= 112) return text;
    return `${text.slice(0, 112).trim()}...`;
  };

  const detailsPreview = (finding) => {
    const text = detailsSummary(finding);
    const expanded = expandedDetails[finding.id];
    if (expanded || text.length <= 150) return text;
    return `${text.slice(0, 150).trim()}...`;
  };

  const stopResize = () => {
    if (!resizeStateRef.current) return;
    window.removeEventListener("mousemove", resizeStateRef.current.onMove);
    window.removeEventListener("mouseup", resizeStateRef.current.onUp);
    resizeStateRef.current = null;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  };

  useEffect(() => stopResize, []);

  const startResize = (columnKey, event) => {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = columnWidths[columnKey] || DEFAULT_COLUMN_WIDTHS[columnKey] || 120;

    const onMove = (moveEvent) => {
      const nextWidth = Math.max(64, startWidth + (moveEvent.clientX - startX));
      setColumnWidths((current) => ({ ...current, [columnKey]: nextWidth }));
    };

    const onUp = () => stopResize();

    resizeStateRef.current = { onMove, onUp };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const renderHeaderCell = (column, index) => (
    <th key={column.key} className="findings-table-layout__header-cell">
      <div className="findings-table-layout__header-inner">
        {column.sortable ? renderSortHeader(column.label, column.key) : <span className="findings-table-layout__header-label">{column.label}</span>}
        {index < COLUMN_DEFS.length - 1 ? (
          <span
            className="findings-table-layout__resize-handle"
            onMouseDown={(event) => startResize(column.key, event)}
            role="separator"
            aria-orientation="vertical"
            aria-label={`Resize ${column.label} column`}
          />
        ) : null}
      </div>
    </th>
  );

  return (
    <section className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Normalized results</p>
          <h2>Findings</h2>
        </div>
        <div className="table-controls">
          <select className="scan-select" value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))}>
            <option value={10}>10 per page</option>
            <option value={20}>20 per page</option>
          </select>
          <span className="topbar__user-label">AI source {aiProvider}</span>
          <span className="topbar__user-label">
            {aiStatus === "ready" ? "Gemini live" : aiStatus === "fallback" ? "Fallback active" : aiStatus === "error" ? "AI unavailable" : "Loading AI"}
          </span>
        </div>
      </div>

      <div className="subtabs">
        {TAB_OPTIONS.map((tab) => (
          <button key={tab.key} type="button" className={activeTab === tab.key ? "subtab is-active" : "subtab"} onClick={() => setActiveTab(tab.key)}>
            {tab.label}
            <span>{localFindings.filter((finding) => findingMatchesTab(finding, tab.key)).length}</span>
          </button>
        ))}
      </div>

      <div className="table-wrap">
        <table className="table findings-table-compact findings-table-layout">
          <colgroup>
            {COLUMN_DEFS.map((column) => (
              <col
                key={column.key}
                className={`findings-col findings-col--${column.key}`}
                style={{ width: `${columnWidths[column.key] || DEFAULT_COLUMN_WIDTHS[column.key]}px` }}
              />
            ))}
          </colgroup>
          <thead>
            <tr>{COLUMN_DEFS.map(renderHeaderCell)}</tr>
          </thead>
          <tbody>
            {visibleFindings.map((finding) => {
              const draft = assignmentState[finding.id] || {
                assigned_to: finding.assigned_to || "",
                team_name: finding.team_name || "",
                verification_state: finding.verification_state || "pending",
              };
              return (
                <tr key={finding.id} className={targetLabel(finding) === selectedTarget ? "finding-row--selected" : ""}>
                  <td data-label="Date">{detectedLabel(finding)}</td>
                  <td data-label="Severity"><span className={`pill pill--${severityLabel(finding.severity)}`}>{severityLabel(finding.severity)}</span></td>
                  <td data-label="Title">
                    <Link className="finding-title-link" to={`/findings/${finding.id}`}>
                      {finding.title}
                    </Link>
                    <p>{finding.port}/{finding.protocol}</p>
                  </td>
                  <td data-label="Details">
                    <div className="recommendation-cell">
                      <span className={expandedDetails[finding.id] ? "finding-detail-copy is-expanded" : "finding-detail-copy"}>{detailsPreview(finding)}</span>
                      {detailsSummary(finding).length > 150 ? (
                        <button
                          type="button"
                          className="recommendation-cell__toggle"
                          onClick={() => setExpandedDetails((current) => ({ ...current, [finding.id]: !current[finding.id] }))}
                        >
                          {expandedDetails[finding.id] ? "See less" : "See more"}
                        </button>
                      ) : null}
                    </div>
                  </td>
                  <td data-label="Target"><strong>{targetSummary(finding).primary}</strong><p>{targetSummary(finding).secondary}</p></td>
                  <td data-label="CVE">{renderCveLinks(finding)}</td>
                  <td data-label="Count">{finding.duplicate_count || 1}</td>
                  <td data-label="CVSS">{finding.cvss_score || "n/a"}</td>
                  <td data-label="Owner / Group">
                    <div className="finding-actions-cell">
                      <select className="scan-select" value={draft.assigned_to} onChange={(event) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, assigned_to: event.target.value } }))}>
                        <option value="">Unassigned</option>
                        {(users || []).map((entry) => (
                          <option key={entry.id} value={entry.username}>{entry.username}</option>
                        ))}
                      </select>
                      <select className="scan-select" value={draft.team_name} onChange={(event) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, team_name: event.target.value } }))}>
                        <option value="">No group</option>
                        {(groups || []).map((group) => (
                          <option key={group.id} value={group.name}>{group.name}</option>
                        ))}
                      </select>
                      <div className="scan-actions">
                        <button type="button" className="scan-action scan-action--resume" onClick={() => updateFinding(finding.id)}>Assign</button>
                        <button type="button" className="scan-action scan-action--cancel" onClick={() => markFalsePositive(finding.id)}>False Positive</button>
                      </div>
                    </div>
                  </td>
                  <td data-label="Verification">
                    <select className="scan-select" value={draft.verification_state} onChange={(event) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, verification_state: event.target.value } }))}>
                      <option value="pending">Pending</option>
                      <option value="in_review">In Review</option>
                      <option value="scheduled">Scheduled</option>
                      <option value="verified">Verified</option>
                    </select>
                  </td>
                  <td data-label="AI Recommendation">
                    <div className="recommendation-cell">
                      <span>{recommendationPreview(finding)}</span>
                      {(aiRecommendations[finding.id] || "").length > 112 ? (
                        <button
                          type="button"
                          className="recommendation-cell__toggle"
                          onClick={() => setExpandedRecommendations((current) => ({ ...current, [finding.id]: !current[finding.id] }))}
                        >
                          {expandedRecommendations[finding.id] ? "See less" : "See more"}
                        </button>
                      ) : null}
                    </div>
                  </td>
                  <td data-label="Status">{finding.status}</td>
                </tr>
              );
            })}
            {!visibleFindings.length ? (
              <tr>
                <td colSpan="12"><p className="empty-copy">No findings are available in this category yet.</p></td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div className="pagination-bar">
        <span>Showing {visibleFindings.length ? pageIndex * pageSize + 1 : 0}-{Math.min((pageIndex + 1) * pageSize, tabFindings.length)} of {tabFindings.length}</span>
        <div className="scan-actions">
          <button type="button" className="scan-action" disabled={pageIndex === 0} onClick={() => setPageIndex((current) => Math.max(current - 1, 0))}>Previous</button>
          <span className="pagination-page">Page {pageIndex + 1} of {totalPages}</span>
          <button type="button" className="scan-action" disabled={pageIndex >= totalPages - 1} onClick={() => setPageIndex((current) => Math.min(current + 1, totalPages - 1))}>Next</button>
        </div>
      </div>
    </section>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import api from "../api/client";

const TAB_OPTIONS = [
  { key: "all", label: "All Findings" },
  { key: "endpoint", label: "Endpoint Findings" },
  { key: "openvas", label: "Network Findings" },
  { key: "zap", label: "Web Findings" },
  { key: "mobsf", label: "Mobile Findings" },
];

const TAB_SOURCE_MAP = {
  all: null,
  endpoint: ["endpoint-agent", "agent", "windows-agent", "Endpoint", "VAP Agent"],
  openvas: ["openvas", "network-db", "host", "host-scan", "network", "nmap", "socket", "nmap+socket", "Network"],
  zap: ["zap", "web", "web-scan", "web-db", "zap-proxy", "owasp", "nuclei", "Web"],
  mobsf: ["mobsf", "mobile", "apk", "ipa", "Mobile"],
};

const DEFAULT_COLUMN_WIDTHS = {
  select: 45,
  date: 110,
  severity: 110,
  title: 220,
  details: 280,
  target: 200,
  cve: 110,
  count: 70,
  cvss: 75,
  owner: 240,
  verification: 140,
  recommendation: 260,
  status: 100,
};

const COLUMN_DEFS = [
  { key: "select", label: "", sortable: false },
  { key: "date", label: "Date", sortable: true },
  { key: "severity", label: "Severity", sortable: true },
  { key: "title", label: "Title", sortable: true },
  { key: "details", label: "Details", sortable: false },
  { key: "target", label: "Target Asset", sortable: true },
  { key: "cve", label: "CVE", sortable: true },
  { key: "count", label: "Count", sortable: true },
  { key: "cvss", label: "CVSS", sortable: true },
  { key: "owner", label: "Owner / Group", sortable: true },
  { key: "verification", label: "Verification", sortable: true },
  { key: "recommendation", label: "AI Recommendation", sortable: true },
  { key: "status", label: "Status", sortable: true },
];

function severityLabel(value) {
  return (value || "info").toLowerCase();
}

const IS_ENDPOINT_SOURCE = (src, cat) =>
  (cat || "").toLowerCase() === "endpoint" ||
  TAB_SOURCE_MAP.endpoint.some((s) => (src || "").toLowerCase().includes(s.toLowerCase())) ||
  (src || "").toLowerCase().includes("agent") ||
  (src || "").toLowerCase().includes("endpoint");

const IS_WEB_SOURCE = (src, cat) =>
  (cat || "").toLowerCase() === "web" ||
  TAB_SOURCE_MAP.zap.some((s) => (src || "").toLowerCase().includes(s.toLowerCase())) ||
  (src || "").toLowerCase().includes("web") ||
  (src || "").toLowerCase().includes("zap");

const IS_NETWORK_SOURCE = (src, cat) =>
  (cat || "").toLowerCase() === "network" ||
  TAB_SOURCE_MAP.openvas.some((s) => (src || "").toLowerCase().includes(s.toLowerCase())) ||
  (src || "").toLowerCase().includes("network") ||
  (src || "").toLowerCase().includes("host") ||
  (src || "").toLowerCase().includes("nmap") ||
  (src || "").toLowerCase().includes("socket") ||
  (src || "").toLowerCase().includes("openvas");

const IS_MOBILE_SOURCE = (src, cat) =>
  (cat || "").toLowerCase() === "mobile" ||
  TAB_SOURCE_MAP.mobsf.some((s) => (src || "").toLowerCase().includes(s.toLowerCase())) ||
  (src || "").toLowerCase().includes("mobile") ||
  (src || "").toLowerCase().includes("mobsf") ||
  (src || "").toLowerCase().includes("apk") ||
  (src || "").toLowerCase().includes("ipa");

function resolveHost(finding) {
  const meta = finding.finding_metadata || {};
  const details = finding.target_details || {};
  if (finding.asset_name && finding.asset_name !== "n/a") return finding.asset_name;
  if (details.hostname && details.hostname !== "n/a") return details.hostname;
  if (finding.target && finding.target !== "n/a") return finding.target;
  if (meta.host && meta.host !== "n/a") return meta.host;
  if (details.host && details.host !== "n/a") return details.host;
  if (details.ip_address && details.ip_address !== "n/a") return details.ip_address;
  if (meta.ip_address && meta.ip_address !== "n/a") return meta.ip_address;
  if (meta.hostname && meta.hostname !== "n/a") return meta.hostname;
  return "n/a";
}

function targetLabel(finding) {
  const src = finding.source || "";
  const cat = finding.category || "";
  const meta = finding.finding_metadata || {};
  const details = finding.target_details || {};

  if (IS_ENDPOINT_SOURCE(src, cat)) return meta.ip_address || resolveHost(finding);
  if (IS_WEB_SOURCE(src, cat)) return finding.asset_name || details.hostname || resolveHost(finding);
  if (IS_NETWORK_SOURCE(src, cat)) return resolveHost(finding);
  if (IS_MOBILE_SOURCE(src, cat)) return meta.file || meta.package_name || meta.stored_file_name || resolveHost(finding);
  return resolveHost(finding);
}

function targetSummary(finding) {
  const src = finding.source || "";
  const cat = finding.category || "";
  const meta = finding.finding_metadata || {};
  const details = finding.target_details || {};
  const host = resolveHost(finding);

  if (IS_ENDPOINT_SOURCE(src, cat)) {
    const ip = details.ip_address || meta.ip_address || host;
    const hostname = details.hostname || meta.hostname;
    return {
      primary: hostname || ip,
      secondary: hostname ? `Host: ${hostname}` : "VAP Agent Device",
    };
  }

  if (IS_WEB_SOURCE(src, cat)) {
    const primaryHost = finding.asset_name || details.hostname || host;
    const rawUrl = details.url || meta.url || "";
    let formattedSecondary = "Web target";
    try {
      if (rawUrl && rawUrl.startsWith("http")) {
        const parsed = new URL(rawUrl);
        const effectiveHost = (primaryHost && primaryHost !== "n/a" && !primaryHost.includes("://")) ? primaryHost : parsed.host;
        formattedSecondary = `${parsed.protocol}//${effectiveHost}${parsed.pathname || "/"}`;
      } else {
        const proto = primaryHost.startsWith("http") ? "" : "https://";
        formattedSecondary = `${proto}${primaryHost}/`;
      }
    } catch {
      formattedSecondary = primaryHost.startsWith("http") ? primaryHost : `https://${primaryHost}/`;
    }

    return {
      primary: primaryHost || "n/a",
      secondary: formattedSecondary,
    };
  }

  if (IS_NETWORK_SOURCE(src, cat) || (!IS_MOBILE_SOURCE(src, cat) && (finding.port || meta.host || details.host))) {
    return {
      primary: host,
      secondary: finding.port ? `${finding.port}/${finding.protocol || "tcp"}` : "Network host",
    };
  }

  if (IS_MOBILE_SOURCE(src, cat)) {
    return {
      primary: meta.file || meta.package_name || meta.stored_file_name || host,
      secondary: "Mobile package",
    };
  }

  return {
    primary: host,
    secondary: finding.port ? `${finding.port}/${finding.protocol || "tcp"}` : "Discovered Target",
  };
}

function identifierLabel(finding) {
  return finding.display_id || finding.cve_id || finding.cve || (finding.finding_metadata?.cwe_id ? `CWE-${finding.finding_metadata.cwe_id}` : "n/a");
}

function cveValues(finding) {
  const raw = finding.cve_id || finding.cve || finding.display_id || "";
  const matches = raw.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map((item) => item.toUpperCase()))];
}

function detailsSummary(finding) {
  const meta = finding.finding_metadata || {};
  const correlation = meta.correlation || {};

  // Priority: Specific finding explanation & evidence → metadata description → details → correlation summary → remediation
  const explanationText =
    meta.description ||
    finding.evidence ||
    meta.details ||
    finding.details ||
    correlation.correlation_summary ||
    finding.remediation ||
    "";

  if (!explanationText || explanationText.trim() === "") {
    return `Vulnerability type: ${finding.title || "Unknown"}. No additional detail captured.`;
  }

  return explanationText.trim();
}



function findingMatchesTab(finding, tabKey) {
  if (tabKey === "all") return true;
  const sources = TAB_SOURCE_MAP[tabKey] || [tabKey];
  const src = (finding.source || "").toLowerCase();
  const cat = (finding.category || "").toLowerCase();
  return sources.some((s) => src.includes(s.toLowerCase()) || cat.includes(s.toLowerCase()));
}

function sortValue(finding, sortKey) {
  if (sortKey === "severity") {
    return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[(finding.severity || "info").toLowerCase()] || 0;
  }
  if (sortKey === "count") return finding.duplicate_count || finding.count || 1;
  if (sortKey === "cvss") return finding.cvss_score || 0;
  if (sortKey === "title") return finding.title || "";
  if (sortKey === "cve") return finding.cve_id || finding.cve || "";
  if (sortKey === "owner") return `${finding.assigned_to || ""} ${finding.team_name || ""}`.trim();
  if (sortKey === "date") return finding.detected_at || finding.discovered_at || "";
  if (sortKey === "status") return finding.status || "";
  if (sortKey === "verification") return finding.verification_state || finding.verification_status || "";
  return targetLabel(finding);
}

function detectedLabel(finding) {
  const dt = finding.detected_at || finding.discovered_at;
  if (!dt) return "n/a";
  return new Date(dt).toLocaleString();
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
  const [localFindings, setLocalFindings] = useState(findings || []);

  const scanIdParam = searchParams.get("scan_id") || "";
  const tabParam = searchParams.get("tab") || "";
  const targetParam = searchParams.get("target") || searchParams.get("target_ip") || "";
  const queryParam = searchParams.get("search") || searchParams.get("q") || "";
  
  const [activeTab, setActiveTab] = useState(() => {
    if (tabParam && ["all", "endpoint", "openvas", "zap", "mobsf"].includes(tabParam)) {
      return tabParam;
    }
    return "all";
  });
  
  // Advanced Filters
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [verificationFilter, setVerificationFilter] = useState("ALL");

  const [pageSize, setPageSize] = useState(10);
  const [pageIndex, setPageIndex] = useState(0);
  const [assignmentState, setAssignmentState] = useState({});
  const [sortState, setSortState] = useState({ key: "date", direction: "desc" });
  
  const [aiRecommendations, setAiRecommendations] = useState({});
  const [aiProvider, setAiProvider] = useState("nvidia-nim");
  const [aiStatus, setAiStatus] = useState("loading");
  const [expandedRecommendations, setExpandedRecommendations] = useState({});
  const [expandedDetails, setExpandedDetails] = useState({});
  const [columnWidths, setColumnWidths] = useState(DEFAULT_COLUMN_WIDTHS);
  const [selectedIds, setSelectedIds] = useState(new Set());
  
  const [queryText, setQueryText] = useState(queryParam);

  useEffect(() => {
    setQueryText(queryParam);
  }, [queryParam]);

  useEffect(() => {
    setLocalFindings(findings || []);
  }, [findings]);

  useEffect(() => {
    setPageIndex(0);
  }, [activeTab, severityFilter, statusFilter, verificationFilter, pageSize, sortState, queryText, scanIdParam, targetParam]);

  // Multi-criteria Filtering & Sorting
  const filteredAndSortedFindings = useMemo(() => {
    const needle = (queryText || targetParam).trim().toLowerCase();
    
    const filtered = localFindings.filter((finding) => {
      // 0. Flexible Target IP / CIDR / URL filter if target query param is present
      if (targetParam) {
        const paramStr = targetParam.trim().toLowerCase().replace(/^https?:\/\//, "");
        const rawTarget = (finding.target || "").toLowerCase().replace(/^https?:\/\//, "");
        const metaHost = (finding.finding_metadata?.host || finding.finding_metadata?.url || finding.finding_metadata?.ip_address || "").toLowerCase().replace(/^https?:\/\//, "");
        const matches = rawTarget.includes(paramStr) || paramStr.includes(rawTarget) || metaHost.includes(paramStr) || paramStr.includes(metaHost);
        if (!matches) return false;
      }

      // 0b. Strict Scan Job ID filter if scan_id query param is present
      if (scanIdParam && String(finding.scan_id) !== String(scanIdParam)) {
        return false;
      }

      // 1. Tab source filter
      if (!findingMatchesTab(finding, activeTab)) return false;

      // 2. Severity Filter
      if (severityFilter !== "ALL" && (finding.severity || "").toUpperCase() !== severityFilter) {
        return false;
      }

      // 3. Status Filter
      if (statusFilter !== "ALL" && (finding.status || "").toUpperCase() !== statusFilter) {
        return false;
      }

      // 4. Verification Status Filter
      if (verificationFilter !== "ALL") {
        const vState = (finding.verification_state || finding.verification_status || "").toUpperCase();
        if (vState !== verificationFilter) return false;
      }

      // 5. Search Text Filter
      if (!needle) return true;
      const target = targetLabel(finding);
      const cveStr = cveValues(finding).join(" ");
      const blob = `${target} ${(finding.title || "")} ${(finding.evidence || "")} ${(finding.details || "")} ${cveStr}`.toLowerCase();
      return blob.includes(needle);
    });

    const sorted = [...filtered].sort((left, right) => {
      const leftValue = sortValue(left, sortState.key);
      const rightValue = sortValue(right, sortState.key);
      if (leftValue < rightValue) return sortState.direction === "asc" ? -1 : 1;
      if (leftValue > rightValue) return sortState.direction === "asc" ? 1 : -1;
      return 0;
    });

    return sorted;
  }, [localFindings, activeTab, severityFilter, statusFilter, verificationFilter, sortState, queryText, targetParam, scanIdParam]);

  const totalPages = Math.max(1, Math.ceil(filteredAndSortedFindings.length / pageSize));
  const visibleFindings = filteredAndSortedFindings.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize);
  const visibleIdsKey = visibleFindings.map((finding) => finding.id).join(",");

  // Fetch AI Recommendations safely without infinite re-render loops
  useEffect(() => {
    if (!visibleIdsKey) return;
    const pending = visibleFindings.filter((finding) => finding.id && !aiRecommendations[finding.id]);
    if (!pending.length) return;
    const pendingIds = pending.map((f) => f.id);

    api.post("/ai/finding-recommendations", { finding_ids: pendingIds }).then((response) => {
      setAiProvider(response.data.provider || "local-fallback");
      setAiStatus(response.data.provider === "nvidia-nim" ? "ready" : "fallback");
      setAiRecommendations((current) => {
        const next = { ...current };
        for (const id of pendingIds) {
          next[id] = "AI recommendation generated.";
        }
        for (const item of response.data.items || []) {
          if (item.finding_id) {
            next[item.finding_id] = item.recommendation;
          }
        }
        return next;
      });
    }).catch(() => {
      setAiStatus("error");
    });
  }, [visibleIdsKey]);

  // Update Finding Assignment / Verification / Status
  const updateFinding = async (findingId) => {
    const payload = assignmentState[findingId];
    if (!payload) return;
    try {
      const response = await api.patch(`/findings/${findingId}`, {
        assigned_to: payload.assigned_to || null,
        team_name: payload.team_name || null,
        verification_state: payload.verification_state || null,
        status: payload.status || null,
      });
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
    } catch {
      // Graceful error handling
    }
  };

  const markFalsePositive = async (findingId) => {
    try {
      const response = await api.patch(`/findings/${findingId}`, { mark_false_positive: true });
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
    } catch {
      // Graceful error handling
    }
  };

  const deleteFinding = async (findingId) => {
    if (!window.confirm("Are you sure you want to delete this finding?")) return;
    try {
      await api.delete(`/findings/${findingId}`);
      setLocalFindings((current) => current.filter((item) => item.id !== findingId));
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(findingId);
        return next;
      });
    } catch (error) {
      console.error("Failed to delete finding:", error);
    }
  };

  const toggleSelectOne = (id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const visibleIds = (visibleFindings || []).map((f) => f.id);
    const allVisSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.has(id));

    if (allVisSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        visibleIds.forEach((id) => next.delete(id));
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        visibleIds.forEach((id) => next.add(id));
        return next;
      });
    }
  };

  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) return;
    if (!window.confirm(`Are you sure you want to delete ${selectedIds.size} selected finding(s)?`)) return;

    const idsToDelete = Array.from(selectedIds);
    try {
      await api.post("/findings/batch-delete", { finding_ids: idsToDelete });
      setLocalFindings((current) => current.filter((item) => !selectedIds.has(item.id)));
      setSelectedIds(new Set());
    } catch (error) {
      console.error("Failed to delete selected findings:", error);
    }
  };

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
    const text = aiRecommendations[finding.id] || (finding.ai_recommendation ? finding.ai_recommendation : (aiStatus === "error" ? "AI recommendation unavailable." : "Analyzing remediation..."));
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

  const renderHeaderCell = (column, index) => {
    if (column.key === "select") {
      const visIds = (visibleFindings || []).map((f) => f.id);
      const allVisSelected = visIds.length > 0 && visIds.every((id) => selectedIds.has(id));
      return (
        <th key={column.key} className="findings-table-layout__header-cell" style={{ textAlign: "center", padding: "8px" }}>
          <input
            type="checkbox"
            checked={allVisSelected}
            onChange={toggleSelectAll}
            title="Select all visible findings"
            style={{ cursor: "pointer", width: "16px", height: "16px", accentColor: "#ef4444" }}
          />
        </th>
      );
    }
    return (
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
  };

  // Empty state copy depending on selected tab
  const getEmptyStateMessage = () => {
    if (activeTab === "openvas") return "No network findings detected";
    if (activeTab === "zap") return "No web findings detected";
    if (activeTab === "mobsf") return "No mobile findings detected";
    return "No findings found";
  };

  return (
    <section className="panel" style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
      {/* Target Active Filter Banner */}
      {targetParam && (
        <div style={{ background: "linear-gradient(135deg, #0284c722 0%, #0369a122 100%)", border: "1px solid #0284c755", padding: "12px 16px", borderRadius: "8px", marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "1.4rem" }}>🎯</span>
            <div>
              <div style={{ color: "#38bdf8", fontWeight: 700, fontSize: "0.95rem" }}>
                Filtered Vulnerability Findings for Target: <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: "4px", color: "#34d399" }}>{targetParam}</code>
              </div>
              <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginTop: "2px" }}>
                Displaying {filteredAndSortedFindings.length} security findings matching target IP, CIDR block, or URL.
              </div>
            </div>
          </div>
          <Link to="/findings" style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "6px 14px", borderRadius: "6px", fontSize: "0.8rem", textDecoration: "none", fontWeight: 600, transition: "background 0.2s" }}>
            Show All Findings ✕
          </Link>
        </div>
      )}

      {/* Panel Header & Controls */}
      <div className="panel__header" style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "16px", marginBottom: "20px" }}>
        <div>
          <p className="eyebrow" style={{ color: "#38bdf8", textTransform: "uppercase", fontSize: "0.75rem", letterSpacing: "1px" }}>
            Security Findings Engine
          </p>
          <h2 style={{ color: "#f8fafc", margin: "4px 0 0 0", fontSize: "1.5rem" }}>
            Vulnerability Findings & Telemetry
          </h2>
        </div>

        {/* Global Controls & Filters */}
        <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
          {/* Search Box */}
          <input
            className="scan-input"
            placeholder="Search title, target, CVE, details..."
            value={queryText}
            onChange={(event) => setQueryText(event.target.value)}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "8px 12px", borderRadius: "6px", minWidth: "220px" }}
          />

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "8px 12px", borderRadius: "6px" }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "8px 12px", borderRadius: "6px" }}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Verification Status Filter */}
          <select
            value={verificationFilter}
            onChange={(e) => setVerificationFilter(e.target.value)}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "8px 12px", borderRadius: "6px" }}
          >
            <option value="ALL">All Verifications</option>
            <option value="PENDING">Pending</option>
            <option value="VERIFIED">Verified</option>
            <option value="UNVERIFIED">Unverified</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Page Size */}
          <select
            className="scan-select"
            value={pageSize}
            onChange={(event) => setPageSize(Number(event.target.value))}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "8px 12px", borderRadius: "6px" }}
          >
            <option value={10}>10 per page</option>
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={100}>100 per page</option>
          </select>
        </div>
      </div>

      {/* Batch Actions Bar when items are checked */}
      {selectedIds.size > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: "12px", background: "#451a1a44", border: "1px solid #7f1d1daa", padding: "10px 16px", borderRadius: "8px", marginBottom: "16px" }}>
          <span style={{ color: "#fca5a5", fontWeight: 600, fontSize: "0.9rem" }}>
            {selectedIds.size} finding(s) selected
          </span>
          <button
            type="button"
            className="scan-action scan-action--cancel"
            onClick={handleBatchDelete}
            style={{ background: "#dc2626", color: "#ffffff", border: "1px solid #b91c1c", padding: "6px 14px", borderRadius: "6px", cursor: "pointer", fontWeight: 700, fontSize: "0.85rem" }}
          >
            🗑️ Delete Selected ({selectedIds.size})
          </button>
          <button
            type="button"
            onClick={() => setSelectedIds(new Set())}
            style={{ background: "#1e293b", color: "#94a3b8", border: "1px solid #334155", padding: "6px 12px", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem" }}
          >
            Deselect All
          </button>
        </div>
      )}

      {/* Target Type Filter Tabs (All / Network / Web / Mobile) */}
      <div className="subtabs" style={{ display: "flex", gap: "8px", borderBottom: "1px solid #1e293b", paddingBottom: "12px", marginBottom: "16px" }}>
        {TAB_OPTIONS.map((tab) => {
          const count = localFindings.filter((finding) => findingMatchesTab(finding, tab.key)).length;
          return (
            <button
              key={tab.key}
              type="button"
              className={activeTab === tab.key ? "subtab is-active" : "subtab"}
              onClick={() => setActiveTab(tab.key)}
              style={{
                background: activeTab === tab.key ? "#0284c722" : "#1e293b",
                color: activeTab === tab.key ? "#38bdf8" : "#94a3b8",
                border: `1px solid ${activeTab === tab.key ? "#0284c766" : "#334155"}`,
                padding: "8px 16px",
                borderRadius: "6px",
                fontWeight: 600,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              {tab.label}
              <span style={{ background: "#0f172a", padding: "2px 6px", borderRadius: "10px", fontSize: "0.75rem" }}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Findings Data Table */}
      <div className="table-wrap" style={{ overflowX: "auto" }}>
        <table className="table findings-table-compact findings-table-layout" style={{ width: "100%", borderCollapse: "collapse" }}>
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
            <tr style={{ borderBottom: "1px solid #334155", textAlign: "left" }}>
              {COLUMN_DEFS.map(renderHeaderCell)}
            </tr>
          </thead>
          <tbody>
            {visibleFindings.map((finding) => {
              const draft = assignmentState[finding.id] || {
                assigned_to: finding.assigned_to || "",
                team_name: finding.team_name || "",
                verification_state: finding.verification_state || finding.verification_status || "pending",
                status: finding.status || "OPEN",
              };
              const targetSum = targetSummary(finding);
              const isChecked = selectedIds.has(finding.id);

              return (
                <tr
                  key={finding.id}
                  className={isChecked ? "finding-row--selected" : (targetParam && targetLabel(finding).toLowerCase().includes(targetParam.toLowerCase()) ? "finding-row--selected" : "")}
                  style={{ borderBottom: "1px solid #1e293b", background: isChecked ? "#451a1a22" : "transparent" }}
                >
                  {/* Select Checkbox */}
                  <td style={{ padding: "12px", textAlign: "center" }}>
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleSelectOne(finding.id)}
                      style={{ cursor: "pointer", width: "16px", height: "16px", accentColor: "#ef4444" }}
                    />
                  </td>

                  {/* Date */}
                  <td data-label="Date" style={{ padding: "12px", fontSize: "0.85rem", color: "#94a3b8" }}>
                    {detectedLabel(finding)}
                  </td>

                  {/* Severity */}
                  <td data-label="Severity" style={{ padding: "12px" }}>
                    <span className={`pill pill--${severityLabel(finding.severity)}`}>
                      {severityLabel(finding.severity).toUpperCase()}
                    </span>
                  </td>

                  {/* Title & Port */}
                  <td data-label="Title" style={{ padding: "12px" }}>
                    <Link className="finding-title-link" to={`/findings/${finding.id}`} style={{ fontWeight: 600, color: "#38bdf8", textDecoration: "none" }}>
                      {finding.title}
                    </Link>
                    <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "4px", flexWrap: "wrap" }}>
                      {finding.port > 0 && (
                        <span style={{ fontSize: "0.72rem", color: "#94a3b8", fontFamily: "monospace" }}>
                          {finding.port}/{finding.protocol || "tcp"}
                        </span>
                      )}
                      <span style={{
                        fontSize: "0.7rem",
                        fontWeight: 700,
                        padding: "1px 7px",
                        borderRadius: "4px",
                        background: (finding.source || "").includes("nmap+socket") ? "#065f4622" : (finding.source || "").includes("nmap") ? "#0284c722" : "#3b82f622",
                        color: (finding.source || "").includes("nmap+socket") ? "#34d399" : (finding.source || "").includes("nmap") ? "#38bdf8" : "#60a5fa",
                        border: `1px solid ${(finding.source || "").includes("nmap+socket") ? "#05966944" : "#0284c744"}`,
                      }}>
                        {finding.source === "nmap+socket" ? "⚡ Dual-Engine (Nmap + Socket)" : finding.source === "nmap" ? "🔍 Nmap Engine" : finding.source === "socket" ? "🔌 Socket Scanner" : finding.source === "zap" ? "🌐 ZAP Web Engine" : finding.source === "mobsf" ? "📱 MobSF Mobile Engine" : (finding.source || "Scanner Engine").toUpperCase()}
                      </span>
                    </div>
                  </td>

                  {/* Details */}
                  <td data-label="Details" style={{ padding: "12px", fontSize: "0.85rem", color: "#cbd5e1", maxWidth: "320px" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                      <span style={{
                        display: "block",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        overflow: expandedDetails[finding.id] ? "visible" : "hidden",
                        maxHeight: expandedDetails[finding.id] ? "none" : "5.2em",
                        lineHeight: "1.5",
                        color: "#cbd5e1",
                      }}>
                        {detailsSummary(finding)}
                      </span>
                      {detailsSummary(finding).length > 150 && (
                        <button
                          type="button"
                          onClick={() => setExpandedDetails((current) => ({ ...current, [finding.id]: !current[finding.id] }))}
                          style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", fontSize: "0.75rem", padding: 0, marginTop: "2px", textAlign: "left" }}
                        >
                          {expandedDetails[finding.id] ? "See less ▲" : "See more ▼"}
                        </button>
                      )}
                    </div>
                  </td>


                  {/* Target Asset Link */}
                  <td data-label="Target Asset" style={{ padding: "12px" }}>
                    <Link
                      to={`/hosts?target=${encodeURIComponent(targetSum.primary)}`}
                      style={{ color: "#f8fafc", fontWeight: 600, textDecoration: "none" }}
                      title="View Asset details on Hosts page"
                    >
                      {targetSum.primary}
                    </Link>
                    <p style={{ margin: "2px 0 0 0", fontSize: "0.75rem", color: "#64748b" }}>
                      {targetSum.secondary}
                    </p>
                  </td>

                  {/* CVE */}
                  <td data-label="CVE" style={{ padding: "12px" }}>
                    {renderCveLinks(finding)}
                  </td>

                  {/* Count */}
                  <td data-label="Count" style={{ padding: "12px", textAlign: "center", color: "#94a3b8" }}>
                    {finding.duplicate_count || finding.count || 1}
                  </td>

                  {/* CVSS */}
                  <td data-label="CVSS" style={{ padding: "12px", fontWeight: 700, color: (finding.cvss_score || 0) >= 7.0 ? "#ef4444" : "#eab308" }}>
                    {finding.cvss_score != null ? finding.cvss_score.toFixed(1) : "n/a"}
                  </td>

                  {/* Owner / Group Assignment (IAM Integration) */}
                  <td data-label="Owner / Group" style={{ padding: "12px" }}>
                    <div className="finding-actions-cell" style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                      <select
                        className="scan-select"
                        value={draft.assigned_to}
                        onChange={(event) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, assigned_to: event.target.value } }))}
                        style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem" }}
                      >
                        <option value="">-- Assign Owner --</option>
                        {(users || []).map((entry) => (
                          <option key={entry.id || entry.username} value={entry.username}>
                            {entry.username} ({entry.role || "User"})
                          </option>
                        ))}
                      </select>

                      <select
                        className="scan-select"
                        value={draft.team_name}
                        onChange={(event) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, team_name: event.target.value } }))}
                        style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem" }}
                      >
                        <option value="">-- Assign Group --</option>
                        {(groups || []).map((group) => (
                          <option key={group.id || group.name} value={group.name}>
                            {group.name}
                          </option>
                        ))}
                      </select>

                      <div className="scan-actions" style={{ display: "flex", gap: "4px", marginTop: "2px" }}>
                        <button
                          type="button"
                          className="scan-action scan-action--resume"
                          onClick={() => updateFinding(finding.id)}
                          style={{ background: "#0284c722", color: "#38bdf8", border: "1px solid #0284c744", padding: "2px 8px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}
                        >
                          Save
                        </button>
                        <button
                          type="button"
                          className="scan-action scan-action--cancel"
                          onClick={() => markFalsePositive(finding.id)}
                          style={{ background: "#451a1a", color: "#fca5a5", border: "1px solid #7f1d1d", padding: "2px 8px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}
                        >
                          False Positive
                        </button>
                        <button
                          type="button"
                          className="scan-action scan-action--delete"
                          onClick={() => deleteFinding(finding.id)}
                          style={{ background: "#7f1d1d22", color: "#f87171", border: "1px solid #7f1d1d66", padding: "2px 8px", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}
                          title="Delete finding"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </td>

                  {/* Verification Status */}
                  <td data-label="Verification" style={{ padding: "12px" }}>
                    <select
                      className="scan-select"
                      value={draft.verification_state}
                      onChange={(event) => {
                        const verification_state = event.target.value;
                        let nextStatus = draft.status || "open";
                        if (verification_state === "scheduled") nextStatus = "in_progress";
                        if (verification_state === "verified") nextStatus = "resolved";
                        setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, verification_state, status: nextStatus } }));
                      }}
                      style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem" }}
                    >
                      <option value="pending">Pending</option>
                      <option value="unverified">Unverified</option>
                      <option value="in_review">In Review</option>
                      <option value="scheduled">Scheduled</option>
                      <option value="verified">Verified</option>
                    </select>
                  </td>

                  {/* AI Recommendation */}
                  <td data-label="AI Recommendation" style={{ padding: "12px", fontSize: "0.85rem", color: "#cbd5e1" }}>
                    <div className="recommendation-cell">
                      <span>{recommendationPreview(finding)}</span>
                      {(aiRecommendations[finding.id] || finding.ai_recommendation || "").length > 112 && (
                        <button
                          type="button"
                          className="recommendation-cell__toggle"
                          onClick={() => setExpandedRecommendations((current) => ({ ...current, [finding.id]: !current[finding.id] }))}
                          style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", fontSize: "0.75rem", padding: 0, marginTop: "4px" }}
                        >
                          {expandedRecommendations[finding.id] ? "See less" : "See more"}
                        </button>
                      )}
                    </div>
                  </td>

                  {/* Status */}
                  <td data-label="Status" style={{ padding: "12px" }}>
                    <select
                      className="scan-select"
                      value={draft.status}
                      onChange={(event) => {
                        const status = event.target.value;
                        let nextVerification = draft.verification_state || "pending";
                        if (status === "resolved" || status === "RESOLVED") nextVerification = "verified";
                        else if ((status === "in_progress" || status === "IN_PROGRESS") && nextVerification === "pending") nextVerification = "scheduled";
                        setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, status, verification_state: nextVerification } }));
                      }}
                      style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "4px 8px", borderRadius: "4px", fontSize: "0.8rem" }}
                    >
                      <option value="open">Open</option>
                      <option value="in_progress">In Progress</option>
                      <option value="resolved">Resolved</option>
                    </select>
                  </td>
                </tr>
              );
            })}

            {/* Empty State - Absolute No Mock Data */}
            {!visibleFindings.length && (
              <tr>
                <td colSpan="12" style={{ textAlign: "center", padding: "48px 16px", color: "#64748b" }}>
                  <p style={{ fontSize: "1rem", fontWeight: 600, color: "#94a3b8", margin: 0 }}>
                    {getEmptyStateMessage()}
                  </p>
                  <p style={{ fontSize: "0.85rem", margin: "4px 0 0 0" }}>
                    No vulnerability findings matched your filter or search criteria.
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div className="pagination-bar" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "20px", color: "#94a3b8", fontSize: "0.875rem" }}>
        <span>
          Showing {visibleFindings.length ? pageIndex * pageSize + 1 : 0}-{Math.min((pageIndex + 1) * pageSize, filteredAndSortedFindings.length)} of {filteredAndSortedFindings.length} findings
        </span>
        <div className="scan-actions" style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            type="button"
            className="scan-action"
            disabled={pageIndex === 0}
            onClick={() => setPageIndex((current) => Math.max(current - 1, 0))}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "6px 12px", borderRadius: "6px", cursor: pageIndex === 0 ? "not-allowed" : "pointer" }}
          >
            Previous
          </button>
          <span className="pagination-page">
            Page {pageIndex + 1} of {totalPages}
          </span>
          <button
            type="button"
            className="scan-action"
            disabled={pageIndex >= totalPages - 1}
            onClick={() => setPageIndex((current) => Math.min(current + 1, totalPages - 1))}
            style={{ background: "#1e293b", color: "#f8fafc", border: "1px solid #334155", padding: "6px 12px", borderRadius: "6px", cursor: pageIndex >= totalPages - 1 ? "not-allowed" : "pointer" }}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}

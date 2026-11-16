import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import api from "../api/client";
import BarField3D from "../components/cc/BarField3D";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import { SEV_HEX } from "../components/cc/ccConstants";
import "../commandcenter.css";
import "../findings.css";

const SLA_DAYS = { critical: 7, high: 30, medium: 90, low: 180 };
const ENGINE_COLS = [["openvas", "Network"], ["zap", "Web"], ["mobsf", "Mobile"], ["endpoint", "Endpoint"]];
const MATRIX_ROWS = ["critical", "high", "medium", "low"].map((sev) => ({ key: sev, label: sev, color: SEV_HEX[sev] }));

/** "13 Nov 2026, 14:32" in the viewer's time zone. */
function fmtStamp(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString([], { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function Kpi({ label, value, tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value == null ? "—" : shown}</strong>
      {hint ? <small className="fxp-hint">{hint}</small> : null}
    </div>
  );
}

const TAB_OPTIONS = [
  { key: "all", label: "All" },
  { key: "openvas", label: "Network" },
  { key: "zap", label: "Web" },
  { key: "mobsf", label: "Mobile" },
  { key: "endpoint", label: "Endpoint" },
];

const TAB_SOURCE_MAP = {
  all: null,
  endpoint: ["endpoint-agent", "agent", "windows-agent", "Endpoint", "VAP Agent"],
  openvas: ["openvas", "network-db", "host", "host-scan", "network", "nmap", "socket", "nmap+socket", "Network"],
  zap: ["zap", "web", "web-scan", "web-db", "zap-proxy", "owasp", "nuclei", "testssl", "Web"],
  mobsf: ["mobsf", "mobile", "apk", "ipa", "Mobile"],
};

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
  if (details.url && details.url !== "n/a") {
    try { return new URL(details.url).host || details.url; } catch { return details.url; }
  }
  if (meta.url && meta.url !== "n/a") {
    try { return new URL(meta.url).host || meta.url; } catch { return meta.url; }
  }
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

function cveValues(finding) {
  const raw = finding.cve_id || finding.cve || finding.display_id || "";
  const matches = raw.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map((item) => item.toUpperCase()))];
}

function sanitizeProofText(raw) {
  if (!raw || typeof raw !== "string") return "";
  return raw
    // eslint-disable-next-line no-control-regex -- stripping control characters from scanner output is the point
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function detailsExplanation(finding) {
  // Only what the scanner or correlation engine actually recorded. No canned text per keyword.
  const meta = finding.finding_metadata || {};
  const correlation = meta.correlation || {};
  if (typeof meta.description === "string" && meta.description.trim().length > 25) return meta.description.trim();
  if (correlation.correlation_summary) return correlation.correlation_summary;
  if (typeof finding.details === "string" && finding.details.trim().length > 10) return finding.details.trim();
  return "";
}

function detailsProof(finding) {
  const meta = finding.finding_metadata || {};
  const evidence = sanitizeProofText(finding.evidence || "");
  const target = finding.target || meta.host || meta.url || "";
  const port = finding.port ? `${finding.port}/${finding.protocol || "tcp"}` : "";

  const proofItems = [];

  if (evidence && !evidence.toLowerCase().startsWith("security finding")) {
    proofItems.push(evidence);
  }
  if (meta.banner && typeof meta.banner === "string" && !evidence.includes(meta.banner)) {
    proofItems.push(`Service Banner: ${sanitizeProofText(meta.banner)}`);
  }
  if (meta.param && !evidence.includes(meta.param)) {
    proofItems.push(`Vulnerable Parameter: ${meta.param}`);
  }
  if (meta.attack && !evidence.includes(meta.attack)) {
    proofItems.push(`Probe Payload: ${meta.attack}`);
  }
  if (meta.path && !evidence.includes(meta.path)) {
    proofItems.push(`Discovered Path: ${meta.path}`);
  }

  if (proofItems.length > 0) {
    return proofItems.join("\n");
  }

  if (port && target) {
    return `The scanner reported ${port} ${finding.state || "open"} on ${target}${finding.service ? ` (${finding.service})` : ""}. No further evidence was recorded.`;
  }

  return "";
}

function findingMatchesTab(finding, tabKey) {
  if (tabKey === "all") return true;
  const sources = TAB_SOURCE_MAP[tabKey] || [tabKey];
  const src = (finding.source || "").toLowerCase();
  const cat = (finding.category || "").toLowerCase();
  return sources.some((s) => src.includes(s.toLowerCase()) || cat.includes(s.toLowerCase()));
}

/** Host part of a target: no scheme, path or port, lower-cased. */
function hostOf(value) {
  let host = String(value || "").trim().toLowerCase().replace(/^[a-z]+:\/\//, "").split("/")[0];
  if (host.split(":").length === 2) host = host.split(":")[0];
  return host === "n/a" ? "" : host;
}

/** Exact host match, or a subdomain of the wanted domain. Never a partial IP ("10.0.0.2" is not "10.0.0.25"). */
function hostMatches(host, wanted) {
  if (!host || !wanted) return false;
  if (host === wanted) return true;
  const isIp = /^[\d.]+$/.test(wanted) || wanted.includes(":");
  return !isIp && host.endsWith(`.${wanted}`);
}

function statusMatches(finding, filter) {
  const status = String(finding.status || "open").toUpperCase();
  if (filter === "ALL") return true;
  if (filter === "ACTIVE") return status === "OPEN" || status === "IN_PROGRESS";
  return status === filter;
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

function errorText(error) {
  const status = error?.response?.status;
  if (status === 403) return "You don't have permission to change findings.";
  const detail = error?.response?.data?.detail;
  return typeof detail === "string" ? detail : "Couldn't save. Please try again.";
}

const SOURCE_LABELS = {
  zap: "ZAP web engine",
  mobsf: "Mobile engine",
  nmap: "Nmap",
  socket: "Socket probe",
  "nmap+socket": "Nmap + socket",
  openvas: "Network engine",
  "endpoint-agent": "Endpoint agent",
  nuclei: "Nuclei",
  testssl: "testssl.sh",
  web: "Built-in web checks",
  "network-db": "Network checks",
};

function sourceLabel(source) {
  const key = String(source || "").toLowerCase();
  return SOURCE_LABELS[key] || (source ? String(source) : "Scanner");
}

function detectedShort(finding) {
  return fmtStamp(finding.detected_at || finding.discovered_at) || "—";
}

/** When this finding was last confirmed by a scan. */
function lastScanned(finding) {
  return fmtStamp(finding.last_seen || finding.scan_finished_at);
}

export default function Findings({ findings, users, groups, canEdit = true }) {
  const [searchParams] = useSearchParams();
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
  const [statusFilter, setStatusFilter] = useState("ACTIVE");
  const [verificationFilter, setVerificationFilter] = useState("ALL");

  const [pageSize, setPageSize] = useState(10);
  const [pageIndex, setPageIndex] = useState(0);
  const [assignmentState, setAssignmentState] = useState({});
  const [sortState, setSortState] = useState({ key: "date", direction: "desc" });
  
  const [assignees, setAssignees] = useState(null);
  const [batchError, setBatchError] = useState("");
  const [expandedDetails, setExpandedDetails] = useState({});
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [saveNotes, setSaveNotes] = useState({});
  
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
    const needle = queryText.trim().toLowerCase();
    
    const filtered = localFindings.filter((finding) => {
      // 0. Flexible Target IP / CIDR / URL filter if target query param is present
      if (targetParam) {
        const wanted = hostOf(targetParam);
        const meta = finding.finding_metadata || {};
        const candidates = [finding.target, meta.host, meta.url, meta.ip_address, meta.hostname, targetSummary(finding).primary].map(hostOf);
        if (!candidates.some((host) => hostMatches(host, wanted))) return false;
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
      if (!statusMatches(finding, statusFilter)) return false;

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

  // People and teams to assign to. Works for analysts too (the IAM user list is admin-only).
  useEffect(() => {
    if (!canEdit) return;
    api.get("/findings/assignees").then((response) => setAssignees(response.data)).catch(() => setAssignees(null));
  }, [canEdit]);

  const ownerOptions = assignees?.users || (users || []).map((entry) => ({ username: entry.username, full_name: entry.full_name }));
  const teamOptions = assignees?.groups || (groups || []).map((group) => group.name);

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
      setSaveNotes((current) => ({ ...current, [findingId]: { ok: true, text: "Saved." } }));
    } catch (error) {
      setSaveNotes((current) => ({ ...current, [findingId]: { ok: false, text: errorText(error) } }));
    }
  };

  const markFalsePositive = async (findingId) => {
    try {
      const response = await api.patch(`/findings/${findingId}`, { mark_false_positive: true });
      setLocalFindings((current) => current.map((item) => (item.id === findingId ? response.data : item)));
      setSaveNotes((current) => ({ ...current, [findingId]: { ok: true, text: "Marked as false positive." } }));
    } catch (error) {
      setSaveNotes((current) => ({ ...current, [findingId]: { ok: false, text: errorText(error) } }));
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
      setSaveNotes((current) => ({ ...current, [findingId]: { ok: false, text: errorText(error) } }));
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
      setBatchError("");
    } catch (error) {
      setBatchError(errorText(error));
    }
  };

  const toggleSort = (key) => {
    setSortState((current) => (
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: key === "title" || key === "target" || key === "owner" || key === "recommendation" ? "asc" : "desc" }
    ));
  };

  const severityCounts = useMemo(() => {
    const counts = { ALL: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const finding of localFindings) {
      if (!findingMatchesTab(finding, activeTab) || !statusMatches(finding, statusFilter)) continue;
      counts.ALL += 1;
      const key = (finding.severity || "info").toUpperCase();
      if (counts[key] !== undefined) counts[key] += 1;
    }
    return counts;
  }, [localFindings, activeTab, statusFilter]);

  const overview = useMemo(() => {
    const now = Date.now();
    const active = localFindings.filter((f) => statusMatches(f, "ACTIVE"));
    const sevOf = (f) => (f.severity || "info").toLowerCase();
    const values = MATRIX_ROWS.map((row) => ENGINE_COLS.map(([tab]) => active.filter((f) => sevOf(f) === row.key && findingMatchesTab(f, tab)).length));
    const pastSla = active.filter((f) => {
      const days = SLA_DAYS[sevOf(f)];
      const due = f.sla_due_at ? new Date(f.sla_due_at).getTime() : (days ? new Date(f.detected_at).getTime() + days * 86400000 : NaN);
      return Number.isFinite(due) && due < now;
    }).length;
    const lastScan = localFindings.reduce((max, f) => Math.max(max, new Date(f.last_seen || f.scan_finished_at || 0).getTime() || 0), 0);
    return {
      open: active.filter((f) => sevOf(f) !== "info").length,
      urgent: active.filter((f) => ["critical", "high"].includes(sevOf(f))).length,
      unassigned: active.filter((f) => !f.assigned_to && sevOf(f) !== "info").length,
      newDay: active.filter((f) => now - new Date(f.detected_at).getTime() < 86400000).length,
      pastSla,
      withCve: active.filter((f) => cveValues(f).length).length,
      values,
      lastScan: lastScan ? new Date(lastScan).toISOString() : null,
    };
  }, [localFindings]);

  const toggleExpanded = (id) => setExpandedDetails((current) => ({ ...current, [id]: !current[id] }));

  const sortIndicator = (key) => {
    if (sortState.key !== key) return "none";
    return sortState.direction === "asc" ? "ascending" : "descending";
  };

  const sortButton = (label, sortKey) => (
    <button type="button" className="fx-sort" onClick={() => toggleSort(sortKey)}>
      {label}
      <span aria-hidden="true">{sortState.key === sortKey ? (sortState.direction === "asc" ? "↑" : "↓") : "↕"}</span>
    </button>
  );

  const visIds = visibleFindings.map((f) => f.id);
  const allVisSelected = visIds.length > 0 && visIds.every((id) => selectedIds.has(id));

  const emptyMessage = activeTab === "openvas" ? "No network findings" : activeTab === "zap" ? "No web findings" : activeTab === "mobsf" ? "No mobile findings" : activeTab === "endpoint" ? "No endpoint findings" : "No findings";

  return (
    <div className="cc fx-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Findings</h1>
        </div>
        <div className="cc-top__tools">
          {overview.lastScan ? <span className="cc-clock">Last scan result {fmtStamp(overview.lastScan)}</span> : null}
          <span className="fxp-live">Live · refreshes every 30 s</span>
        </div>
      </header>

      <div className="cc-kpis">
        <Kpi label="Open findings" value={overview.open} hint="excluding info" />
        <Kpi label="Critical + high" value={overview.urgent} tone={overview.urgent ? "hot" : ""} />
        <Kpi label="Past SLA" value={overview.pastSla} tone={overview.pastSla ? "hot" : ""} hint="7 / 30 / 90 / 180 days" />
        <Kpi label="Unassigned" value={overview.unassigned} />
        <Kpi label="New · last 24 h" value={overview.newDay} tone="live" />
        <Kpi label="With a confirmed CVE" value={overview.withCve} />
      </div>

      {overview.values.some((row) => row.some(Boolean)) ? (
        <section className="cc-panel fxp-chart" aria-label="Open findings by severity and engine">
          <header className="cc-panel__head"><h2>Open findings · severity × engine</h2></header>
          <BarField3D rows={MATRIX_ROWS} cols={ENGINE_COLS.map(([, label]) => label)} values={overview.values}
            caption="Open findings per severity and scan engine"
            describe={(row, col, value) => <><strong>{value}</strong> {row.label} open from the {col.toLowerCase()} engine</>} />
        </section>
      ) : null}

      <div className="fx">
      {targetParam && (
        <div className="fx-banner" role="status">
          <span>
            Showing findings for <code className="nw-mono">{targetParam}</code> ({filteredAndSortedFindings.length})
          </span>
          <Link to="/findings" className="nw-btn nw-btn--ghost">Clear filter</Link>
        </div>
      )}

      <section className="nw-card fx-toolbar" aria-label="Filter findings">
        <div className="fx-toolbar__row">
          <label className="fx-search">
            <span className="fx-sr">Search findings</span>
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
              <circle cx="7" cy="7" r="5" stroke="currentColor" strokeWidth="1.6" fill="none" />
              <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
            <input
              type="search"
              placeholder="Search title, target, CVE or evidence"
              value={queryText}
              onChange={(event) => setQueryText(event.target.value)}
            />
          </label>
          <div className="fx-segment" role="group" aria-label="Finding type">
            {TAB_OPTIONS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                aria-pressed={activeTab === tab.key}
                onClick={() => setActiveTab(tab.key)}
              >
                {tab.label}
                <span className="fx-count">{localFindings.filter((finding) => findingMatchesTab(finding, tab.key) && statusMatches(finding, statusFilter)).length}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="fx-toolbar__row">
          <div className="fx-chips" role="group" aria-label="Severity">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => (
              <button
                key={sev}
                type="button"
                className={`fx-chip fx-chip--${sev.toLowerCase()}`}
                aria-pressed={severityFilter === sev}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev === "ALL" ? "All severities" : sev.charAt(0) + sev.slice(1).toLowerCase()}
                <span className="fx-count">{severityCounts[sev]}</span>
              </button>
            ))}
          </div>
          <div className="fx-selects">
            <label>
              <span className="fx-sr">Status</span>
              <select className="scan-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                <option value="ACTIVE">Open + in progress</option>
                <option value="ALL">Any status</option>
                <option value="OPEN">Open</option>
                <option value="IN_PROGRESS">In progress</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False positive</option>
              </select>
            </label>
            <label>
              <span className="fx-sr">Verification</span>
              <select className="scan-select" value={verificationFilter} onChange={(e) => setVerificationFilter(e.target.value)}>
                <option value="ALL">Any verification</option>
                <option value="PENDING">Pending</option>
                <option value="VERIFIED">Verified</option>
                <option value="UNVERIFIED">Unverified</option>
                <option value="FALSE_POSITIVE">False positive</option>
              </select>
            </label>
          </div>
        </div>
      </section>

      {canEdit && selectedIds.size > 0 && (
        <div className="fx-batch" role="region" aria-label="Bulk actions">
          <strong>{selectedIds.size} selected</strong>
          <button type="button" className="nw-btn fx-danger" onClick={handleBatchDelete}>
            Delete selected
          </button>
          <button type="button" className="nw-btn nw-btn--ghost" onClick={() => setSelectedIds(new Set())}>
            Clear selection
          </button>
          {batchError ? <span className="fx-note fx-note--error" role="alert">{batchError}</span> : null}
        </div>
      )}

      <section className="nw-card fx-table-card" aria-label="Findings">
        <div className="fx-table-scroll">
          <table className="fx-table">
            <thead>
              <tr>
                <th scope="col" className="fx-col-check">
                  <input
                    type="checkbox"
                    checked={allVisSelected}
                    onChange={toggleSelectAll}
                    aria-label="Select all findings on this page"
                  />
                </th>
                <th scope="col" aria-sort={sortIndicator("severity")}>{sortButton("Severity", "severity")}</th>
                <th scope="col" aria-sort={sortIndicator("title")}>{sortButton("Issue", "title")}</th>
                <th scope="col" aria-sort={sortIndicator("target")}>{sortButton("Target", "target")}</th>
                <th scope="col" aria-sort={sortIndicator("owner")}>{sortButton("Owner", "owner")}</th>
                <th scope="col" aria-sort={sortIndicator("status")}>{sortButton("Status", "status")}</th>
                <th scope="col" aria-sort={sortIndicator("date")}>{sortButton("Detected (local time)", "date")}</th>
                <th scope="col" className="fx-col-expand"><span className="fx-sr">Details</span></th>
              </tr>
            </thead>
            <tbody>
              {visibleFindings.map((finding) => {
                const draft = assignmentState[finding.id] || {
                  assigned_to: finding.assigned_to || "",
                  team_name: finding.team_name || "",
                  verification_state: finding.verification_state || finding.verification_status || "pending",
                  status: finding.status || "open",
                };
                const setDraft = (patch) => setAssignmentState((current) => ({ ...current, [finding.id]: { ...draft, ...patch } }));
                const target = targetSummary(finding);
                const isChecked = selectedIds.has(finding.id);
                const isOpen = !!expandedDetails[finding.id];
                const sev = severityLabel(finding.severity);
                const count = finding.duplicate_count || finding.count || 1;
                const cves = cveValues(finding);
                const proof = detailsProof(finding);
                const explanation = detailsExplanation(finding);
                const status = String(finding.status || "open").toLowerCase();
                const detailId = `finding-detail-${finding.id}`;

                return [
                  <tr key={finding.id} className={`fx-row${isChecked ? " is-selected" : ""}${isOpen ? " is-open" : ""}`}>
                    <td className="fx-col-check">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSelectOne(finding.id)}
                        aria-label={`Select ${finding.title}`}
                      />
                    </td>
                    <td><span className={`nw-sev nw-sev--${sev}`}>{sev}</span></td>
                    <td className="fx-issue">
                      <Link to={`/findings/${finding.id}`} className="fx-issue__title">{finding.title}</Link>
                      <div className="fx-meta">
                        <span>{sourceLabel(finding.source)}</span>
                        {finding.port > 0 ? <span className="nw-mono">{finding.port}/{finding.protocol || "tcp"}</span> : null}
                        {finding.cvss_score != null ? <span className="nw-mono">CVSS {Number(finding.cvss_score).toFixed(1)}</span> : null}
                        {cves.slice(0, 2).map((cve) => (
                          <a key={cve} className="nw-mono fx-cve" href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}`} target="_blank" rel="noreferrer">{cve}</a>
                        ))}
                        {count > 1 ? <span className="fx-times">×{count}</span> : null}
                        {finding.finding_metadata?.confirmation?.status === "confirmed" ? (
                          <span className="fx-proof-tag fx-proof-tag--ok" title={finding.finding_metadata.confirmation.detail}>Confirmed · {finding.finding_metadata.confirmation.tool}</span>
                        ) : finding.finding_metadata?.confirmation?.status === "not_reproduced" ? (
                          <span className="fx-proof-tag fx-proof-tag--warn" title={finding.finding_metadata.confirmation.detail}>Not reproduced · likely false positive</span>
                        ) : finding.finding_metadata?.confirmation?.status === "inconclusive" ? (
                          <span className="fx-proof-tag" title={finding.finding_metadata.confirmation.detail}>Check inconclusive · {finding.finding_metadata.confirmation.tool}</span>
                        ) : null}
                        {(finding.finding_metadata?.sources || []).length > 1 ? (
                          <span className="fx-proof-tag" title="Independent engines reported the same issue">
                            {finding.finding_metadata.sources.length} engines agree
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <Link to={`/findings?target=${encodeURIComponent(target.primary)}`} className="fx-target">{target.primary}</Link>
                      {target.secondary ? <div className="fx-sub">{target.secondary}</div> : null}
                    </td>
                    <td className={finding.assigned_to ? "" : "fx-sub"}>
                      {finding.assigned_to || "Unassigned"}
                      {finding.team_name ? <div className="fx-sub">{finding.team_name}</div> : null}
                    </td>
                    <td><span className={`fx-status fx-status--${status}`}>{status.replace(/_/g, " ")}</span></td>
                    <td className="fx-when">
                      <span className="nw-mono">{detectedShort(finding)}</span>
                      {lastScanned(finding) && lastScanned(finding) !== detectedShort(finding) ? <span className="fx-sub">Last scan {lastScanned(finding)}</span> : null}
                    </td>
                    <td className="fx-col-expand">
                      <button
                        type="button"
                        className="fx-expand"
                        aria-expanded={isOpen}
                        aria-controls={detailId}
                        aria-label={isOpen ? `Hide details for ${finding.title}` : `Show details for ${finding.title}`}
                        onClick={() => toggleExpanded(finding.id)}
                      >
                        <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
                          <path d="M3.5 5.25L7 8.75l3.5-3.5" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" />
                        </svg>
                      </button>
                    </td>
                  </tr>,
                  isOpen ? (
                    <tr key={`${finding.id}-detail`} className="fx-detail-row" id={detailId}>
                      <td colSpan={8}>
                        <div className="fx-detail">
                          <div className="fx-detail__body">
                            {explanation ? (
                              <section>
                                <h3>What was found</h3>
                                <p>{explanation}</p>
                              </section>
                            ) : null}
                            {finding.finding_metadata?.confirmation ? (
                              <section>
                                <h3>Confirmation</h3>
                                <p>
                                  <strong>{finding.finding_metadata.confirmation.status === "confirmed" ? "Confirmed" : finding.finding_metadata.confirmation.status === "not_reproduced" ? "Not reproduced" : finding.finding_metadata.confirmation.status === "inconclusive" ? "Inconclusive" : "Not tested"}</strong>
                                  {" "}by {finding.finding_metadata.confirmation.tool}: {finding.finding_metadata.confirmation.detail}
                                </p>
                              </section>
                            ) : null}
                            {(finding.finding_metadata?.sources || []).length > 1 ? (
                              <section>
                                <h3>Reported by</h3>
                                <p>{finding.finding_metadata.sources.map(sourceLabel).join(", ")}</p>
                              </section>
                            ) : null}
                            {proof ? (
                              <section>
                                <h3>Proof</h3>
                                <pre className="fx-proof">{proof}</pre>
                              </section>
                            ) : null}
                            {finding.finding_metadata?.possible_cves?.length ? (
                              <section>
                                <h3>Possible CVEs (unconfirmed)</h3>
                                <p>
                                  {finding.finding_metadata.possible_cves.map((cve, i) => (
                                    <span key={cve}>{i ? ", " : ""}<a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">{cve}</a></span>
                                  ))}
                                  {" — "}matched on the exposed port or service only. The version wasn't confirmed, so check whether this host is actually affected.
                                </p>
                              </section>
                            ) : null}
                            <section>
                              <h3>How to fix</h3>
                              <p>{finding.remediation || "No remediation guidance from the scanner."}</p>
                            </section>
                            <section>
                              <Link className="nw-btn" to={`/findings/${finding.id}`}>Open fix workspace</Link>
                              <p className="fx-sub">Exploitation status, EPSS, other affected targets and triage history for this issue.</p>
                            </section>
                          </div>
                          {canEdit ? (
                          <form
                            className="fx-triage"
                            aria-label={`Triage ${finding.title}`}
                            onSubmit={(event) => { event.preventDefault(); updateFinding(finding.id); }}
                          >
                            <h3>Triage</h3>
                            <label>
                              Owner
                              <select className="scan-select" value={draft.assigned_to} onChange={(e) => setDraft({ assigned_to: e.target.value })}>
                                <option value="">Unassigned</option>
                                {draft.assigned_to && !ownerOptions.some((entry) => entry.username === draft.assigned_to) ? <option value={draft.assigned_to}>{draft.assigned_to}</option> : null}
                                {ownerOptions.map((entry) => (
                                  <option key={entry.username} value={entry.username}>{entry.full_name && entry.full_name !== entry.username ? `${entry.full_name} (${entry.username})` : entry.username}</option>
                                ))}
                              </select>
                            </label>
                            <label>
                              Team
                              <select className="scan-select" value={draft.team_name} onChange={(e) => setDraft({ team_name: e.target.value })}>
                                <option value="">No team</option>
                                {draft.team_name && !teamOptions.includes(draft.team_name) ? <option value={draft.team_name}>{draft.team_name}</option> : null}
                                {teamOptions.map((name) => <option key={name} value={name}>{name}</option>)}
                              </select>
                            </label>
                            <label>
                              Status
                              <select
                                className="scan-select"
                                value={String(draft.status).toLowerCase()}
                                onChange={(e) => {
                                  const next = e.target.value;
                                  let verification = draft.verification_state || "pending";
                                  if (next === "resolved") verification = "verified";
                                  else if (next === "in_progress" && verification === "pending") verification = "scheduled";
                                  setDraft({ status: next, verification_state: verification });
                                }}
                              >
                                <option value="open">Open</option>
                                <option value="in_progress">In progress</option>
                                <option value="resolved">Resolved</option>
                                {String(draft.status).toLowerCase() === "false_positive" ? <option value="false_positive">False positive</option> : null}
                              </select>
                            </label>
                            <label>
                              Verification
                              <select
                                className="scan-select"
                                value={draft.verification_state}
                                onChange={(e) => {
                                  const verification = e.target.value;
                                  let next = draft.status || "open";
                                  if (verification === "scheduled") next = "in_progress";
                                  if (verification === "verified") next = "resolved";
                                  setDraft({ verification_state: verification, status: next });
                                }}
                              >
                                <option value="pending">Pending</option>
                                <option value="unverified">Unverified</option>
                                <option value="in_review">In review</option>
                                <option value="scheduled">Scheduled</option>
                                <option value="verified">Verified</option>
                              </select>
                            </label>
                            <div className="fx-triage__actions">
                              <button type="submit" className="nw-btn nw-btn--accent">Save</button>
                              <button type="button" className="nw-btn" onClick={() => markFalsePositive(finding.id)}>Mark false positive</button>
                              <button type="button" className="nw-btn fx-danger-text" onClick={() => deleteFinding(finding.id)}>Delete</button>
                            </div>
                            {saveNotes[finding.id] ? (
                              <p className={saveNotes[finding.id].ok ? "fx-note" : "fx-note fx-note--error"} role="status">
                                {saveNotes[finding.id].text}
                              </p>
                            ) : null}
                          </form>
                          ) : (
                            <aside className="fx-triage fx-triage--readonly">
                              <h3>Triage</h3>
                              <p>Owner: {finding.assigned_to || "Unassigned"}</p>
                              <p>Verification: {String(finding.verification_state || "pending").replace(/_/g, " ")}</p>
                              <p className="fx-sub">Read-only access. Ask an analyst or admin to change this finding.</p>
                            </aside>
                          )}
                        </div>
                      </td>
                    </tr>
                  ) : null,
                ];
              })}

              {!visibleFindings.length && (
                <tr>
                  <td colSpan={8} className="fx-empty">
                    <strong>{emptyMessage}</strong>
                    <span>Nothing matches the current filters.</span>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="fx-pager">
          <span>
            {visibleFindings.length ? pageIndex * pageSize + 1 : 0}–{Math.min((pageIndex + 1) * pageSize, filteredAndSortedFindings.length)} of {filteredAndSortedFindings.length}
          </span>
          <div className="fx-pager__controls">
            <label>
              <span className="fx-sr">Rows per page</span>
              <select className="scan-select" value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))}>
                <option value={10}>10 rows</option>
                <option value={25}>25 rows</option>
                <option value={50}>50 rows</option>
                <option value={100}>100 rows</option>
              </select>
            </label>
            <button type="button" className="nw-btn" disabled={pageIndex === 0} onClick={() => setPageIndex((current) => Math.max(current - 1, 0))}>
              Previous
            </button>
            <span className="nw-mono">{pageIndex + 1} / {totalPages}</span>
            <button type="button" className="nw-btn" disabled={pageIndex >= totalPages - 1} onClick={() => setPageIndex((current) => Math.min(current + 1, totalPages - 1))}>
              Next
            </button>
          </div>
        </div>
      </section>
      </div>
    </div>
  );
}

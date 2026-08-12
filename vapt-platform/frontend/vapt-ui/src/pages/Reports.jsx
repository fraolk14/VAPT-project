import React, { useState, useMemo, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDropzone } from "react-dropzone";
import { motion, AnimatePresence } from "framer-motion";
import axios from "axios";
import {
  FiFileText,
  FiDownload,
  FiUploadCloud,
  FiSliders,
  FiEye,
  FiCheck,
  FiAlertTriangle,
  FiShield,
  FiX,
  FiCalendar,
  FiCheckSquare,
  FiGlobe,
  FiServer,
  FiCpu,
  FiRefreshCw,
  FiFile,
  FiLock,
} from "react-icons/fi";

const fetchReportDataApi = async (scanJobId = "latest") => {
  const res = await axios.get(`/api/reports/data/${scanJobId}`);
  return res.data;
};

export default function Reports() {
  const [scanJobId, setScanJobId] = useState("latest");
  const [reportType, setReportType] = useState("executive"); // executive | technical | compliance
  const [companyName, setCompanyName] = useState("VAP");
  const [reportTitle, setReportTitle] = useState("Vulnerability & Penetration Testing Executive Summary");
  const [authorName, setAuthorName] = useState("Lead Security Auditor");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [logoPreview, setLogoPreview] = useState(null);
  const [isUploadingLogo, setIsUploadingLogo] = useState(false);

  // Toggle Switches
  const [includeCves, setIncludeCves] = useState(true);
  const [includeRemediation, setIncludeRemediation] = useState(true);
  const [includeRawScan, setIncludeRawScan] = useState(true);
  const [includeComplianceMap, setIncludeComplianceMap] = useState(true);

  // Preview Modal
  const [isPreviewModalOpen, setIsPreviewModalOpen] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState(null);

  // Fetch Real Scan Data
  const { data: rawReportData, isLoading, isError, refetch } = useQuery({
    queryKey: ["report-data", scanJobId],
    queryFn: () => fetchReportDataApi(scanJobId),
    staleTime: 30000,
  });

  // Dropzone Logo Upload
  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;
    const file = acceptedFiles[0];
    const previewUrl = URL.createObjectURL(file);
    setLogoPreview(previewUrl);

    setIsUploadingLogo(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("company_name", companyName);
      await axios.post("/api/reports/logo", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
    } catch (err) {
      console.error("Logo upload failed", err);
    } finally {
      setIsUploadingLogo(false);
    }
  }, [companyName]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "image/*": [".png", ".jpg", ".jpeg", ".svg"] },
    maxSize: 5 * 1024 * 1024,
    multiple: false,
  });

  // Filtered Findings based on Date Range
  const filteredMisconfigs = useMemo(() => {
    if (!rawReportData?.misconfigurations) return [];
    return rawReportData.misconfigurations.filter((item) => {
      if (!item.discovered_at) return true;
      const itemDate = new Date(item.discovered_at).getTime();
      if (startDate) {
        const start = new Date(startDate).getTime();
        if (itemDate < start) return false;
      }
      if (endDate) {
        const end = new Date(endDate).getTime() + 86400000;
        if (itemDate > end) return false;
      }
      return true;
    });
  }, [rawReportData, startDate, endDate]);

  const summaryMetrics = useMemo(() => {
    const totalAssets = Math.max(1, rawReportData?.summary?.total_assets || rawReportData?.assets?.length || 1);
    const totalFindings = filteredMisconfigs.length;
    const critical = filteredMisconfigs.filter((m) => m.severity?.toUpperCase() === "CRITICAL").length;
    const high = filteredMisconfigs.filter((m) => m.severity?.toUpperCase() === "HIGH").length;
    const medium = filteredMisconfigs.filter((m) => m.severity?.toUpperCase() === "MEDIUM").length;
    const low = filteredMisconfigs.filter((m) => m.severity?.toUpperCase() === "LOW").length;

    const penalty = (critical * 25 + high * 12 + medium * 5 + low * 1) / (totalAssets * 2);
    const complianceScore = Math.min(100, Math.max(20, Math.round(100 - penalty)));

    return { totalAssets, totalFindings, critical, high, medium, low, complianceScore };
  }, [filteredMisconfigs, rawReportData]);

  // Download File Handler
  const handleDownload = async (format) => {
    setDownloadingFormat(format);
    try {
      const jobId = rawReportData?.scan_job_id || "latest";
      const payload = {
        mode: reportType,
        format,
        company_name: companyName,
        report_title: reportTitle,
        author_name: authorName,
        start_date: startDate,
        end_date: endDate,
        include_cves: includeCves,
        include_remediation: includeRemediation,
        include_raw_scan: includeRawScan,
        include_compliance_map: includeComplianceMap,
      };

      const res = await axios.post(`/api/reports/download/${jobId}`, payload, {
        responseType: "blob",
      });

      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `VAPT_${companyName.replace(/\s+/g, "_")}_${reportType.toUpperCase()}_Report.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(`Failed to download ${format} report`, err);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", padding: "8px 0" }}>
      {/* Header Studio Banner */}
      <div
        className="panel"
        style={{
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.85))",
          border: "1px solid rgba(148, 163, 184, 0.15)",
          borderRadius: "16px",
          padding: "20px 24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{ background: "rgba(56, 189, 248, 0.1)", padding: "12px", borderRadius: "12px", border: "1px solid rgba(56, 189, 248, 0.2)" }}>
            <FiFileText style={{ color: "#38bdf8", fontSize: "24px" }} />
          </div>
          <div>
            <h1 style={{ fontSize: "1.5rem", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
              Report Studio & Document Generator
            </h1>
            <p style={{ color: "#94a3b8", fontSize: "0.88rem", margin: 0 }}>
              Real-time report aggregation, compliance mapping, and custom PDF / DOCX / CSV downloads.
            </p>
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>Target Scan ID:</span>
          <select
            className="scan-select"
            value={scanJobId}
            onChange={(e) => setScanJobId(e.target.value)}
            style={{ width: "130px", height: "38px" }}
          >
            <option value="latest">Latest Scan</option>
            <option value="1">Scan #1</option>
            <option value="2">Scan #2</option>
          </select>

          <button
            onClick={() => refetch()}
            className="btn btn--secondary"
            style={{ height: "38px", padding: "0 14px", display: "flex", alignItems: "center", gap: "6px" }}
          >
            <FiRefreshCw className={isLoading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {/* Main 2-Column Grid (30% / 70%) */}
      <div style={{ display: "grid", gridTemplateColumns: "3.2fr 6.8fr", gap: "24px" }}>
        
        {/* LEFT COLUMN: Report Configuration Panel (30%) */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          {/* 1. Organization Branding Card */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: "600", color: "#f8fafc", marginBottom: "14px", display: "flex", alignItems: "center", gap: "8px" }}>
              <FiUploadCloud style={{ color: "#38bdf8" }} /> Organization Branding
            </h3>

            <div
              {...getRootProps()}
              style={{
                border: "2px dashed " + (isDragActive ? "#38bdf8" : "rgba(148, 163, 184, 0.25)"),
                borderRadius: "12px",
                padding: "20px",
                textAlign: "center",
                background: isDragActive ? "rgba(56, 189, 248, 0.05)" : "rgba(15, 23, 42, 0.5)",
                cursor: "pointer",
                transition: "all 0.2s ease",
              }}
            >
              <input {...getInputProps()} />
              {logoPreview ? (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "10px" }}>
                  <img src={logoPreview} alt="Company Logo" style={{ maxHeight: "60px", maxWidth: "100%", objectFit: "contain" }} />
                  <span style={{ fontSize: "0.78rem", color: "#10b981", display: "flex", alignItems: "center", gap: "4px" }}>
                    <FiCheck /> Logo uploaded
                  </span>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "8px", color: "#94a3b8" }}>
                  <FiUploadCloud style={{ fontSize: "28px", color: "#64748b" }} />
                  <p style={{ margin: 0, fontSize: "0.85rem", fontWeight: "500", color: "#cbd5e1" }}>
                    Drag & drop logo or click to browse
                  </p>
                  <small style={{ fontSize: "0.75rem", color: "#64748b" }}>Supports PNG, JPG, SVG (Max 5MB)</small>
                </div>
              )}
            </div>
          </div>

          {/* 2. Company Information */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: "600", color: "#f8fafc", marginBottom: "14px" }}>
              Company Information
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "0.78rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>Company Name</label>
                <input
                  className="scan-input"
                  value={companyName}
                  onChange={(e) => setCompanyName(e.target.value)}
                  placeholder="e.g. Acme Corporation"
                  style={{ width: "100%" }}
                />
              </div>

              <div>
                <label style={{ fontSize: "0.78rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>Report Title</label>
                <input
                  className="scan-input"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g. Technical Assessment Audit"
                  style={{ width: "100%" }}
                />
              </div>

              <div>
                <label style={{ fontSize: "0.78rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>Author Name</label>
                <input
                  className="scan-input"
                  value={authorName}
                  onChange={(e) => setAuthorName(e.target.value)}
                  placeholder="e.g. Security Engineering Team"
                  style={{ width: "100%" }}
                />
              </div>
            </div>
          </div>

          {/* 3. Report Type Selector (Toggle Tabs) */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: "600", color: "#f8fafc", marginBottom: "14px" }}>
              Report Format Type
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "8px" }}>
              {[
                { id: "executive", label: "Executive" },
                { id: "technical", label: "Technical" },
                { id: "compliance", label: "Compliance" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setReportType(tab.id)}
                  style={{
                    padding: "10px 8px",
                    borderRadius: "8px",
                    border: reportType === tab.id ? "1px solid #38bdf8" : "1px solid rgba(148, 163, 184, 0.15)",
                    background: reportType === tab.id ? "rgba(56, 189, 248, 0.15)" : "rgba(15, 23, 42, 0.6)",
                    color: reportType === tab.id ? "#38bdf8" : "#94a3b8",
                    fontSize: "0.85rem",
                    fontWeight: "600",
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                  }}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* 4. Date Range Filter */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: "600", color: "#f8fafc", marginBottom: "14px", display: "flex", alignItems: "center", gap: "6px" }}>
              <FiCalendar style={{ color: "#38bdf8" }} /> Date Range Filter
            </h3>
            <div style={{ display: "flex", gap: "10px" }}>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>Start Date</label>
                <input
                  type="date"
                  className="scan-input"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  style={{ width: "100%", fontSize: "0.8rem" }}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>End Date</label>
                <input
                  type="date"
                  className="scan-input"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  style={{ width: "100%", fontSize: "0.8rem" }}
                />
              </div>
            </div>
          </div>

          {/* 5. Report Settings (Toggle Switches) */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: "600", color: "#f8fafc", marginBottom: "14px", display: "flex", alignItems: "center", gap: "6px" }}>
              <FiSliders style={{ color: "#38bdf8" }} /> Report Sections
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {[
                { label: "Include CVE Mapping", state: includeCves, set: setIncludeCves },
                { label: "Include Remediation Steps", state: includeRemediation, set: setIncludeRemediation },
                { label: "Include Raw Scan Output", state: includeRawScan, set: setIncludeRawScan },
                { label: "Include Compliance Matrix", state: includeComplianceMap, set: setIncludeComplianceMap },
              ].map((opt, i) => (
                <label key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", fontSize: "0.85rem", color: "#cbd5e1" }}>
                  <span>{opt.label}</span>
                  <input
                    type="checkbox"
                    checked={opt.state}
                    onChange={(e) => opt.set(e.target.checked)}
                    style={{ width: "16px", height: "16px", accentColor: "#38bdf8" }}
                  />
                </label>
              ))}
            </div>
          </div>

          {/* 6. Download Actions Button Group */}
          <div className="panel" style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "10px" }}>
            <button
              onClick={() => setIsPreviewModalOpen(true)}
              className="btn btn--secondary"
              style={{ width: "100%", height: "42px", display: "flex", justifyContent: "center", alignItems: "center", gap: "8px" }}
            >
              <FiEye /> Full Screen Preview
            </button>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <button
                onClick={() => handleDownload("pdf")}
                disabled={downloadingFormat === "pdf"}
                className="btn btn--primary"
                style={{ height: "40px", display: "flex", justifyContent: "center", alignItems: "center", gap: "6px", fontSize: "0.82rem" }}
              >
                <FiDownload /> {downloadingFormat === "pdf" ? "Exporting..." : "Download PDF"}
              </button>

              <button
                onClick={() => handleDownload("docx")}
                disabled={downloadingFormat === "docx"}
                className="btn btn--secondary"
                style={{ height: "40px", display: "flex", justifyContent: "center", alignItems: "center", gap: "6px", fontSize: "0.82rem" }}
              >
                <FiFile /> {downloadingFormat === "docx" ? "Exporting..." : "Download DOCX"}
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <button
                onClick={() => handleDownload("csv")}
                disabled={downloadingFormat === "csv"}
                style={{
                  height: "36px",
                  background: "rgba(30, 41, 59, 0.6)",
                  border: "1px solid rgba(148, 163, 184, 0.15)",
                  color: "#cbd5e1",
                  borderRadius: "8px",
                  fontSize: "0.78rem",
                  cursor: "pointer",
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  gap: "4px",
                }}
              >
                <FiDownload /> Export CSV
              </button>

              <button
                onClick={() => handleDownload("json")}
                disabled={downloadingFormat === "json"}
                style={{
                  height: "36px",
                  background: "rgba(30, 41, 59, 0.6)",
                  border: "1px solid rgba(148, 163, 184, 0.15)",
                  color: "#cbd5e1",
                  borderRadius: "8px",
                  fontSize: "0.78rem",
                  cursor: "pointer",
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  gap: "4px",
                }}
              >
                <FiDownload /> Export JSON
              </button>
            </div>
          </div>

        </div>

        {/* RIGHT COLUMN: Live Report Preview Paper Container (70%) */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.88rem", fontWeight: "600", color: "#94a3b8" }}>
              LIVE DOCUMENT PREVIEW ({reportType.toUpperCase()} MODE)
            </span>
            <span style={{ fontSize: "0.78rem", color: "#64748b" }}>Paper View 8.5" x 11"</span>
          </div>

          {/* Paper Style Scrollable Box */}
          <div
            style={{
              maxHeight: "85vh",
              overflowY: "auto",
              background: "#ffffff",
              color: "#1e293b",
              borderRadius: "12px",
              padding: "40px 48px",
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4)",
              fontFamily: "'Times New Roman', 'Georgia', serif",
            }}
          >
            {/* Document Header */}
            <div style={{ borderBottom: "2px solid #e2e8f0", paddingBottom: "24px", marginBottom: "28px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <h1 style={{ fontFamily: "'Inter', sans-serif", fontSize: "1.8rem", fontWeight: "800", color: "#0f172a", margin: "0 0 6px 0" }}>
                  {companyName}
                </h1>
                <h2 style={{ fontFamily: "'Inter', sans-serif", fontSize: "1.2rem", fontWeight: "600", color: "#2563eb", margin: "0 0 12px 0" }}>
                  {reportTitle}
                </h2>
                <div style={{ fontSize: "0.85rem", color: "#64748b", display: "flex", gap: "16px" }}>
                  <span><strong>Author:</strong> {authorName}</span>
                  <span><strong>Generated:</strong> {new Date().toLocaleDateString()}</span>
                </div>
              </div>

              {logoPreview ? (
                <img src={logoPreview} alt="Logo" style={{ maxHeight: "50px", maxWidth: "160px", objectFit: "contain" }} />
              ) : (
                <div style={{ padding: "8px 14px", border: "1px dashed #cbd5e1", borderRadius: "6px", fontSize: "0.75rem", color: "#94a3b8" }}>
                  {companyName} Logo
                </div>
              )}
            </div>

            {/* SECTION 1: EXECUTIVE SUMMARY */}
            <div style={{ marginBottom: "32px" }}>
              <h3 style={{ fontFamily: "'Inter', sans-serif", fontSize: "1.1rem", fontWeight: "700", color: "#0f172a", borderBottom: "1px solid #cbd5e1", paddingBottom: "6px", marginBottom: "16px" }}>
                1. Executive Summary & Risk Overview
              </h3>

              {/* 4 Metric Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "16px", marginBottom: "24px" }}>
                <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", textAlign: "center" }}>
                  <span style={{ fontSize: "0.78rem", color: "#64748b", fontFamily: "'Inter', sans-serif" }}>TOTAL ASSETS</span>
                  <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#0f172a", marginTop: "4px" }}>{summaryMetrics.totalAssets}</div>
                </div>

                <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", textAlign: "center" }}>
                  <span style={{ fontSize: "0.78rem", color: "#64748b", fontFamily: "'Inter', sans-serif" }}>TOTAL FINDINGS</span>
                  <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#0f172a", marginTop: "4px" }}>{summaryMetrics.totalFindings}</div>
                </div>

                <div style={{ background: "#fef2f2", padding: "14px", borderRadius: "8px", border: "1px solid #fecaca", textAlign: "center" }}>
                  <span style={{ fontSize: "0.78rem", color: "#dc2626", fontFamily: "'Inter', sans-serif" }}>CRITICAL</span>
                  <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#991b1b", marginTop: "4px" }}>{summaryMetrics.critical}</div>
                </div>

                <div style={{ background: "#fffbebe", padding: "14px", borderRadius: "8px", border: "1px solid #fde68a", textAlign: "center" }}>
                  <span style={{ fontSize: "0.78rem", color: "#d97706", fontFamily: "'Inter', sans-serif" }}>HIGH SEVERITY</span>
                  <div style={{ fontSize: "1.6rem", fontWeight: "800", color: "#92400e", marginTop: "4px" }}>{summaryMetrics.high}</div>
                </div>
              </div>

              {/* Compliance Gauge */}
              <div style={{ display: "flex", alignItems: "center", gap: "24px", background: "#f8fafc", padding: "20px", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
                <svg width="80" height="80" viewBox="0 0 36 36">
                  <path
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="#e2e8f0"
                    strokeWidth="3.8"
                  />
                  <path
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke={summaryMetrics.complianceScore > 75 ? "#16a34a" : summaryMetrics.complianceScore > 50 ? "#d97706" : "#dc2626"}
                    strokeWidth="3.8"
                    strokeDasharray={`${summaryMetrics.complianceScore}, 100`}
                  />
                  <text x="18" y="20.35" fill="#0f172a" fontSize="9" textAnchor="middle" fontWeight="bold" fontFamily="'Inter', sans-serif">
                    {summaryMetrics.complianceScore}%
                  </text>
                </svg>
                <div>
                  <h4 style={{ fontFamily: "'Inter', sans-serif", margin: "0 0 4px 0", color: "#0f172a", fontSize: "1rem" }}>
                    Security Posture Score
                  </h4>
                  <p style={{ margin: 0, fontSize: "0.88rem", color: "#475569", lineHeight: "1.4" }}>
                    Evaluated across active infrastructure, web applications, and network endpoints.
                  </p>
                </div>
              </div>
            </div>

            {/* SECTION 2: TECHNICAL FINDINGS (Visible in Technical mode or if enabled) */}
            {(reportType === "technical" || reportType === "executive") && (
              <div style={{ marginBottom: "32px" }}>
                <h3 style={{ fontFamily: "'Inter', sans-serif", fontSize: "1.1rem", fontWeight: "700", color: "#0f172a", borderBottom: "1px solid #cbd5e1", paddingBottom: "6px", marginBottom: "16px" }}>
                  2. Detailed Technical Findings ({filteredMisconfigs.length})
                </h3>

                {filteredMisconfigs.length > 0 ? (
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                    <thead>
                      <tr style={{ background: "#f1f5f9", borderBottom: "2px solid #cbd5e1", textAlign: "left", fontFamily: "'Inter', sans-serif" }}>
                        <th style={{ padding: "8px 10px" }}>Target</th>
                        <th style={{ padding: "8px 10px" }}>Issue Description</th>
                        <th style={{ padding: "8px 10px" }}>Type</th>
                        {includeCves && <th style={{ padding: "8px 10px" }}>CVE</th>}
                        <th style={{ padding: "8px 10px" }}>Severity</th>
                        {includeRemediation && <th style={{ padding: "8px 10px" }}>Remediation</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredMisconfigs.map((m, idx) => (
                        <tr key={m.id || idx} style={{ borderBottom: "1px solid #e2e8f0" }}>
                          <td style={{ padding: "10px", fontWeight: "bold" }}>{m.hostname || m.ip}</td>
                          <td style={{ padding: "10px" }}>{m.issue}</td>
                          <td style={{ padding: "10px" }}>{m.asset_type}</td>
                          {includeCves && <td style={{ padding: "10px", color: "#dc2626" }}>{m.cve || "n/a"}</td>}
                          <td style={{ padding: "10px" }}>
                            <span
                              style={{
                                padding: "2px 8px",
                                borderRadius: "4px",
                                fontSize: "0.75rem",
                                fontWeight: "bold",
                                fontFamily: "'Inter', sans-serif",
                                background: m.severity?.toUpperCase() === "CRITICAL" ? "#fee2e2" : m.severity?.toUpperCase() === "HIGH" ? "#fef3c7" : "#e0f2fe",
                                color: m.severity?.toUpperCase() === "CRITICAL" ? "#991b1b" : m.severity?.toUpperCase() === "HIGH" ? "#92400e" : "#0369a1",
                              }}
                            >
                              {m.severity}
                            </span>
                          </td>
                          {includeRemediation && (
                            <td style={{ padding: "10px", fontSize: "0.8rem", color: "#334155" }}>
                              {m.remediation}
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ textAlign: "center", color: "#94a3b8", padding: "30px 0", fontStyle: "italic" }}>
                    No findings discovered for this report.
                  </p>
                )}
              </div>
            )}

            {/* SECTION 3: COMPLIANCE MATRIX (Compliance mode or if enabled) */}
            {(reportType === "compliance" || includeComplianceMap) && (
              <div>
                <h3 style={{ fontFamily: "'Inter', sans-serif", fontSize: "1.1rem", fontWeight: "700", color: "#0f172a", borderBottom: "1px solid #cbd5e1", paddingBottom: "6px", marginBottom: "16px" }}>
                  3. Regulatory Compliance Control Matrix
                </h3>

                {filteredMisconfigs.length > 0 ? (
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem", textAlign: "center" }}>
                    <thead>
                      <tr style={{ background: "#f1f5f9", borderBottom: "2px solid #cbd5e1", fontFamily: "'Inter', sans-serif" }}>
                        <th style={{ padding: "8px", textAlign: "left" }}>Finding Issue</th>
                        <th style={{ padding: "8px" }}>CIS</th>
                        <th style={{ padding: "8px" }}>NIST</th>
                        <th style={{ padding: "8px" }}>GDPR</th>
                        <th style={{ padding: "8px" }}>HIPAA</th>
                        <th style={{ padding: "8px" }}>SOC 2</th>
                        <th style={{ padding: "8px" }}>ISO 27001</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredMisconfigs.map((m, idx) => (
                        <tr key={m.id || idx} style={{ borderBottom: "1px solid #e2e8f0" }}>
                          <td style={{ padding: "8px", textAlign: "left", fontWeight: "600" }}>{m.issue}</td>
                          <td style={{ padding: "8px", color: "#dc2626", fontWeight: "bold" }}>X</td>
                          <td style={{ padding: "8px", color: m.severity === "CRITICAL" ? "#dc2626" : "#cbd5e1" }}>{m.severity === "CRITICAL" ? "X" : "-"}</td>
                          <td style={{ padding: "8px", color: m.issue?.includes("Password") || m.issue?.includes("Exposed") ? "#dc2626" : "#cbd5e1" }}>{m.issue?.includes("Password") || m.issue?.includes("Exposed") ? "X" : "-"}</td>
                          <td style={{ padding: "8px", color: m.severity === "CRITICAL" ? "#dc2626" : "#cbd5e1" }}>{m.severity === "CRITICAL" ? "X" : "-"}</td>
                          <td style={{ padding: "8px", color: m.issue?.includes("CORS") ? "#dc2626" : "#cbd5e1" }}>{m.issue?.includes("CORS") ? "X" : "-"}</td>
                          <td style={{ padding: "8px", color: "#dc2626", fontWeight: "bold" }}>X</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ textAlign: "center", color: "#94a3b8", padding: "30px 0", fontStyle: "italic" }}>
                    No compliance violations identified in the current scope.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Full Screen Preview Modal */}
      <AnimatePresence>
        {isPreviewModalOpen && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: "rgba(0, 0, 0, 0.85)",
              backdropFilter: "blur(6px)",
              zIndex: 99999,
              display: "flex",
              flexDirection: "column",
              padding: "24px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ color: "#fff", fontSize: "1.3rem", margin: 0, display: "flex", alignItems: "center", gap: "10px" }}>
                <FiEye style={{ color: "#38bdf8" }} /> Full Screen Report Preview ({reportType.toUpperCase()})
              </h2>
              <button
                onClick={() => setIsPreviewModalOpen(false)}
                style={{ background: "none", border: "none", color: "#cbd5e1", fontSize: "24px", cursor: "pointer" }}
              >
                <FiX />
              </button>
            </div>

            <div style={{ flex: 1, overflowY: "auto", display: "flex", justifyContent: "center" }}>
              <div
                style={{
                  width: "900px",
                  background: "#fff",
                  color: "#1e293b",
                  padding: "48px",
                  borderRadius: "12px",
                  fontFamily: "'Times New Roman', serif",
                }}
              >
                <h1 style={{ fontFamily: "'Inter', sans-serif", color: "#0f172a", fontSize: "2rem" }}>{companyName}</h1>
                <h2 style={{ fontFamily: "'Inter', sans-serif", color: "#2563eb", fontSize: "1.3rem" }}>{reportTitle}</h2>
                <hr style={{ margin: "20px 0" }} />
                <p><strong>Generated for:</strong> {companyName}</p>
                <p><strong>Date:</strong> {new Date().toLocaleDateString()}</p>
                <p><strong>Total Audited Assets:</strong> {summaryMetrics.totalAssets}</p>
                <p><strong>Discovered Misconfigurations:</strong> {summaryMetrics.totalFindings}</p>
              </div>
            </div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

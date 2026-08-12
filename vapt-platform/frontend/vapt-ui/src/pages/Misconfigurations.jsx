import React, { useState, useMemo } from "react";
import { useForm } from "react-hook-form";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiShield,
  FiSearch,
  FiAlertTriangle,
  FiPlay,
  FiCheckCircle,
  FiClock,
  FiFilter,
  FiChevronRight,
  FiX,
  FiServer,
  FiGlobe,
  FiTerminal,
  FiCpu,
  FiInfo,
  FiRefreshCw,
} from "react-icons/fi";

const fetchMisconfigs = async () => {
  const res = await axios.get("/api/misconfig/list");
  return res.data;
};

const triggerScanApi = async ({ scope, organization_name }) => {
  const res = await axios.post("/api/misconfig/scan", {
    scope,
    organization_name: organization_name || "Acme Security Org",
  });
  return res.data;
};

export default function Misconfigurations({ findings = [], assets = [] }) {
  const [scopeInput, setScopeInput] = useState("");
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [assetTypeFilter, setAssetTypeFilter] = useState("all");
  const [scannerFilter, setScannerFilter] = useState("all");

  const queryClient = useQueryClient();

  const { register, handleSubmit, reset } = useForm({
    defaultValues: { scope: "", organization_name: "Acme Security Org" },
  });

  const { data: apiList = [], isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["misconfig-list"],
    queryFn: fetchMisconfigs,
    staleTime: 15000,
  });

  const scanMutation = useMutation({
    mutationFn: triggerScanApi,
    onSuccess: (data) => {
      reset();
      queryClient.invalidateQueries(["misconfig-list"]);
    },
  });

  const onSubmit = (formData) => {
    if (formData.scope?.trim()) {
      scanMutation.mutate({
        scope: formData.scope.trim(),
        organization_name: formData.organization_name,
      });
    }
  };

  // Combine real API misconfigurations with findings prop (if any) without mock data
  const combinedMisconfigs = useMemo(() => {
    const list = [...apiList];

    // Also include findings from prop if category is network/web or has hardening recommendations
    findings.forEach((f) => {
      const metadata = f.finding_metadata || {};
      const cat = String(f.category || "").toLowerCase();
      if (metadata.cis_benchmark || metadata.hardening_recommendation || cat === "network" || cat === "web") {
        const target = metadata.url || metadata.host || f.source || "Target";
        list.push({
          id: f.id,
          target: target,
          ip: metadata.host || target,
          hostname: target,
          asset_type: cat === "web" ? "Website" : "OS",
          os_type: metadata.os_family || "Linux",
          issue: f.title,
          severity: (f.severity || "medium").toLowerCase(),
          cve: f.cve_id,
          detected_by: f.source || "Scanner",
          remediation: metadata.hardening_recommendation || f.remediation || "Apply vendor hardening guidance.",
          status: f.status || "OPEN",
          discovered_at: f.detected_at || f.last_seen || new Date().toISOString(),
        });
      }
    });

    return list;
  }, [apiList, findings]);

  const filteredItems = useMemo(() => {
    return combinedMisconfigs.filter((item) => {
      const matchesSearch =
        !searchFilter ||
        item.issue?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.target?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.cve?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.detected_by?.toLowerCase().includes(searchFilter.toLowerCase());

      const matchesSeverity =
        severityFilter === "all" || item.severity?.toLowerCase() === severityFilter.toLowerCase();

      const matchesAssetType =
        assetTypeFilter === "all" || item.asset_type?.toLowerCase() === assetTypeFilter.toLowerCase();

      const matchesScanner =
        scannerFilter === "all" || item.detected_by?.toLowerCase() === scannerFilter.toLowerCase();

      return matchesSearch && matchesSeverity && matchesAssetType && matchesScanner;
    });
  }, [combinedMisconfigs, searchFilter, severityFilter, assetTypeFilter, scannerFilter]);

  const summary = useMemo(() => {
    const total = combinedMisconfigs.length;
    const critical = combinedMisconfigs.filter((i) => i.severity?.toLowerCase() === "critical").length;
    const high = combinedMisconfigs.filter((i) => i.severity?.toLowerCase() === "high").length;
    const medium = combinedMisconfigs.filter((i) => i.severity?.toLowerCase() === "medium").length;
    const low = combinedMisconfigs.filter((i) => i.severity?.toLowerCase() === "low").length;
    return { total, critical, high, medium, low };
  }, [combinedMisconfigs]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", padding: "8px 0" }}>
      {/* Header & Launch Scope Scanner Panel */}
      <div
        className="panel"
        style={{
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.85))",
          border: "1px solid rgba(148, 163, 184, 0.15)",
          borderRadius: "16px",
          padding: "24px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
              <FiShield style={{ color: "#38bdf8", fontSize: "24px" }} />
              <h1 style={{ fontSize: "1.6rem", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
                Production Misconfiguration Engine
              </h1>
            </div>
            <p style={{ color: "#94a3b8", fontSize: "0.9rem", margin: 0 }}>
              Live scope discovery & scanner integration across Lynis, Nmap, SecurityHeaders, SSL Labs, Nuclei, and ZAP.
            </p>
          </div>

          {/* Trigger Scan Form */}
          <form onSubmit={handleSubmit(onSubmit)} style={{ display: "flex", gap: "10px", alignItems: "center", minWidth: "360px" }}>
            <div style={{ position: "relative", flex: 1 }}>
              <FiSearch style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
              <input
                {...register("scope")}
                className="scan-input"
                placeholder="Enter IP, Domain, CIDR (192.168.1.0/24), Range, ASN, URL..."
                style={{
                  width: "100%",
                  paddingLeft: "38px",
                  paddingRight: "14px",
                  height: "42px",
                  borderRadius: "10px",
                  border: "1px solid rgba(148, 163, 184, 0.2)",
                  background: "rgba(15, 23, 42, 0.8)",
                  color: "#fff",
                }}
              />
            </div>
            <button
              type="submit"
              disabled={scanMutation.isPending}
              className="btn btn--primary"
              style={{
                height: "42px",
                padding: "0 20px",
                borderRadius: "10px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                whiteSpace: "nowrap",
              }}
            >
              <FiPlay className={scanMutation.isPending ? "spin" : ""} />
              {scanMutation.isPending ? "Launching..." : "Scan Scope"}
            </button>
          </form>
        </div>

        {/* Quick Presets */}
        <div style={{ display: "flex", gap: "10px", marginTop: "16px", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "0.8rem", color: "#64748b" }}>Quick scopes:</span>
          {["192.168.1.0/24", "acmecorp.com", "https://acmecorp.com/api/v1", "AS15169", "192.168.1.1-192.168.1.50"].map((preset) => (
            <button
              key={preset}
              onClick={() => {
                onSubmit({ scope: preset, organization_name: "Acme Security Org" });
              }}
              style={{
                background: "rgba(30, 41, 59, 0.6)",
                border: "1px solid rgba(148, 163, 184, 0.15)",
                color: "#94a3b8",
                padding: "4px 10px",
                borderRadius: "6px",
                fontSize: "0.78rem",
                cursor: "pointer",
              }}
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      {/* Metric Cards */}
      <div className="metrics-grid">
        <article className="metric-card" style={{ borderLeft: "4px solid #38bdf8" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>Total Misconfigurations</span>
            <FiShield style={{ color: "#38bdf8" }} />
          </div>
          <strong>{summary.total}</strong>
          <small>Audited across active scanners</small>
        </article>

        <article className="metric-card" style={{ borderLeft: "4px solid #ef4444" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>Critical Issues</span>
            <FiAlertTriangle style={{ color: "#ef4444" }} />
          </div>
          <strong>{summary.critical}</strong>
          <small>Require immediate patch</small>
        </article>

        <article className="metric-card" style={{ borderLeft: "4px solid #f59e0b" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>High Severity</span>
            <FiAlertTriangle style={{ color: "#f59e0b" }} />
          </div>
          <strong>{summary.high}</strong>
          <small>Privilege escalation / exposure</small>
        </article>

        <article className="metric-card" style={{ borderLeft: "4px solid #06b6d4" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>Medium Severity</span>
            <FiInfo style={{ color: "#06b6d4" }} />
          </div>
          <strong>{summary.medium}</strong>
          <small>Missing hardening policy</small>
        </article>

        <article className="metric-card" style={{ borderLeft: "4px solid #10b981" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>Low Severity</span>
            <FiCheckCircle style={{ color: "#10b981" }} />
          </div>
          <strong>{summary.low}</strong>
          <small>Informational hardening</small>
        </article>
      </div>

      {/* Main Table Panel */}
      <div className="panel">
        <div className="panel__header" style={{ flexWrap: "wrap", gap: "14px" }}>
          <div>
            <p className="eyebrow">Audited Inventory</p>
            <h2>Verified Misconfigurations ({filteredItems.length})</h2>
          </div>

          {/* Filter Controls */}
          <div className="table-controls">
            <div style={{ position: "relative" }}>
              <FiFilter style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
              <input
                className="scan-input"
                placeholder="Filter by issue, target, CVE..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{ paddingLeft: "34px", width: "200px" }}
              />
            </div>

            <select className="scan-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} style={{ width: "130px" }}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select className="scan-select" value={assetTypeFilter} onChange={(e) => setAssetTypeFilter(e.target.value)} style={{ width: "130px" }}>
              <option value="all">All Asset Types</option>
              <option value="os">OS</option>
              <option value="network">Network</option>
              <option value="website">Website</option>
              <option value="endpoint">Endpoint</option>
            </select>

            <select className="scan-select" value={scannerFilter} onChange={(e) => setScannerFilter(e.target.value)} style={{ width: "140px" }}>
              <option value="all">All Scanners</option>
              <option value="lynis">Lynis</option>
              <option value="nmap">Nmap</option>
              <option value="securityheaders">SecurityHeaders</option>
              <option value="ssllabs">SSL Labs</option>
              <option value="nuclei">Nuclei</option>
              <option value="zap">ZAP</option>
            </select>
          </div>
        </div>

        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Target</th>
                <th>Misconfiguration Issue</th>
                <th>Asset Type</th>
                <th>OS / Device</th>
                <th>Detected By</th>
                <th>Severity</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((item, idx) => {
                const sev = item.severity?.toLowerCase();
                const isCrit = sev === "critical";
                const isHigh = sev === "high";

                return (
                  <tr
                    key={item.id || idx}
                    onClick={() => setSelectedIssue(item)}
                    style={{ cursor: "pointer", background: selectedIssue?.id === item.id ? "rgba(56, 189, 248, 0.08)" : "transparent" }}
                  >
                    <td data-label="Target">
                      <strong>{item.target}</strong>
                      {item.ip && <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>{item.ip}</p>}
                    </td>
                    <td data-label="Misconfiguration Issue">
                      <strong style={{ color: "#f8fafc" }}>{item.issue}</strong>
                      {item.cve && <p style={{ margin: 0, fontSize: "0.78rem", color: "#ef4444" }}>{item.cve}</p>}
                    </td>
                    <td data-label="Asset Type">
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                        {item.asset_type === "Website" ? <FiGlobe style={{ color: "#38bdf8" }} /> : item.asset_type === "Endpoint" ? <FiCpu style={{ color: "#a855f7" }} /> : <FiServer style={{ color: "#10b981" }} />}
                        {item.asset_type}
                      </span>
                    </td>
                    <td data-label="OS / Device">{item.os_type || "Linux"}</td>
                    <td data-label="Detected By">
                      <span style={{ padding: "2px 8px", borderRadius: "4px", background: "rgba(148, 163, 184, 0.12)", color: "#cbd5e1", fontSize: "0.78rem" }}>
                        {item.detected_by}
                      </span>
                    </td>
                    <td data-label="Severity">
                      <span className={`pill pill--${isCrit ? "critical" : isHigh ? "high" : sev === "medium" ? "medium" : "low"}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td data-label="Actions">
                      <button className="btn btn--secondary" style={{ padding: "4px 10px", fontSize: "0.78rem", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                        Remediation <FiChevronRight />
                      </button>
                    </td>
                  </tr>
                );
              })}

              {filteredItems.length === 0 && (
                <tr>
                  <td colSpan="7" style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                    <FiShield style={{ fontSize: "32px", color: "#38bdf8", marginBottom: "8px" }} />
                    <p style={{ margin: 0, fontWeight: "500" }}>No misconfigurations detected</p>
                    <small>All active systems are verified against CIS benchmarks and scanner rules.</small>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Issue Drawer / Modal */}
      <AnimatePresence>
        {selectedIssue && (
          <div
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: "rgba(0, 0, 0, 0.7)",
              backdropFilter: "blur(4px)",
              zIndex: 9999,
              display: "flex",
              justifyContent: "flex-end",
            }}
            onClick={() => setSelectedIssue(null)}
          >
            <motion.div
              initial={{ x: 450 }}
              animate={{ x: 0 }}
              exit={{ x: 450 }}
              transition={{ type: "spring", damping: 25 }}
              onClick={(e) => e.stopPropagation()}
              style={{
                width: "500px",
                maxWidth: "92vw",
                height: "100%",
                background: "#0f172a",
                borderLeft: "1px solid rgba(148, 163, 184, 0.2)",
                padding: "24px",
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "20px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <FiAlertTriangle style={{ color: "#ef4444", fontSize: "22px" }} />
                  <h3 style={{ margin: 0, color: "#f8fafc", fontSize: "1.1rem" }}>{selectedIssue.issue}</h3>
                </div>
                <button onClick={() => setSelectedIssue(null)} style={{ background: "none", border: "none", color: "#94a3b8", fontSize: "20px", cursor: "pointer" }}>
                  <FiX />
                </button>
              </div>

              <div style={{ background: "rgba(30, 41, 59, 0.6)", padding: "16px", borderRadius: "10px", border: "1px solid rgba(148, 163, 184, 0.1)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Target</span>
                  <strong style={{ color: "#38bdf8", fontSize: "0.85rem" }}>{selectedIssue.target}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Asset Type / OS</span>
                  <strong style={{ color: "#f1f5f9", fontSize: "0.85rem" }}>{selectedIssue.asset_type} ({selectedIssue.os_type || "Linux"})</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Detected By</span>
                  <span style={{ color: "#cbd5e1", fontSize: "0.85rem" }}>{selectedIssue.detected_by}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Severity</span>
                  <span className={`pill pill--${selectedIssue.severity?.toLowerCase()}`}>{selectedIssue.severity}</span>
                </div>
              </div>

              {/* Remediation */}
              <div>
                <h4 style={{ color: "#f8fafc", fontSize: "0.95rem", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <FiShield style={{ color: "#10b981" }} /> Remediation Guidance & CIS Benchmark
                </h4>
                <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", padding: "14px", borderRadius: "8px", color: "#a7f3d0", fontSize: "0.88rem", lineHeight: "1.5" }}>
                  {selectedIssue.remediation || "Apply vendor security hardening patch."}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

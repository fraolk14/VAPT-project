import React, { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FiServer,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiFilter,
  FiRefreshCw,
  FiSearch,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiXCircle,
  FiGlobe,
  FiCpu,
  FiHardDrive,
  FiX,
  FiLayers,
  FiUser,
  FiActivity,
  FiExternalLink,
  FiZap,
} from "react-icons/fi";
import api from "../api/client";

const emptyAssetForm = {
  hostname: "",
  ip_address: "",
  url: "",
  os_type: "Ubuntu 22.04",
  owner: "",
  environment: "Production",
  criticality: "Medium",
  risk_level: "Medium",
  classification: "Internal",
  asset_type: "OS",
  is_active: true,
};

export default function Assets({ assets: propAssets = [], onAssetCreated }) {
  const [assets, setAssets] = useState(propAssets);
  const [loading, setLoading] = useState(!propAssets || propAssets.length === 0);
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (propAssets && propAssets.length > 0) {
      setAssets(propAssets);
      setLoading(false);
    }
  }, [propAssets]);

  // Filters
  const [classificationFilter, setClassificationFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [envFilter, setEnvFilter] = useState("all");
  const [criticalityFilter, setCriticalityFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [managedFilter, setManagedFilter] = useState("all");

  // Modals & Drawers
  const [modalState, setModalState] = useState(null); // null | "create" | "edit"
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [detailDrawerAsset, setDetailDrawerAsset] = useState(null);
  const [assetMisconfigs, setAssetMisconfigs] = useState([]);
  const [loadingMisconfigs, setLoadingMisconfigs] = useState(false);

  const [form, setForm] = useState(emptyAssetForm);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState({ message: "", tone: "" });

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const response = await api.get("/assets/");
      setAssets(response.data || []);
    } catch (err) {
      console.error("Failed to load assets:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!propAssets || propAssets.length === 0) {
      fetchAssets();
    }
  }, []);

  const fetchAssetMisconfigurations = async (asset) => {
    setDetailDrawerAsset(asset);
    setLoadingMisconfigs(true);
    try {
      const res = await api.get(`/assets/${asset.id}/misconfigurations`);
      setAssetMisconfigs(res.data || []);
    } catch (err) {
      console.error("Error fetching asset misconfigurations:", err);
      setAssetMisconfigs(asset.misconfigurations || []);
    } finally {
      setLoadingMisconfigs(false);
    }
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setFeedback({ message: "", tone: "" });
    try {
      const res = await api.post("/assets/", form);
      setAssets((prev) => [res.data, ...prev]);
      onAssetCreated?.(res.data);
      setModalState(null);
      setForm(emptyAssetForm);
      setFeedback({
        message: `Asset "${res.data.hostname || res.data.ip_address}" created. Automatic background discovery scan launched!`,
        tone: "success",
      });
    } catch (err) {
      setFeedback({
        message: err?.response?.data?.detail || "Failed to create asset.",
        tone: "error",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (!selectedAsset) return;
    setSubmitting(true);
    try {
      const res = await api.put(`/assets/${selectedAsset.id}`, form);
      setAssets((prev) => prev.map((a) => (a.id === selectedAsset.id ? res.data : a)));
      setModalState(null);
      setFeedback({ message: "Asset updated successfully.", tone: "success" });
    } catch (err) {
      setFeedback({ message: err?.response?.data?.detail || "Failed to update asset.", tone: "error" });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (asset) => {
    if (!window.confirm(`Delete asset "${asset.hostname || asset.ip_address}"?`)) return;
    try {
      await api.delete(`/assets/${asset.id}`);
      setAssets((prev) => prev.filter((a) => a.id !== asset.id));
      if (detailDrawerAsset?.id === asset.id) setDetailDrawerAsset(null);
      setFeedback({ message: "Asset deleted.", tone: "success" });
    } catch (err) {
      setFeedback({ message: err?.response?.data?.detail || "Failed to delete asset.", tone: "error" });
    }
  };

  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      const isManaged = (a.tags || []).some((t) => t.includes("managed") || t.includes("agent")) || (a.asset_type || "").toLowerCase().includes("endpoint");
      const matchesManaged = managedFilter === "all" || (managedFilter === "managed" ? isManaged : !isManaged);

      const matchesClassification =
        classificationFilter === "all" ||
        (a.classification || "").toLowerCase() === classificationFilter.toLowerCase() ||
        (a.exposure || "").toLowerCase() === classificationFilter.toLowerCase();

      const matchesType = typeFilter === "all" || (a.asset_type || "").toLowerCase() === typeFilter.toLowerCase();
      const matchesEnv = envFilter === "all" || (a.environment || "").toLowerCase() === envFilter.toLowerCase();
      const matchesCriticality = criticalityFilter === "all" || (a.criticality || "").toLowerCase() === criticalityFilter.toLowerCase();
      const matchesRisk = riskFilter === "all" || (a.risk_level || "").toLowerCase() === riskFilter.toLowerCase();

      const searchBlob = `${a.hostname || ""} ${a.ip_address || ""} ${a.url || ""} ${a.owner || ""} ${a.os_type || ""} ${a.os || ""}`.toLowerCase();
      const matchesSearch = !search || searchBlob.includes(search.toLowerCase());

      return matchesManaged && matchesClassification && matchesType && matchesEnv && matchesCriticality && matchesRisk && matchesSearch;
    });
  }, [assets, managedFilter, classificationFilter, typeFilter, envFilter, criticalityFilter, riskFilter, search]);

  const summary = useMemo(() => {
    const total = assets.length;
    const managedCount = assets.filter((a) => (a.tags || []).some((t) => t.includes("managed") || t.includes("agent")) || (a.asset_type || "").toLowerCase().includes("endpoint")).length;
    const internal = assets.filter((a) => (a.classification || a.exposure || "").toLowerCase().includes("internal")).length;
    const external = total - internal;
    const criticalCount = assets.filter((a) => (a.criticality || "").toLowerCase() === "critical").length;
    return { total, managedCount, internal, external, criticalCount };
  }, [assets]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", padding: "8px 0" }}>
      {/* Top Banner Header */}
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
            <FiServer style={{ color: "#38bdf8", fontSize: "24px" }} />
          </div>
          <div>
            <h1 style={{ fontSize: "1.5rem", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
              Asset Inventory & Scope Engine
            </h1>
            <p style={{ color: "#94a3b8", fontSize: "0.88rem", margin: 0 }}>
              Real-time database asset telemetry, classification, misconfiguration correlation, and immediate discovery scanning.
            </p>
          </div>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <a
            href="/agent-management"
            className="btn btn--secondary"
            style={{ height: "38px", padding: "0 14px", display: "flex", alignItems: "center", gap: "6px", borderColor: "#4fd1c5", color: "#4fd1c5", textDecoration: "none" }}
          >
            📡 Deploy Agent (.exe)
          </a>

          <button
            onClick={() => {
              setForm(emptyAssetForm);
              setModalState("create");
            }}
            className="btn btn--primary"
            style={{ height: "38px", padding: "0 16px", display: "flex", alignItems: "center", gap: "6px" }}
          >
            <FiPlus /> Add Asset
          </button>

          <button
            onClick={fetchAssets}
            className="btn btn--secondary"
            style={{ height: "38px", padding: "0 14px", display: "flex", alignItems: "center", gap: "6px" }}
          >
            <FiRefreshCw className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {feedback.message && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: "8px",
            background: feedback.tone === "success" ? "rgba(16, 185, 129, 0.12)" : "rgba(239, 68, 68, 0.12)",
            border: feedback.tone === "success" ? "1px solid rgba(16, 185, 129, 0.3)" : "1px solid rgba(239, 68, 68, 0.3)",
            color: feedback.tone === "success" ? "#34d399" : "#f87171",
            fontSize: "0.88rem",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{feedback.message}</span>
          <button onClick={() => setFeedback({ message: "", tone: "" })} style={{ background: "none", border: "none", color: "inherit", cursor: "pointer" }}>
            <FiX />
          </button>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "16px" }}>
        <div
          className="panel"
          onClick={() => setManagedFilter("all")}
          style={{
            padding: "16px 20px",
            cursor: "pointer",
            border: managedFilter === "all" ? "1px solid #38bdf8" : "1px solid rgba(148, 163, 184, 0.15)",
            transition: "all 0.2s ease",
          }}
          title="Click to view all assets"
        >
          <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Total Discovered Assets</span>
          <strong style={{ display: "block", fontSize: "1.6rem", color: "#38bdf8", marginTop: "4px" }}>{summary.total}</strong>
        </div>
        <div
          className="panel"
          onClick={() => setManagedFilter("managed")}
          style={{
            padding: "16px 20px",
            cursor: "pointer",
            border: managedFilter === "managed" ? "2px solid #4fd1c5" : "1px solid rgba(79, 209, 197, 0.4)",
            background: managedFilter === "managed" ? "rgba(79, 209, 197, 0.15)" : "rgba(79, 209, 197, 0.05)",
            boxShadow: managedFilter === "managed" ? "0 0 12px rgba(79, 209, 197, 0.3)" : "none",
            transition: "all 0.2s ease",
          }}
          title="Click to filter table for Managed Agent Devices only"
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ color: "#4fd1c5", fontSize: "0.78rem", fontWeight: "600" }}>Managed Devices (VAP Agent)</span>
            <span style={{ fontSize: "0.7rem", background: "#4fd1c5", color: "#0f172a", padding: "2px 6px", borderRadius: "10px", fontWeight: "bold" }}>FILTER</span>
          </div>
          <strong style={{ display: "block", fontSize: "1.6rem", color: "#4fd1c5", marginTop: "4px" }}>{summary.managedCount}</strong>
        </div>
        <div className="panel" style={{ padding: "16px 20px" }}>
          <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Internal Footprint</span>
          <strong style={{ display: "block", fontSize: "1.6rem", color: "#34d399", marginTop: "4px" }}>{summary.internal}</strong>
        </div>
        <div className="panel" style={{ padding: "16px 20px" }}>
          <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>External Surface</span>
          <strong style={{ display: "block", fontSize: "1.6rem", color: "#f59e0b", marginTop: "4px" }}>{summary.external}</strong>
        </div>
        <div className="panel" style={{ padding: "16px 20px" }}>
          <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Critical Tier Assets</span>
          <strong style={{ display: "block", fontSize: "1.6rem", color: "#f87171", marginTop: "4px" }}>{summary.criticalCount}</strong>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="panel" style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: "14px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: 1, minWidth: "220px" }}>
            <FiSearch style={{ position: "absolute", left: "12px", top: "11px", color: "#64748b" }} />
            <input
              className="scan-input"
              placeholder="Search by IP, Hostname, URL, Owner, OS..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: "36px", width: "100%", height: "38px" }}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            <select className="scan-select" value={managedFilter} onChange={(e) => setManagedFilter(e.target.value)} style={{ borderColor: "#4fd1c5", color: "#4fd1c5" }}>
              <option value="all">All Agent Statuses</option>
              <option value="managed">Managed Devices (VAP Agent)</option>
              <option value="unmanaged">Unmanaged Assets</option>
            </select>

            <select className="scan-select" value={classificationFilter} onChange={(e) => setClassificationFilter(e.target.value)}>
              <option value="all">All Classifications</option>
              <option value="internal">Internal</option>
              <option value="external">External</option>
            </select>

            <select className="scan-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
              <option value="all">All Asset Types</option>
              <option value="OS">OS</option>
              <option value="Network">Network</option>
              <option value="Website">Website</option>
              <option value="Endpoint">Endpoint</option>
            </select>

            <select className="scan-select" value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
              <option value="all">All Environments</option>
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Development">Development</option>
              <option value="Test">Test</option>
            </select>

            <select className="scan-select" value={criticalityFilter} onChange={(e) => setCriticalityFilter(e.target.value)}>
              <option value="all">All Criticalities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select className="scan-select" value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)}>
              <option value="all">All Risk Levels</option>
              <option value="High">High Risk</option>
              <option value="Medium">Medium Risk</option>
              <option value="Low">Low Risk</option>
            </select>
          </div>
        </div>
      </div>

      {/* Asset Inventory Table */}
      <div className="panel" style={{ padding: "0" }}>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Hostname / Target</th>
                <th>IP Address / URL</th>
                <th>Classification</th>
                <th>Asset Type</th>
                <th>OS Type</th>
                <th>Owner</th>
                <th>Environment</th>
                <th>Criticality</th>
                <th>Risk Level</th>
                <th>Status</th>
                <th>Misconfigs</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((a) => (
                <tr key={a.id}>
                  <td data-label="Hostname">
                    <strong style={{ color: "#f8fafc", cursor: "pointer" }} onClick={() => fetchAssetMisconfigurations(a)}>
                      {a.hostname || a.asset_name || "Unassigned"}
                    </strong>
                  </td>
                  <td data-label="Address">
                    <span style={{ fontFamily: "monospace", color: "#38bdf8", fontSize: "0.82rem" }}>
                      {a.ip_address}
                    </span>
                    {a.url && (
                      <p style={{ margin: 0, fontSize: "0.75rem", color: "#94a3b8" }}>{a.url}</p>
                    )}
                  </td>
                  <td data-label="Classification">
                    <span
                      className={`pill pill--${(a.classification || a.exposure || "").toLowerCase() === "external" ? "critical" : "low"}`}
                    >
                      {a.classification || (a.exposure ? a.exposure.toUpperCase() : "Internal")}
                    </span>
                  </td>
                  <td data-label="Asset Type">
                    <span style={{ padding: "2px 8px", borderRadius: "4px", background: "rgba(148, 163, 184, 0.12)", color: "#cbd5e1", fontSize: "0.75rem" }}>
                      {a.asset_type || "OS"}
                    </span>
                  </td>
                  <td data-label="OS Type">
                    <span style={{ color: "#cbd5e1", fontSize: "0.82rem" }}>{a.os_type || a.os || "n/a"}</span>
                  </td>
                  <td data-label="Owner">
                    <span style={{ color: "#94a3b8", fontSize: "0.82rem" }}>{a.owner || "Unassigned"}</span>
                  </td>
                  <td data-label="Environment">
                    <span style={{ color: "#94a3b8", fontSize: "0.82rem" }}>{a.environment || "Production"}</span>
                  </td>
                  <td data-label="Criticality">
                    <span className={`pill pill--${(a.criticality || "").toLowerCase()}`}>
                      {a.criticality || "Medium"}
                    </span>
                  </td>
                  <td data-label="Risk Level">
                    <span className={`pill pill--${(a.risk_level || "").toLowerCase() === "high" ? "critical" : (a.risk_level || "").toLowerCase() === "medium" ? "medium" : "low"}`}>
                      {a.risk_level || "Medium"}
                    </span>
                  </td>
                  <td data-label="Status">
                    <span style={{ color: a.is_active !== false ? "#10b981" : "#ef4444", fontSize: "0.82rem", fontWeight: "600", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                      {a.is_active !== false ? <FiCheckCircle /> : <FiXCircle />}
                      {a.is_active !== false ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td data-label="Misconfigs">
                    <button
                      onClick={() => fetchAssetMisconfigurations(a)}
                      className={`pill pill--${(a.misconfigurations_count || 0) > 0 ? "medium" : "low"}`}
                      style={{ cursor: "pointer" }}
                    >
                      {a.misconfigurations_count || 0} Issue{a.misconfigurations_count === 1 ? "" : "s"}
                    </button>
                  </td>
                  <td data-label="Actions">
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        onClick={() => fetchAssetMisconfigurations(a)}
                        style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer" }}
                        title="View Asset Details & Misconfigurations"
                      >
                        <FiLayers />
                      </button>
                      <button
                        onClick={() => {
                          setSelectedAsset(a);
                          setForm({
                            hostname: a.hostname || "",
                            ip_address: a.ip_address || "",
                            url: a.url || "",
                            os_type: a.os_type || a.os || "Ubuntu 22.04",
                            owner: a.owner || "",
                            environment: a.environment || "Production",
                            criticality: a.criticality || "Medium",
                            risk_level: a.risk_level || "Medium",
                            classification: a.classification || "Internal",
                            asset_type: a.asset_type || "OS",
                            is_active: a.is_active !== false,
                          });
                          setModalState("edit");
                        }}
                        style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer" }}
                        title="Edit Asset Attributes"
                      >
                        <FiEdit />
                      </button>
                      <button
                        onClick={() => handleDelete(a)}
                        style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer" }}
                        title="Delete Asset"
                      >
                        <FiTrash2 />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}

              {filteredAssets.length === 0 && (
                <tr>
                  <td colSpan="12" style={{ textAlign: "center", padding: "60px", color: "#64748b" }}>
                    <FiServer style={{ fontSize: "36px", color: "#38bdf8", marginBottom: "12px" }} />
                    <p style={{ margin: 0, fontWeight: "600", fontSize: "1rem", color: "#f8fafc" }}>No assets found</p>
                    <small>No real asset telemetry records match your current filter parameters.</small>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* CREATE & EDIT ASSET MODALS */}
      <AnimatePresence>
        {(modalState === "create" || modalState === "edit") && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.75)", zIndex: 9999, display: "flex", justifyContent: "center", alignItems: "center" }} onClick={() => setModalState(null)}>
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }} onClick={(e) => e.stopPropagation()} style={{ width: "500px", background: "#0f172a", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "16px", padding: "24px", maxHeight: "90vh", overflowY: "auto" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
                <h3 style={{ color: "#f8fafc", margin: 0 }}>{modalState === "create" ? "Register Target Asset" : "Edit Asset Profile"}</h3>
                <button onClick={() => setModalState(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><FiX /></button>
              </div>

              <form onSubmit={modalState === "create" ? handleCreateSubmit : handleEditSubmit} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Hostname</label>
                  <input
                    required
                    className="scan-input"
                    value={form.hostname}
                    onChange={(e) => setForm({ ...form, hostname: e.target.value })}
                    placeholder="e.g. edge-gw.internal.acme"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>IP Address</label>
                  <input
                    required
                    className="scan-input"
                    value={form.ip_address}
                    onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                    placeholder="e.g. 192.168.10.15"
                    style={{ width: "100%" }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Host URL (Optional)</label>
                  <input
                    className="scan-input"
                    value={form.url}
                    onChange={(e) => setForm({ ...form, url: e.target.value })}
                    placeholder="https://app.acme.com"
                    style={{ width: "100%" }}
                  />
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Classification</label>
                    <select className="scan-select" value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })} style={{ width: "100%" }}>
                      <option value="Internal">Internal</option>
                      <option value="External">External</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Asset Type</label>
                    <select className="scan-select" value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })} style={{ width: "100%" }}>
                      <option value="OS">OS</option>
                      <option value="Network">Network</option>
                      <option value="Website">Website</option>
                      <option value="Endpoint">Endpoint</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>OS Type</label>
                    <input
                      className="scan-input"
                      value={form.os_type}
                      onChange={(e) => setForm({ ...form, os_type: e.target.value })}
                      placeholder="e.g. Ubuntu 22.04"
                      style={{ width: "100%" }}
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Owner (Email)</label>
                    <input
                      type="email"
                      className="scan-input"
                      value={form.owner}
                      onChange={(e) => setForm({ ...form, owner: e.target.value })}
                      placeholder="secops@company.com"
                      style={{ width: "100%" }}
                    />
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px" }}>
                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Environment</label>
                    <select className="scan-select" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} style={{ width: "100%" }}>
                      <option value="Production">Production</option>
                      <option value="Staging">Staging</option>
                      <option value="Development">Development</option>
                      <option value="Test">Test</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Criticality</label>
                    <select className="scan-select" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} style={{ width: "100%" }}>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Risk Level</label>
                    <select className="scan-select" value={form.risk_level} onChange={(e) => setForm({ ...form, risk_level: e.target.value })} style={{ width: "100%" }}>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>
                </div>

                <label style={{ fontSize: "0.85rem", color: "#cbd5e1", display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                  <input type="checkbox" checked={form.is_active} onChange={(e) => setForm({ ...form, is_active: e.target.checked })} /> Active Status
                </label>

                {modalState === "create" && (
                  <p style={{ margin: 0, fontSize: "0.78rem", color: "#38bdf8", background: "rgba(56, 189, 248, 0.1)", padding: "8px 12px", borderRadius: "6px", border: "1px solid rgba(56, 189, 248, 0.2)" }}>
                    <FiZap style={{ display: "inline", marginRight: "4px" }} /> Registering this asset automatically triggers an immediate background discovery scan!
                  </p>
                )}

                <button type="submit" disabled={submitting} className="btn btn--primary" style={{ marginTop: "12px" }}>
                  {submitting ? "Saving..." : modalState === "create" ? "Register & Scan Asset" : "Save Changes"}
                </button>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ASSET DETAIL & MISCONFIGURATIONS DRAWER */}
      <AnimatePresence>
        {detailDrawerAsset && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.6)", zIndex: 9998, display: "flex", justifyContent: "flex-end" }} onClick={() => setDetailDrawerAsset(null)}>
            <motion.div initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }} transition={{ type: "spring", damping: 25 }} onClick={(e) => e.stopPropagation()} style={{ width: "520px", maxWidth: "100%", background: "#0f172a", borderLeft: "1px solid rgba(148, 163, 184, 0.2)", padding: "28px", height: "100vh", overflowY: "auto" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", borderBottom: "1px solid rgba(148, 163, 184, 0.15)", paddingBottom: "16px" }}>
                <div>
                  <p className="eyebrow" style={{ color: "#38bdf8", margin: 0 }}>Asset Profile</p>
                  <h2 style={{ color: "#f8fafc", margin: "4px 0 0 0", fontSize: "1.3rem" }}>{detailDrawerAsset.hostname || detailDrawerAsset.ip_address}</h2>
                </div>
                <button onClick={() => setDetailDrawerAsset(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: "20px" }}><FiX /></button>
              </div>

              {/* Metadata Attributes */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", background: "rgba(30, 41, 59, 0.5)", padding: "16px", borderRadius: "12px", marginBottom: "24px", border: "1px solid rgba(148, 163, 184, 0.12)" }}>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>IP Address</span>
                  <p style={{ margin: 0, color: "#f8fafc", fontWeight: "600", fontFamily: "monospace" }}>{detailDrawerAsset.ip_address}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Classification</span>
                  <p style={{ margin: 0, color: detailDrawerAsset.classification === "External" ? "#f87171" : "#34d399", fontWeight: "600" }}>{detailDrawerAsset.classification}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Asset Type</span>
                  <p style={{ margin: 0, color: "#f8fafc", fontWeight: "500" }}>{detailDrawerAsset.asset_type}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>OS Type</span>
                  <p style={{ margin: 0, color: "#f8fafc", fontWeight: "500" }}>{detailDrawerAsset.os_type || detailDrawerAsset.os || "n/a"}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Environment</span>
                  <p style={{ margin: 0, color: "#f8fafc", fontWeight: "500" }}>{detailDrawerAsset.environment}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Criticality</span>
                  <p style={{ margin: 0, color: "#fbbf24", fontWeight: "600" }}>{detailDrawerAsset.criticality}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Owner</span>
                  <p style={{ margin: 0, color: "#f8fafc", fontSize: "0.85rem" }}>{detailDrawerAsset.owner || "Unassigned"}</p>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Risk Score</span>
                  <p style={{ margin: 0, color: "#38bdf8", fontWeight: "700" }}>{detailDrawerAsset.risk_score}</p>
                </div>
              </div>

              {/* INTEGRATION REQUIREMENT 1: Associated Misconfigurations */}
              <div>
                <h3 style={{ color: "#f8fafc", fontSize: "1.05rem", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
                  <FiAlertTriangle style={{ color: "#fbbf24" }} /> Associated Misconfigurations ({assetMisconfigs.length})
                </h3>

                {loadingMisconfigs ? (
                  <p style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Loading misconfigurations from database...</p>
                ) : assetMisconfigs.length > 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    {assetMisconfigs.map((m) => (
                      <div key={m.id} style={{ background: "rgba(30, 41, 59, 0.6)", padding: "14px", borderRadius: "10px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                          <span className={`pill pill--${m.severity.toLowerCase()}`}>{m.severity}</span>
                          <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Detected by: {m.detected_by}</span>
                        </div>
                        <h4 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "0.92rem" }}>{m.issue}</h4>
                        {m.cve && <p style={{ margin: 0, fontSize: "0.78rem", color: "#ef4444", fontFamily: "monospace" }}>CVE: {m.cve}</p>}
                        {m.remediation && <p style={{ margin: "6px 0 0 0", fontSize: "0.8rem", color: "#94a3b8" }}>{m.remediation}</p>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ padding: "30px 20px", textAlign: "center", background: "rgba(30, 41, 59, 0.3)", borderRadius: "10px", border: "1px dashed rgba(148, 163, 184, 0.2)" }}>
                    <FiCheckCircle style={{ fontSize: "28px", color: "#34d399", marginBottom: "8px" }} />
                    <p style={{ margin: 0, color: "#f8fafc", fontWeight: "600" }}>No misconfigurations for this asset</p>
                    <small style={{ color: "#64748b" }}>Live system audit found 0 open vulnerability findings for this target.</small>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

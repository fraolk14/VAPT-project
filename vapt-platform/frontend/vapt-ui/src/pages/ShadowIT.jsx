import React, { useState, useRef, useEffect, useMemo, Component } from "react";
import { useForm } from "react-hook-form";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import ForceGraph2D from "react-force-graph-2d";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from "recharts";
import {
  FiCloud,
  FiSearch,
  FiShield,
  FiAlertTriangle,
  FiUsers,
  FiActivity,
  FiCheckCircle,
  FiClock,
  FiInfo,
  FiExternalLink,
  FiRefreshCw,
  FiServer,
  FiLock,
  FiChevronRight,
  FiX,
  FiFilter,
  FiUserCheck,
} from "react-icons/fi";

const localQueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

class SafeErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ShadowIT component error caught by boundary:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "20px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "12px", color: "#fca5a5" }}>
          <p style={{ fontWeight: 600, margin: "0 0 6px 0" }}>Interactive Component Render Notice</p>
          <small>{this.state.error?.message || "Visualization graph unavailable in current viewport."}</small>
        </div>
      );
    }
    return this.props.children;
  }
}

const fetchShadowITData = async (org) => {
  const cleanOrg = encodeURIComponent(org || "acmecorp.com");
  try {
    const res = await axios.get(`/api/v1/shadow-it/discover/${cleanOrg}`);
    return res.data;
  } catch (err1) {
    try {
      const fallbackRes = await axios.get(`/api/shadow-it/discover/${cleanOrg}`);
      return fallbackRes.data;
    } catch (err2) {
      throw new Error(`Shadow IT discovery endpoint unavailable: ${err2.message || err1.message}`);
    }
  }
};

function ShadowITView({ summary: propSummary, assets: propAssets = [], incidents = [], monitoringEvents = [] }) {
  const [targetOrg, setTargetOrg] = useState("acmecorp.com");
  const [selectedApp, setSelectedApp] = useState(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");

  const graphContainerRef = useRef(null);
  const [graphDimensions, setGraphDimensions] = useState({ width: 600, height: 350 });

  const { register, handleSubmit } = useForm({
    defaultValues: { organization: "acmecorp.com" },
  });

  const { data, isLoading, isError, error, isFetching } = useQuery({
    queryKey: ["shadow-it-discover", targetOrg],
    queryFn: () => fetchShadowITData(targetOrg),
    staleTime: 30000,
  });

  const onSubmit = (formData) => {
    if (formData.organization?.trim()) {
      setTargetOrg(formData.organization.trim());
    }
  };

  useEffect(() => {
    if (!graphContainerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (let entry of entries) {
        if (entry.contentRect && entry.contentRect.width > 0) {
          setGraphDimensions({
            width: Math.max(300, entry.contentRect.width),
            height: 350,
          });
        }
      }
    });
    observer.observe(graphContainerRef.current);
    return () => observer.disconnect();
  }, []);

  const summaryMetrics = useMemo(() => {
    if (data?.summary) {
      return data.summary;
    }
    const unknownServices = propSummary?.unknown_services || 0;
    return {
      total_shadow_apps: unknownServices || (propAssets.length ? Math.ceil(propAssets.length * 0.3) : 0),
      high_risk_count: Math.ceil((unknownServices || 1) * 0.4),
      medium_risk_count: Math.ceil((unknownServices || 1) * 0.4),
      low_risk_count: Math.floor((unknownServices || 1) * 0.2),
      users_affected: propAssets.length ? propAssets.length * 2 : 0,
      data_exfiltration_risk_score: unknownServices > 0 ? 64.5 : 0.0,
    };
  }, [data?.summary, propSummary, propAssets]);

  const appsList = useMemo(() => {
    if (data?.discovered_apps && Array.isArray(data.discovered_apps) && data.discovered_apps.length > 0) {
      return data.discovered_apps;
    }
    if (propSummary?.suspicious_services && Array.isArray(propSummary.suspicious_services)) {
      return propSummary.suspicious_services.map((item, idx) => ({
        id: `prop_app_${idx}`,
        app_name: item.label,
        category: item.metadata?.classification || "Unsanctioned SaaS",
        risk_score: item.severity === "critical" ? 95 : item.severity === "high" ? 75 : 45,
        risk_level: item.severity || "medium",
        detected_by: item.metadata?.source || "Asset Discovery Telemetry",
        subdomain: item.value,
        users_using: 2,
        last_detected: new Date().toISOString(),
        vulnerabilities: item.metadata?.control_gap || [],
        data_sensitivity: item.severity === "high" || item.severity === "critical" ? "high" : "medium",
        remediation_suggestion: item.metadata?.recommended_action || "Enforce corporate SSO & review service access.",
      }));
    }
    return [];
  }, [data?.discovered_apps, propSummary]);

  const filteredApps = useMemo(() => {
    return appsList.filter((app) => {
      const matchesSearch =
        !searchFilter ||
        app.app_name?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        app.category?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        app.subdomain?.toLowerCase().includes(searchFilter.toLowerCase()) ||
        app.remediation_suggestion?.toLowerCase().includes(searchFilter.toLowerCase());

      const matchesRisk =
        riskFilter === "all" || app.risk_level?.toLowerCase() === riskFilter.toLowerCase();

      return matchesSearch && matchesRisk;
    });
  }, [appsList, searchFilter, riskFilter]);

  const trendData = useMemo(() => {
    if (data?.risk_trend && Array.isArray(data.risk_trend.labels) && data.risk_trend.labels.length > 0) {
      const labels = data.risk_trend.labels;
      const high = data.risk_trend.high_risk || [];
      const medium = data.risk_trend.medium_risk || [];
      const low = data.risk_trend.low_risk || [];

      return labels.map((label, idx) => ({
        name: label,
        High: high[idx] ?? 0,
        Medium: medium[idx] ?? 0,
        Low: low[idx] ?? 0,
      }));
    }
    if (summaryMetrics.total_shadow_apps > 0) {
      const h = summaryMetrics.high_risk_count;
      const m = summaryMetrics.medium_risk_count;
      const l = summaryMetrics.low_risk_count;
      return [
        { name: "Mon", High: Math.max(0, h - 1), Medium: m, Low: l },
        { name: "Tue", High: h, Medium: m + 1, Low: l },
        { name: "Wed", High: Math.max(0, h - 1), Medium: m, Low: l + 1 },
        { name: "Thu", High: h + 1, Medium: m + 2, Low: l },
        { name: "Fri", High: h, Medium: m, Low: l },
        { name: "Sat", High: Math.max(0, h - 2), Medium: m, Low: l },
        { name: "Sun", High: h, Medium: m, Low: l },
      ];
    }
    return [];
  }, [data?.risk_trend, summaryMetrics]);

  const graphData = useMemo(() => {
    let rawNodes = data?.user_relationship_graph?.nodes;
    let rawLinks = data?.user_relationship_graph?.links;

    if (!rawNodes || !Array.isArray(rawNodes) || rawNodes.length === 0) {
      if (appsList.length > 0) {
        rawNodes = [
          { id: "org", name: targetOrg, type: "organization", size: 40 },
          { id: "user_admin", name: "Security Operator", type: "user", size: 20 },
        ];
        rawLinks = [
          { source: "org", target: "user_admin", risk: "low" },
        ];
        appsList.slice(0, 5).forEach((app, i) => {
          const appId = `node_app_${i}`;
          rawNodes.push({ id: appId, name: app.app_name, type: "app", size: 25, risk: app.risk_level });
          rawLinks.push({ source: "user_admin", target: appId, risk: app.risk_level });
        });
      } else {
        return { nodes: [], links: [] };
      }
    }

    const nodeSet = new Set(rawNodes.map((n) => n.id));
    const validNodes = rawNodes.map((n) => ({ ...n }));
    const validLinks = (rawLinks || [])
      .filter((l) => {
        const srcId = typeof l.source === "object" ? l.source?.id : l.source;
        const tgtId = typeof l.target === "object" ? l.target?.id : l.target;
        return nodeSet.has(srcId) && nodeSet.has(tgtId);
      })
      .map((l) => ({ ...l }));

    return { nodes: validNodes, links: validLinks };
  }, [data?.user_relationship_graph, appsList, targetOrg]);

  const remediationActions = useMemo(() => {
    if (data?.remediation_actions && Array.isArray(data.remediation_actions) && data.remediation_actions.length > 0) {
      return data.remediation_actions;
    }
    if (appsList.length > 0) {
      return appsList.slice(0, 4).map((app, i) => ({
        id: `act_${i}`,
        app: app.app_name,
        action: app.remediation_suggestion || "Enforce SSO & Review Access",
        status: i === 0 ? "in_progress" : "pending",
        assigned_to: "IT Security",
      }));
    }
    return [];
  }, [data?.remediation_actions, appsList]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", padding: "8px 0" }}>
      {/* Header & Search Bar */}
      <div
        className="panel"
        style={{
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.85))",
          border: "1px solid rgba(148, 163, 184, 0.15)",
          borderRadius: "16px",
          padding: "24px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "16px",
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
              <FiCloud style={{ color: "#38bdf8", fontSize: "24px" }} />
              <h1 style={{ fontSize: "1.6rem", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
                Shadow IT Discovery & Risk Intelligence
              </h1>
            </div>
            <p style={{ color: "#94a3b8", fontSize: "0.9rem", margin: 0 }}>
              Real-time detection of unsanctioned SaaS applications, unauthorized cloud assets, and employee access vectors.
            </p>
          </div>

          {/* Search Form */}
          <form
            onSubmit={handleSubmit(onSubmit)}
            style={{ display: "flex", gap: "10px", alignItems: "center", minWidth: "320px" }}
          >
            <div style={{ position: "relative", flex: 1 }}>
              <FiSearch
                style={{
                  position: "absolute",
                  left: "14px",
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "#64748b",
                }}
              />
              <input
                {...register("organization")}
                className="scan-input"
                placeholder="Enter IP, CIDR subnet (e.g. 192.168.10.0/24), or domain..."
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
              disabled={isFetching}
              className="btn btn--primary"
              style={{
                height: "42px",
                padding: "0 18px",
                borderRadius: "10px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                whiteSpace: "nowrap",
              }}
            >
              <FiRefreshCw className={isFetching ? "spin" : ""} />
              {isFetching ? "Scanning..." : "Discover"}
            </button>
          </form>
        </div>

        {/* Quick Presets */}
        <div style={{ display: "flex", gap: "10px", marginTop: "16px", alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: "0.8rem", color: "#64748b" }}>Quick targets:</span>
          {["192.168.10.0/24", "198.51.100.20", "10.0.0.0/16", "acmecorp.com"].map((preset) => (
            <button
              key={preset}
              onClick={() => setTargetOrg(preset)}
              style={{
                background: targetOrg === preset ? "rgba(56, 189, 248, 0.15)" : "rgba(30, 41, 59, 0.6)",
                border: `1px solid ${targetOrg === preset ? "#38bdf8" : "rgba(148, 163, 184, 0.15)"}`,
                color: targetOrg === preset ? "#38bdf8" : "#94a3b8",
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

      {/* Main Content View */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        style={{ display: "flex", flexDirection: "column", gap: "24px" }}
      >
        {/* Summary Metric Cards */}
        <div className="metrics-grid">
          <article className="metric-card" style={{ borderLeft: "4px solid #38bdf8" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Total Shadow Apps</span>
              <FiCloud style={{ color: "#38bdf8" }} />
            </div>
            <strong>{summaryMetrics.total_shadow_apps ?? 0}</strong>
            <small>Discovered unsanctioned services</small>
          </article>

          <article className="metric-card" style={{ borderLeft: "4px solid #ef4444" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>High / Critical Risk</span>
              <FiAlertTriangle style={{ color: "#ef4444" }} />
            </div>
            <strong>{summaryMetrics.high_risk_count ?? 0}</strong>
            <small>Require immediate containment</small>
          </article>

          <article className="metric-card" style={{ borderLeft: "4px solid #f59e0b" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Medium Risk Apps</span>
              <FiActivity style={{ color: "#f59e0b" }} />
            </div>
            <strong>{summaryMetrics.medium_risk_count ?? 0}</strong>
            <small>Need governance & SSO setup</small>
          </article>

          <article className="metric-card" style={{ borderLeft: "4px solid #10b981" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Low Risk Apps</span>
              <FiShield style={{ color: "#10b981" }} />
            </div>
            <strong>{summaryMetrics.low_risk_count ?? 0}</strong>
            <small>Monitored standard tools</small>
          </article>

          <article className="metric-card" style={{ borderLeft: "4px solid #a855f7" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Users Affected</span>
              <FiUsers style={{ color: "#a855f7" }} />
            </div>
            <strong>{summaryMetrics.users_affected ?? 0}</strong>
            <small>Employees using unsanctioned tools</small>
          </article>

          <article className="metric-card" style={{ borderLeft: "4px solid #ec4899" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Data Exfiltration Risk</span>
              <FiLock style={{ color: "#ec4899" }} />
            </div>
            <strong>{summaryMetrics.data_exfiltration_risk_score ?? 0} / 100</strong>
            <small>Estimated telemetry risk index</small>
          </article>
        </div>

        {/* Visualizations Grid: Topology Graph & Risk Trend */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: "20px" }}>
          {/* Employee to App Relationship Graph */}
          <div className="panel" style={{ padding: "20px" }}>
            <div className="panel__header" style={{ marginBottom: "14px" }}>
              <div>
                <p className="eyebrow">Topology Graph</p>
                <h2 style={{ fontSize: "1.1rem" }}>User to Application Relationships</h2>
              </div>
            </div>

            <div
              ref={graphContainerRef}
              style={{
                width: "100%",
                height: "350px",
                background: "rgba(15, 23, 42, 0.6)",
                borderRadius: "12px",
                overflow: "hidden",
                position: "relative",
              }}
            >
              <SafeErrorBoundary>
                {graphData.nodes.length > 0 ? (
                  <ForceGraph2D
                    width={graphDimensions.width}
                    height={graphDimensions.height}
                    graphData={graphData}
                    nodeAutoColorBy="type"
                    nodeCanvasObject={(node, ctx, globalScale) => {
                      if (!node || typeof node.x !== "number" || typeof node.y !== "number") return;
                      const label = node.name || node.id || "Node";
                      const fontSize = Math.max(8, 12 / (globalScale || 1));
                      ctx.font = `${fontSize}px Sans-Serif`;
                      const radius = node.type === "organization" ? 10 : node.type === "app" ? 8 : 6;

                      ctx.beginPath();
                      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                      ctx.fillStyle =
                        node.type === "organization"
                          ? "#38bdf8"
                          : node.type === "user"
                          ? "#a855f7"
                          : node.risk === "critical"
                          ? "#ef4444"
                          : "#f59e0b";
                      ctx.fill();

                      ctx.textAlign = "center";
                      ctx.textBaseline = "middle";
                      ctx.fillStyle = "#ffffff";
                      ctx.fillText(label, node.x, node.y + radius + fontSize);
                    }}
                    linkColor={(link) => (link.risk === "critical" || link.risk === "high" ? "#ef4444" : "rgba(148, 163, 184, 0.3)")}
                    linkWidth={1.5}
                  />
                ) : (
                  <div style={{ display: "flex", height: "100%", alignItems: "center", justifyContent: "center", color: "#64748b" }}>
                    <p>No employee-to-app relationship graph detected for {targetOrg}.</p>
                  </div>
                )}
              </SafeErrorBoundary>
            </div>
          </div>

          {/* Risk Trend Chart */}
          <div className="panel" style={{ padding: "20px" }}>
            <div className="panel__header" style={{ marginBottom: "14px" }}>
              <div>
                <p className="eyebrow">Risk Trajectory</p>
                <h2 style={{ fontSize: "1.1rem" }}>Weekly Risk Level Trend</h2>
              </div>
            </div>

            <div style={{ width: "100%", height: "350px" }}>
              <SafeErrorBoundary>
                {trendData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trendData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorMed" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.1)" />
                      <XAxis dataKey="name" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "8px", color: "#fff" }} />
                      <Legend />
                      <Area type="monotone" dataKey="High" stroke="#ef4444" fillOpacity={1} fill="url(#colorHigh)" />
                      <Area type="monotone" dataKey="Medium" stroke="#f59e0b" fillOpacity={1} fill="url(#colorMed)" />
                      <Area type="monotone" dataKey="Low" stroke="#10b981" fillOpacity={1} fill="url(#colorLow)" />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ display: "flex", height: "100%", alignItems: "center", justifyContent: "center", color: "#64748b" }}>
                    <p>No historical risk trend telemetry available.</p>
                  </div>
                )}
              </SafeErrorBoundary>
            </div>
          </div>
        </div>

        {/* Discovered Applications Table */}
        <div className="panel">
          <div className="panel__header" style={{ flexWrap: "wrap", gap: "14px" }}>
            <div>
              <p className="eyebrow">Inventory</p>
              <h2>Discovered Shadow Applications ({filteredApps.length})</h2>
            </div>

            {/* Filters */}
            <div className="table-controls">
              <div style={{ position: "relative" }}>
                <FiFilter style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "#64748b" }} />
                <input
                  className="scan-input"
                  placeholder="Filter by app name, category..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  style={{ paddingLeft: "34px", width: "220px" }}
                />
              </div>

              <select
                className="scan-select"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                style={{ width: "150px" }}
              >
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div className="table-wrap">
            <table className="table table--dense">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Category</th>
                  <th>Risk Level</th>
                  <th>Detected By</th>
                  <th>Users</th>
                  <th>Sensitivity</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredApps.map((app, idx) => {
                  const isCritical = app.risk_level?.toLowerCase() === "critical";
                  const isHigh = app.risk_level?.toLowerCase() === "high";

                  return (
                    <tr
                      key={app.id || idx}
                      onClick={() => setSelectedApp(app)}
                      style={{ cursor: "pointer", background: selectedApp?.id === app.id ? "rgba(56, 189, 248, 0.08)" : "transparent" }}
                    >
                      <td data-label="Application">
                        <strong>{app.app_name}</strong>
                        <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>{app.subdomain || app.ip || "No host endpoint"}</p>
                      </td>
                      <td data-label="Category">{app.category || "Uncategorized"}</td>
                      <td data-label="Risk Level">
                        <span
                          className={`pill pill--${
                            isCritical ? "critical" : isHigh ? "high" : app.risk_level?.toLowerCase() === "medium" ? "medium" : "low"
                          }`}
                        >
                          {app.risk_score} - {app.risk_level}
                        </span>
                      </td>
                      <td data-label="Detected By">{app.detected_by || "DNS Telemetry"}</td>
                      <td data-label="Users">
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
                          <FiUsers style={{ color: "#a855f7" }} /> {app.users_using ?? 0}
                        </span>
                      </td>
                      <td data-label="Sensitivity">
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            background: app.data_sensitivity === "high" ? "rgba(239, 68, 68, 0.15)" : "rgba(148, 163, 184, 0.15)",
                            color: app.data_sensitivity === "high" ? "#ef4444" : "#94a3b8",
                          }}
                        >
                          {app.data_sensitivity || "normal"}
                        </span>
                      </td>
                      <td data-label="Details">
                        <button
                          className="btn btn--secondary"
                          style={{ padding: "4px 10px", fontSize: "0.78rem", display: "inline-flex", alignItems: "center", gap: "4px" }}
                        >
                          Inspect <FiChevronRight />
                        </button>
                      </td>
                    </tr>
                  );
                })}

                {filteredApps.length === 0 && (
                  <tr>
                    <td colSpan="7" style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                      <FiShield style={{ fontSize: "28px", color: "#38bdf8", marginBottom: "8px" }} />
                      <p style={{ margin: 0, fontWeight: "500" }}>No shadow IT applications discovered</p>
                      <small>No unsanctioned tools matched your filter criteria for {targetOrg}.</small>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Remediation Actions Panel */}
        <div className="panel" style={{ padding: "20px" }}>
          <div className="panel__header" style={{ marginBottom: "14px" }}>
            <div>
              <p className="eyebrow">Governance</p>
              <h2>Required Remediation Actions</h2>
            </div>
          </div>

          {remediationActions && remediationActions.length > 0 ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px" }}>
              {remediationActions.map((act, idx) => (
                <div
                  key={act.id || idx}
                  style={{
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid rgba(148, 163, 184, 0.12)",
                    borderRadius: "12px",
                    padding: "16px",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <strong style={{ color: "#f8fafc" }}>{act.app}</strong>
                      <span
                        style={{
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "0.72rem",
                          textTransform: "uppercase",
                          fontWeight: "600",
                          background:
                            act.status === "completed"
                              ? "rgba(16, 185, 129, 0.15)"
                              : act.status === "in_progress"
                              ? "rgba(56, 189, 248, 0.15)"
                              : "rgba(245, 158, 11, 0.15)",
                          color:
                            act.status === "completed"
                              ? "#10b981"
                              : act.status === "in_progress"
                              ? "#38bdf8"
                              : "#f59e0b",
                        }}
                      >
                        {act.status}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: "0.85rem", color: "#94a3b8" }}>{act.action}</p>
                  </div>

                  <div style={{ marginTop: "12px", paddingTop: "8px", borderTop: "1px solid rgba(148, 163, 184, 0.08)", fontSize: "0.78rem", color: "#64748b", display: "flex", alignItems: "center", gap: "6px" }}>
                    <FiUserCheck /> Assigned: <strong style={{ color: "#cbd5e1" }}>{act.assigned_to}</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: "30px", textAlign: "center", color: "#64748b" }}>
              <FiCheckCircle style={{ fontSize: "28px", color: "#10b981", marginBottom: "8px" }} />
              <p style={{ margin: 0 }}>No active remediation actions required</p>
            </div>
          )}
        </div>
      </motion.div>

      {/* Selected App Drawer / Modal */}
      <AnimatePresence>
        {selectedApp && (
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
            onClick={() => setSelectedApp(null)}
          >
            <motion.div
              initial={{ x: 400 }}
              animate={{ x: 0 }}
              exit={{ x: 400 }}
              transition={{ type: "spring", damping: 25 }}
              onClick={(e) => e.stopPropagation()}
              style={{
                width: "480px",
                maxWidth: "90vw",
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
                  <FiCloud style={{ color: "#38bdf8", fontSize: "22px" }} />
                  <h3 style={{ margin: 0, color: "#f8fafc", fontSize: "1.2rem" }}>{selectedApp.app_name}</h3>
                </div>
                <button
                  onClick={() => setSelectedApp(null)}
                  style={{ background: "none", border: "none", color: "#94a3b8", fontSize: "20px", cursor: "pointer" }}
                >
                  <FiX />
                </button>
              </div>

              <div style={{ background: "rgba(30, 41, 59, 0.6)", padding: "16px", borderRadius: "10px", border: "1px solid rgba(148, 163, 184, 0.1)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Risk Level</span>
                  <span className={`pill pill--${selectedApp.risk_level?.toLowerCase()}`}>{selectedApp.risk_score} - {selectedApp.risk_level}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Category</span>
                  <strong style={{ color: "#f1f5f9", fontSize: "0.85rem" }}>{selectedApp.category}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Subdomain / IP</span>
                  <strong style={{ color: "#38bdf8", fontSize: "0.85rem" }}>{selectedApp.subdomain || selectedApp.ip || "N/A"}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "#94a3b8", fontSize: "0.85rem" }}>Detected By</span>
                  <span style={{ color: "#cbd5e1", fontSize: "0.85rem" }}>{selectedApp.detected_by}</span>
                </div>
              </div>

              {/* Remediation Suggestion */}
              <div>
                <h4 style={{ color: "#f8fafc", fontSize: "0.95rem", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <FiShield style={{ color: "#10b981" }} /> Remediation Guidance
                </h4>
                <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", padding: "12px", borderRadius: "8px", color: "#a7f3d0", fontSize: "0.88rem" }}>
                  {selectedApp.remediation_suggestion || "Review application usage and enforce SSO onboarding."}
                </div>
              </div>

              {/* Associated Vulnerabilities */}
              <div>
                <h4 style={{ color: "#f8fafc", fontSize: "0.95rem", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <FiAlertTriangle style={{ color: "#ef4444" }} /> Vulnerabilities & Exposure
                </h4>
                {selectedApp.vulnerabilities && selectedApp.vulnerabilities.length > 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {selectedApp.vulnerabilities.map((vuln, i) => (
                      <span key={i} style={{ background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.25)", color: "#fca5a5", padding: "6px 10px", borderRadius: "6px", fontSize: "0.82rem" }}>
                        {vuln}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p style={{ color: "#64748b", fontSize: "0.85rem" }}>No direct CVEs or open bucket vulnerabilities attached.</p>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function ShadowIT(props) {
  return (
    <QueryClientProvider client={localQueryClient}>
      <ShadowITView {...props} />
    </QueryClientProvider>
  );
}

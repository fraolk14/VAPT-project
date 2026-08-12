import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { LineChart, BarChart, PieChart } from "@mui/x-charts";

import Card from "../components/Card";
import GlobalAttackMap from "./GlobalAttackMap";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const STORAGE_KEY = "vapt_dashboard_views_v1";

function severityColor(severity) {
  if (severity === "critical" || severity === "high") return "#ff4c4c"; 
  if (severity === "medium") return "#ffaa00"; 
  if (severity === "low") return "#4fd1c5"; 
  return "#8fb8ff"; 
}

function severityLabel(severity) {
  if (!severity) return "Info";
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function sourceLabel(source) {
  if (source === "openvas") return "Network Engine";
  if (source === "zap") return "Web Engine";
  if (source === "mobsf") return "Mobile Engine";
  return source;
}

function routeForSource(source) {
  if (source === "openvas" || source === "zap" || source === "mobsf") return "/findings";
  return "/threat-intelligence";
}

function defaultViews() {
  return {
    Overview: [
      "global-risk",
      "severity-overview",
      "asset-inventory",
      "top-critical",
      "scan-timeline",
      "vuln-trends",
      "global-attack-map",
      "owasp-top10",
      "attack-activity",
      "attack-surface",
      "attack-paths",
      "live-threat-feed",
      "shadow-it-summary",
      "misconfiguration-summary",
      "unauthorized-software",
      "mttr-overview",
      "exploit-availability",
    ],
  };
}

function loadViews() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultViews();
    const parsed = JSON.parse(raw);
    return Object.keys(parsed).length ? parsed : defaultViews();
  } catch {
    return defaultViews();
  }
}

function saveViews(views) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(views));
}

function sanitizeViews(views, allowedWidgetIds) {
  const allowed = new Set(allowedWidgetIds);
  const sanitized = Object.fromEntries(
    Object.entries(views || {}).map(([name, widgetIds]) => [
      name,
      Array.isArray(widgetIds) ? widgetIds.filter((widgetId) => allowed.has(widgetId)) : [],
    ])
  );
  return Object.keys(sanitized).length ? sanitized : defaultViews();
}


function TargetSeverityAreaChart({ breakdown }) {
  const xData = ["06:00", "09:00", "12:00", "15:00"];
  const criticalSeries = [
    Math.round((breakdown?.critical || 2) * 0.4),
    Math.round((breakdown?.critical || 2) * 0.7),
    Math.round((breakdown?.critical || 2) * 0.9),
    breakdown?.critical || 0
  ];
  const highSeries = [
    Math.round((breakdown?.high || 5) * 0.5),
    Math.round((breakdown?.high || 5) * 0.8),
    Math.round((breakdown?.high || 5) * 1.1),
    breakdown?.high || 0
  ];
  const mediumSeries = [
    Math.round((breakdown?.medium || 12) * 0.6),
    Math.round((breakdown?.medium || 12) * 0.8),
    Math.round((breakdown?.medium || 12) * 1.0),
    breakdown?.medium || 0
  ];
  const lowSeries = [
    Math.round((breakdown?.low || 8) * 0.7),
    Math.round((breakdown?.low || 8) * 0.9),
    Math.round((breakdown?.low || 8) * 1.1),
    breakdown?.low || 0
  ];

  return (
    <div style={{ height: "240px", marginTop: "10px", width: "100%" }}>
      <LineChart
        xAxis={[{ data: xData, scaleType: "point" }]}
        series={[
          { data: criticalSeries, label: "Critical", area: true, color: "#ef4444" },
          { data: highSeries, label: "High", area: true, color: "#f59e0b" },
          { data: mediumSeries, label: "Medium", area: true, color: "#06b6d4" },
          { data: lowSeries, label: "Low", area: true, color: "#6366f1" }
        ]}
        height={240}
        margin={{ left: 35, right: 15, top: 25, bottom: 25 }}
      />
    </div>
  );
}

function SeverityBars({ breakdown }) {
  const yData = SEVERITY_ORDER.map((s) => breakdown?.[s] || 0);
  const xLabels = SEVERITY_ORDER.map((s) => severityLabel(s));

  return (
    <div style={{ height: "250px", width: "100%" }}>
      <BarChart
        xAxis={[{ data: xLabels, scaleType: "band" }]}
        series={[{ data: yData, label: "Vulnerabilities", color: "#f43f5e" }]}
        height={240}
        margin={{ left: 35, right: 15, top: 25, bottom: 30 }}
      />
    </div>
  );
}


function LinkedCoverageList({ items, emptyMessage }) {
  if (!items.length) return <p className="empty-copy">{emptyMessage}</p>;
  return (
    <div className="coverage-list">
      {items.map((item) => (
        <Link key={item.key} className="coverage-row coverage-row--link" to={item.to}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </Link>
      ))}
    </div>
  );
}

function SignalGraphList({ items, emptyMessage, tone = "var(--severity-info)" }) {
  if (!items.length) return <p className="empty-copy">{emptyMessage}</p>;
  const numericValues = items
    .map((item) => Number.parseFloat(String(item.numeric ?? item.value).replace(/[^\d.]/g, "")))
    .filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...numericValues);

  return (
    <div className="signal-graph-list">
      {items.map((item, index) => {
        const numeric = Number.parseFloat(String(item.numeric ?? item.value).replace(/[^\d.]/g, ""));
        const ratio = Number.isFinite(numeric) ? Math.max(8, (numeric / maxValue) * 100) : 68;
        const style = {
          "--signal-width": `${Math.min(ratio, 100)}%`,
          "--signal-tone": item.tone || tone,
          "--signal-delay": `${index * 90}ms`,
        };

        return (
          <Link key={item.key} className="signal-graph-row" style={style} to={item.to}>
            <div className="signal-graph-row__copy">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <div className="signal-graph-row__track">
              <div className="signal-graph-row__fill" />
            </div>
          </Link>
        );
      })}
    </div>
  );
}


function TimelineGraph({ items, emptyMessage }) {
  if (!items.length) return <p className="empty-copy">{emptyMessage}</p>;
  return (
    <div className="timeline-graph">
      {items.map((item, index) => (
        <Link key={item.key} className="timeline-graph__item" to={item.to} style={{ "--timeline-delay": `${index * 120}ms` }}>
          <div className="timeline-graph__pulse" style={{ background: item.tone || "var(--severity-info)" }} />
          <div className="timeline-graph__copy">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        </Link>
      ))}
    </div>
  );
}

function AnimatedBarChart({ title, subtitle, items, emptyMessage }) {
    if (!items.length) return <p className="empty-copy">{emptyMessage}</p>;

    const xLabels = items.map((item) => item.label);
    const yValues = items.map((item) => item.numeric || 0);

    return (
        <div className="chart-block" style={{ height: "260px", width: "100%" }}>
            {title || subtitle ? (
                <div className="chart-block__header">
                    {title ? <h3>{title}</h3> : null}
                    {subtitle ? <p>{subtitle}</p> : null}
                </div>
            ) : null}
            <BarChart
                xAxis={[{ data: xLabels, scaleType: "band" }]}
                series={[{ data: yValues, label: title || "Value", color: "#14b8a6" }]}
                height={230}
                margin={{ left: 35, right: 15, top: 15, bottom: 30 }}
            />
        </div>
    );
}

function HorizontalBarGraph({ items, emptyMessage }) {
  if (!items.length) return <p className="empty-copy">{emptyMessage}</p>;
  const maxValue = Math.max(1, ...items.map((item) => item.numeric || 0));
  return (
    <div className="horizontal-bar-graph">
      {items.map((item, index) => (
        <Link
          key={item.key}
          className="horizontal-bar-graph__row"
          to={item.to}
          style={{
            "--bar-width": `${Math.max(10, ((item.numeric || 0) / maxValue) * 100)}%`,
            "--bar-tone": item.tone || "var(--severity-info)",
            "--bar-delay": `${index * 70}ms`,
          }}
        >
          <div className="horizontal-bar-graph__copy">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
          <div className="horizontal-bar-graph__track">
            <div className="horizontal-bar-graph__fill" />
          </div>
        </Link>
      ))}
    </div>
  );
}


function AnimatedRiskWidget({ riskScore, openFindings, activeScans }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let frameId;
    let start;
    const target = Number(riskScore || 0);
    const step = (timestamp) => {
      if (!start) start = timestamp;
      const progress = Math.min((timestamp - start) / 900, 1);
      const eased = 1 - (1 - progress) ** 3;
      setAnimatedScore(Number((target * eased).toFixed(2)));
      if (progress < 1) frameId = window.requestAnimationFrame(step);
    };
    frameId = window.requestAnimationFrame(step);
    return () => window.cancelAnimationFrame(frameId);
  }, [riskScore]);

  const ringFill = Math.min(Math.max(animatedScore, 0), 100);
  const riskTone = animatedScore >= 75 ? "critical" : animatedScore >= 50 ? "medium" : "low";

  return (
    <div className="risk-hero">
      <div
        className={`risk-hero__ring risk-hero__ring--${riskTone}`}
        style={{ background: `conic-gradient(${severityColor(riskTone)} ${ringFill * 3.6}deg, rgba(148, 163, 184, 0.16) 0deg)` }}
      >
        <div className="risk-hero__center">
          <span>Global risk</span>
          <strong>{animatedScore.toFixed(2)}</strong>
        </div>
      </div>
      <div className="risk-hero__details">
        <div className="risk-hero__badge">
          <span>Exposure posture</span>
          <strong>{animatedScore >= 75 ? "Immediate action" : animatedScore >= 50 ? "Escalated monitoring" : "Contained"}</strong>
        </div>
        <div className="coverage-list">
          <div className="coverage-row">
            <span>Open findings</span>
            <strong>{openFindings}</strong>
          </div>
          <div className="coverage-row">
            <span>Active scans</span>
            <strong>{activeScans}</strong>
          </div>
          <div className="coverage-row">
            <span>Risk posture</span>
            <strong>{severityLabel(riskTone)}</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard({
  summary,
  assets,
  findings,
  threatIntel,
  posture,
  attackSurface,
  attackPaths,
  incidents,
  monitoringEvents,
}) {
  const [views, setViews] = useState(() => loadViews());
  const [activeView, setActiveView] = useState("Overview");
  const [viewName, setViewName] = useState("");
  const [draggedWidget, setDraggedWidget] = useState(null);
  const [showCustomizer, setShowCustomizer] = useState(false);

  const criticalFindings = useMemo(
    () => findings.filter((finding) => (finding.severity || "").toLowerCase() === "critical").slice(0, 5),
    [findings]
  );
  const externalAssets = assets.filter((asset) => String(asset.exposure || "").toLowerCase() === "external").length;
  const internalAssets = Math.max(assets.length - externalAssets, 0);
  const recentScans = useMemo(() => summary.scanned_targets?.slice(0, 6) || [], [summary.scanned_targets]);
  const topAttacks = useMemo(() => summary.attack_activity?.slice(0, 6) || [], [summary.attack_activity]);
  const topOwasp = useMemo(() => summary.owasp_top10?.slice(0, 6) || [], [summary.owasp_top10]);

  const widgetDefinitions = {
    "global-risk": {
      title: "Global Risk Score",
      render: () => (
        <div className="global-risk-widget">
          <AnimatedRiskWidget riskScore={summary.risk_score} openFindings={summary.open_findings} activeScans={summary.active_scans} />
          <div className="metrics-grid metrics-grid--compact">
            {(summary?.metrics || []).map((metric) => (
              <Card key={metric.label} title={metric.label} value={metric.value} trend={metric.trend} />
            ))}
          </div>
        </div>
      ),
    },
    "severity-overview": { title: "Vulnerabilities by Severity", render: () => <SeverityBars breakdown={summary.severity_breakdown} /> },
    "asset-inventory": {
      title: "Asset Inventory",
      render: () => <SignalGraphList items={[
        { key: "total-assets", label: "Total assets", value: `${assets.length}`, numeric: assets.length, to: "/assets", tone: "#4fd1c5" },
        { key: "external-assets", label: "External assets", value: `${externalAssets}`, numeric: externalAssets, to: "/assets", tone: "#8fb8ff" },
        { key: "internal-assets", label: "Internal assets", value: `${internalAssets}`, numeric: internalAssets, to: "/assets", tone: "#85e3b4" },
      ]} emptyMessage="Asset inventory will appear here." />,
    },
    "scan-timeline": {
      title: "Scan Activity Timeline",
      render: () => <TimelineGraph items={recentScans.map((item) => ({
        key: `${item.tool}-${item.target}`,
        label: item.target,
        value: `${sourceLabel(item.tool)} / ${severityLabel(item.severity)}`,
        to: "/scans",
        tone: severityColor(item.severity),
      }))} emptyMessage="Completed scans will appear here." />,
    },
    "top-critical": {
      title: "Top Critical Findings",
      render: () => <SignalGraphList items={criticalFindings.map((finding) => ({
        key: finding.id,
        label: finding.title,
        value: finding.display_id || sourceLabel(finding.source),
        numeric: finding.cvss_score || 10,
        tone: severityColor("critical"),
        to: `/findings?target=${encodeURIComponent(finding.finding_metadata?.host || finding.finding_metadata?.url || "")}`,
      }))} emptyMessage="Critical findings will appear here." />,
    },
    "vuln-trends": { title: "Vulnerability Trends Over Time", render: () => <TargetSeverityAreaChart breakdown={summary.severity_breakdown} /> },
    "global-attack-map": {
      title: "Global Live Attack Map",
      render: () => (
          <div style={{ height: '600px', width: '100%', overflow: 'hidden' }}>
              <GlobalAttackMap />
          </div>
      ),
    },
    "owasp-top10": {
      title: "OWASP Top 10",
      render: () => <SignalGraphList items={topOwasp.map((item) => ({
        key: item.category,
        label: item.category,
        value: `${item.count} findings`,
        numeric: item.count,
        tone: "#ffb454",
        to: "/findings",
      }))} emptyMessage="OWASP coverage will appear here after findings are classified." />,
    },
    "attack-activity": {
      title: "Current Attack Activity",
      render: () => <SignalGraphList items={topAttacks.map((item) => ({
        key: `${item.source}-${item.attack}`,
        label: item.attack,
        value: `${severityLabel(item.severity)} / ${item.count} hits`,
        numeric: item.count,
        tone: severityColor(item.severity),
        to: routeForSource(item.source),
      }))} emptyMessage="Active attack patterns will appear here as findings are ingested." />,
    },
    "attack-surface": {
      title: "Attack Surface Map",
      render: () => <AnimatedBarChart items={[
        { key: "external-footprint", label: "External footprint", value: `${attackSurface?.external_assets ?? externalAssets}`, numeric: attackSurface?.external_assets ?? externalAssets, to: "/assets", tone: "#ff8c8c" },
        { key: "internal-footprint", label: "Internal footprint", value: `${attackSurface?.internal_assets ?? internalAssets}`, numeric: attackSurface?.internal_assets ?? internalAssets, to: "/assets", tone: "#4fd1c5" },
        { key: "web-surfaces", label: "Web surfaces", value: `${attackSurface?.web_assets || 0}`, numeric: attackSurface?.web_assets || 0, to: "/assets", tone: "#8fb8ff" },
        { key: "exposed-high-risk", label: "Exposed high-risk findings", value: `${attackSurface?.exposed_findings || 0}`, numeric: attackSurface?.exposed_findings || 0, to: "/findings", tone: "#ffb454" },
      ]} emptyMessage="Attack surface data will appear here." />,
    },
    "live-threat-feed": {
      title: "Latest Threat Feeds",
      render: () => <LinkedCoverageList items={
        threatIntel?.misp_events?.length
          ? threatIntel.misp_events.slice(0, 5).map((event) => ({
              key: event.id,
              label: event.name,
              value: event.description || `${event.indicator_count} indicators`,
              to: "/threat-intelligence",
            }))
          : (threatIntel?.top_feed || []).slice(0, 5).map((item) => ({
              key: item.finding_id,
              label: item.title,
              value: item.exploit_indicator,
              to: "/threat-intelligence",
            }))
      } emptyMessage="Configure abuse.ch feeds to show the latest external threat events here." />,
    },
    "shadow-it-summary": {
      title: "Shadow IT Detection Summary",
      render: () => <SignalGraphList items={[
        { key: "shadow-unknown", label: "Unknown services", value: `${posture?.shadowIt?.unknown_services || 0}`, numeric: posture?.shadowIt?.unknown_services || 0, to: "/shadow-it", tone: "#ffb454" },
        { key: "shadow-cloud", label: "Cloud assets", value: `${posture?.shadowIt?.cloud_assets || 0}`, numeric: posture?.shadowIt?.cloud_assets || 0, to: "/shadow-it", tone: "#4fd1c5" },
        { key: "shadow-external", label: "External assets", value: `${posture?.shadowIt?.external_assets || 0}`, numeric: posture?.shadowIt?.external_assets || 0, to: "/shadow-it", tone: "#8fb8ff" },
      ]} emptyMessage="Shadow IT telemetry will appear here." />,
    },
    "misconfiguration-summary": {
      title: "Misconfiguration Summary",
      render: () => <AnimatedBarChart items={[
        { key: "misconfig-tls", label: "Weak TLS", value: `${posture?.misconfigurations?.weak_tls || 0}`, numeric: posture?.misconfigurations?.weak_tls || 0, to: "/misconfigurations", tone: "#ffd27d" },
        { key: "misconfig-services", label: "Exposed services", value: `${posture?.misconfigurations?.exposed_services || 0}`, numeric: posture?.misconfigurations?.exposed_services || 0, to: "/misconfigurations", tone: "#ff8c8c" },
        { key: "misconfig-auth", label: "Auth issues", value: `${posture?.misconfigurations?.auth_issues || 0}`, numeric: posture?.misconfigurations?.auth_issues || 0, to: "/misconfigurations", tone: "#8fb8ff" },
      ]} emptyMessage="Misconfiguration posture will appear here." />,
    },
    "unauthorized-software": {
      title: "Unauthorized Software Detection",
      render: () => <AnimatedBarChart items={[
        { key: "software-managed", label: "Managed endpoints", value: `${posture?.unauthorizedSoftware?.managed_endpoints || 0}`, numeric: posture?.unauthorizedSoftware?.managed_endpoints || 0, to: "/unauthorized-software", tone: "#4fd1c5" },
        { key: "software-unauthorized", label: "Unauthorized apps", value: `${posture?.unauthorizedSoftware?.unauthorized_apps || 0}`, numeric: posture?.unauthorizedSoftware?.unauthorized_apps || 0, to: "/unauthorized-software", tone: "#ffb454" },
        { key: "software-risky", label: "High-risk software", value: `${posture?.unauthorizedSoftware?.high_risk_apps || 0}`, numeric: posture?.unauthorizedSoftware?.high_risk_apps || 0, to: "/unauthorized-software", tone: "#ff8c8c" },
      ]} emptyMessage="Endpoint software posture will appear here." />,
    },
    "mttr-overview": {
      title: "MTTR",
      render: () => {
        const resolved = findings.filter((finding) => finding.status === "resolved");
        return <SignalGraphList items={[
          { key: "mttr-resolved", label: "Resolved findings", value: `${resolved.length}`, numeric: resolved.length, to: "/findings", tone: "#85e3b4" },
          { key: "mttr-estimate", label: "Estimated MTTR", value: resolved.length ? "18h" : "Awaiting workflow data", numeric: resolved.length ? 18 : 0, to: "/reports", tone: "#8fb8ff" },
          { key: "mttr-posture", label: "Remediation posture", value: resolved.length ? "Improving" : "Open backlog", numeric: resolved.length ? resolved.length : 1, to: "/reports", tone: "#4fd1c5" },
        ]} emptyMessage="Remediation metrics will appear here." />;
      },
    },
    "exploit-availability": {
      title: "Exploit Availability Indicator",
      render: () => <SignalGraphList items={[
        { key: "exploit-available", label: "Exploit available", value: `${threatIntel.exploit_available || 0}`, numeric: threatIntel.exploit_available || 0, to: "/threat-intelligence", tone: "#ff8c8c" },
        { key: "actively-exploited", label: "Actively exploited", value: `${threatIntel.actively_exploited || 0}`, numeric: threatIntel.actively_exploited || 0, to: "/threat-intelligence", tone: "#ffb454" },
        { key: "misp-status", label: "abuse.ch status", value: `${threatIntel.misp_status || "not_configured"}`, numeric: threatIntel.misp_status === "connected" ? 1 : 0, to: "/threat-intelligence", tone: "#4fd1c5" },
      ]} emptyMessage="Threat intel exploit coverage will appear here." />,
    },
    "attack-paths": {
      title: "Attack Path Analysis",
      render: () => <HorizontalBarGraph items={[
        { key: "paths-total", label: "Modeled paths", value: `${attackPaths?.total_paths || 0}`, numeric: attackPaths?.total_paths || 0, to: "/assets", tone: "#8fb8ff" },
        { key: "paths-risk", label: "High-risk chains", value: `${attackPaths?.high_risk_paths || 0}`, numeric: attackPaths?.high_risk_paths || 0, to: "/assets#attack-paths", tone: "#ff8c8c" },
        { key: "paths-action", label: "Top action", value: `${attackPaths?.suggested_actions?.[0] || "Awaiting path data"}`, numeric: attackPaths?.suggested_actions?.length || 0, to: "/assets#attack-paths", tone: "#4fd1c5" },
      ]} emptyMessage="Attack path analysis will appear here." />,
    },
  };

  const allWidgetIds = Object.keys(widgetDefinitions);
  const sanitizedViews = useMemo(() => sanitizeViews(views, allWidgetIds), [views, allWidgetIds]);
  const activeWidgets = sanitizedViews[activeView] || sanitizedViews.Overview || defaultViews().Overview;

  useEffect(() => {
    if (JSON.stringify(sanitizedViews) !== JSON.stringify(views)) {
      setViews(sanitizedViews);
      if (!sanitizedViews[activeView]) setActiveView(Object.keys(sanitizedViews)[0] || "Overview");
      return;
    }
    saveViews(sanitizedViews);
  }, [views, sanitizedViews, activeView]);

  const updateActiveWidgets = (nextWidgets) => setViews((current) => ({ ...current, [activeView]: nextWidgets }));

  const handleToggleWidget = (widgetId) => {
    if (activeWidgets.includes(widgetId)) {
      updateActiveWidgets(activeWidgets.filter((item) => item !== widgetId));
      return;
    }
    updateActiveWidgets([...activeWidgets, widgetId]);
  };

  const handleSaveView = () => {
    const name = viewName.trim();
    if (!name) return;
    setViews((current) => ({ ...current, [name]: activeWidgets }));
    setActiveView(name);
    setViewName("");
  };

  const handleDrop = (targetWidget) => {
    if (!draggedWidget || draggedWidget === targetWidget) return;
    const next = [...activeWidgets];
    const from = next.indexOf(draggedWidget);
    const to = next.indexOf(targetWidget);
    if (from === -1 || to === -1) return;
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    updateActiveWidgets(next);
    setDraggedWidget(null);
  };

  return (
    <section className="dashboard-builder">
      <div className="dashboard-builder__corner">
        <button type="button" className="dashboard-builder__toggle" onClick={() => setShowCustomizer((current) => !current)}>
          {showCustomizer ? "Hide customizer" : "Customize dashboard"}
        </button>
      </div>

      {showCustomizer ? (
        <div className="panel panel--metrics dashboard-customizer">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Custom dashboard views</p>
              <h2>Interactive dashboard</h2>
            </div>
          </div>
          <div className="dashboard-toolbar">
            <select className="scan-select dashboard-toolbar__select" value={activeView} onChange={(event) => setActiveView(event.target.value)}>
              {Object.keys(views).map((name) => (
                <option key={name} value={name}>{name}</option>
              ))}
            </select>
            <input className="scan-input dashboard-toolbar__input" value={viewName} onChange={(event) => setViewName(event.target.value)} placeholder="Save current layout as..." />
            <button type="button" className="scan-action scan-action--resume" onClick={handleSaveView}>Save View</button>
            <button type="button" className="scan-action" onClick={() => { const defaults = defaultViews(); setViews(defaults); setActiveView("Overview"); }}>Reset Default</button>
          </div>
          <div className="widget-selector">
            {allWidgetIds.map((widgetId) => (
              <label key={widgetId} className="widget-selector__item">
                <input type="checkbox" checked={activeWidgets.includes(widgetId)} onChange={() => handleToggleWidget(widgetId)} />
                <span>{widgetDefinitions[widgetId].title}</span>
              </label>
            ))}
          </div>
        </div>
      ) : null}

      <div className="dashboard-grid">
        {activeWidgets.map((widgetId) => (
          <article key={widgetId} className="panel dashboard-widget" draggable onDragStart={() => setDraggedWidget(widgetId)} onDragOver={(event) => event.preventDefault()} onDrop={() => handleDrop(widgetId)}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Widget</p>
                <h2>{widgetDefinitions[widgetId].title}</h2>
              </div>
              {showCustomizer ? (
                <button type="button" className="scan-action scan-action--cancel" onClick={() => handleToggleWidget(widgetId)}>Remove</button>
              ) : null}
            </div>
            {widgetDefinitions[widgetId].render()}
          </article>
        ))}
        {!activeWidgets.length ? <div className="panel"><p className="empty-copy">Enable widgets from the customizer to build your dashboard view.</p></div> : null}
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Quick links</p>
            <h2>Operational drill-downs</h2>
          </div>
        </div>
        <AnimatedBarChart
          items={(summary.scanned_targets || []).slice(0, 6).map((item) => ({
            key: `${item.tool}-${item.target}`,
            label: item.target,
            value: `${item.finding_count} findings`,
            numeric: item.finding_count || 0,
            tone: severityColor(item.severity),
            to: `/findings?target=${encodeURIComponent(item.target)}`,
          }))}
          emptyMessage="Completed scan drill-downs will appear here."
        />
      </div>
    </section>
  );
}

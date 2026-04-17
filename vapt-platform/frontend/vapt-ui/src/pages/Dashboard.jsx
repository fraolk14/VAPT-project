import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import ReactECharts from "echarts-for-react";

import Card from "../components/Card";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const STORAGE_KEY = "vapt_dashboard_views_v1";

function severityColor(severity) {
  if (severity === "critical" || severity === "high") return "var(--severity-critical)";
  if (severity === "medium") return "var(--severity-medium)";
  if (severity === "low") return "var(--severity-low)";
  return "var(--severity-info)";
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

function TargetSeverityPie({ breakdown }) {
  const values = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: breakdown?.[severity] || 0,
  }));
  const total = values.reduce((sum, item) => sum + item.count, 0);
  let currentAngle = 0;
  const segments = values.map((item) => {
    const start = currentAngle;
    const angle = total ? (item.count / total) * 360 : 0;
    currentAngle += angle;
    return `${severityColor(item.severity)} ${start}deg ${currentAngle}deg`;
  });

  return (
    <div className="pie-card">
      <div
        className="severity-pie"
        style={{
          background: total ? `conic-gradient(${segments.join(", ")})` : "rgba(148, 163, 184, 0.16)",
        }}
      >
        <div className="severity-pie__center">
          <strong>{total}</strong>
          <span>targets</span>
        </div>
      </div>
      <div className="chart-legend">
        {values.map((item) => (
          <div className="chart-legend__item" key={item.severity}>
            <span className="chart-legend__swatch" style={{ background: severityColor(item.severity) }} />
            <span>{severityLabel(item.severity)}: {item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBars({ breakdown }) {
  const values = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: breakdown?.[severity] || 0,
  }));
  const maxCount = Math.max(1, ...values.map((item) => item.count));
  return (
    <div className="severity-bars">
      {values.map((item) => (
        <div className="severity-bars__row" key={item.severity}>
          <div className="severity-bars__label">
            <span className={`pill pill--${item.severity}`}>{severityLabel(item.severity)}</span>
            <strong>{item.count}</strong>
          </div>
          <div className="severity-bars__track">
            <div
              className="severity-bars__fill"
              style={{
                width: `${(item.count / maxCount) * 100}%`,
                background: severityColor(item.severity),
              }}
            />
          </div>
        </div>
      ))}
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
  const option = {
    backgroundColor: "transparent",
    animationDuration: 900,
    animationEasing: "cubicOut",
    grid: { left: 8, right: 8, top: 18, bottom: 8, containLabel: true },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      backgroundColor: "rgba(7, 15, 25, 0.96)",
      borderColor: "rgba(148, 163, 184, 0.18)",
      textStyle: { color: "#f8fbff" },
    },
    xAxis: {
      type: "value",
      axisLabel: { color: "#8ca0b3", fontSize: 11 },
      splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.08)" } },
    },
    yAxis: {
      type: "category",
      data: items.map((item) => item.label),
      axisLabel: { color: "#d7e3ef", fontSize: 11, width: 120, overflow: "truncate" },
      axisTick: { show: false },
      axisLine: { show: false },
    },
    series: [
      {
        type: "bar",
        data: items.map((item) => ({
          value: item.numeric || 0,
          itemStyle: {
            color: item.tone || "#8fb8ff",
            borderRadius: [0, 10, 10, 0],
          },
        })),
        label: {
          show: true,
          position: "right",
          color: "#f8fbff",
          fontSize: 11,
          formatter: ({ dataIndex }) => items[dataIndex]?.value || "",
        },
        barWidth: 14,
      },
    ],
  };

  return (
    <div className="chart-block chart-block--echarts">
      {title || subtitle ? (
        <div className="chart-block__header">
          {title ? <h3>{title}</h3> : null}
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      ) : null}
      <ReactECharts option={option} style={{ height: 260, width: "100%" }} opts={{ renderer: "svg" }} />
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

const GLOBAL_POINTS = {
  "North America": { x: 19, y: 32 },
  "South America": { x: 28, y: 69 },
  Europe: { x: 50, y: 24 },
  Africa: { x: 51, y: 55 },
  "Middle East": { x: 59, y: 39 },
  Asia: { x: 73, y: 35 },
  Oceania: { x: 84, y: 73 },
};

function inferRegionFromText(value) {
  const text = String(value || "").toLowerCase();
  if (!text) return "Europe";
  if (text.includes("usa") || text.includes("canada") || text.includes("new york") || text.includes("california")) return "North America";
  if (text.includes("brazil") || text.includes("argentina") || text.includes("colombia") || text.includes("latam")) return "South America";
  if (text.includes("uk") || text.includes("london") || text.includes("germany") || text.includes("france") || text.includes("europe")) return "Europe";
  if (text.includes("ethiopia") || text.includes("kenya") || text.includes("nigeria") || text.includes("africa")) return "Africa";
  if (text.includes("uae") || text.includes("dubai") || text.includes("saudi") || text.includes("middle east")) return "Middle East";
  if (text.includes("india") || text.includes("singapore") || text.includes("japan") || text.includes("china") || text.includes("asia")) return "Asia";
  if (text.includes("australia") || text.includes("oceania")) return "Oceania";
  return "Europe";
}

function regionForFinding(finding) {
  return inferRegionFromText(
    [finding?.asset_name, finding?.asset_identifier, finding?.target, finding?.source, finding?.title].filter(Boolean).join(" ")
  );
}

function curvedPath(from, to) {
  const curveX = (from.x + to.x) / 2;
  const curveY = Math.min(from.y, to.y) - Math.abs(to.x - from.x) * 0.18 - 6;
  return `M ${from.x} ${from.y} Q ${curveX} ${curveY} ${to.x} ${to.y}`;
}

function buildAttackMapItems({ incidents, monitoringEvents, findings }) {
  const eventItems = (monitoringEvents || []).slice(0, 8).map((event, index) => ({
    key: `event-${event.id || index}`,
    label: event?.description || event?.rule_name || "Suspicious activity observed",
    sourceRegion: inferRegionFromText(event?.source || event?.rule_name || event?.description || `source-${index}`),
    targetRegion: inferRegionFromText(event?.asset_identifier || event?.asset_name || event?.description || `target-${index}`),
    severity: String(event?.severity || "medium").toLowerCase(),
    to: "/scans",
    type: "Monitoring event",
  }));

  const incidentItems = (incidents || []).slice(0, 6).map((incident, index) => ({
    key: `incident-${incident.id || index}`,
    label: incident?.title || incident?.summary || "Escalated incident",
    sourceRegion: inferRegionFromText(incident?.title || incident?.summary || incident?.status || `incident-${index}`),
    targetRegion: inferRegionFromText(incident?.affected_asset || incident?.summary || incident?.title || `incident-target-${index}`),
    severity: String(incident?.severity || "high").toLowerCase(),
    to: "/findings",
    type: "Incident",
  }));

  const findingItems = (findings || [])
    .filter((finding) => ["critical", "high"].includes(String(finding?.severity || "").toLowerCase()))
    .slice(0, 8)
    .map((finding, index) => ({
      key: `finding-${finding.id || index}`,
      label: finding?.title || "High-risk finding",
      sourceRegion: finding?.source === "zap" ? "North America" : inferRegionFromText(finding?.source),
      targetRegion: regionForFinding(finding),
      severity: String(finding?.severity || "high").toLowerCase(),
      to: "/findings",
      type: sourceLabel(finding?.source),
    }));

  return [...eventItems, ...incidentItems, ...findingItems].slice(0, 12);
}

function GlobalAttackMap({ incidents, monitoringEvents, findings }) {
  const [activeIndex, setActiveIndex] = useState(0);
  const items = useMemo(
    () => buildAttackMapItems({ incidents, monitoringEvents, findings }),
    [incidents, monitoringEvents, findings]
  );

  useEffect(() => {
    if (!items.length) return undefined;
    const interval = window.setInterval(() => {
      setActiveIndex((current) => (current + 1) % items.length);
    }, 2600);
    return () => window.clearInterval(interval);
  }, [items]);

  const activeItem = items[activeIndex] || null;
  const regionCounts = items.reduce((accumulator, item) => {
    accumulator[item.targetRegion] = (accumulator[item.targetRegion] || 0) + 1;
    return accumulator;
  }, {});

  return (
    <div className="attack-map">
      <div className="attack-map__visual">
        <div className="attack-map__frame">
          <svg className="attack-map__svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
            <path className="attack-map__land" d="M8 28 C14 20, 22 18, 28 20 C30 27, 25 35, 18 37 C12 36, 9 32, 8 28 Z" />
            <path className="attack-map__land" d="M22 48 C28 44, 34 48, 35 57 C33 68, 28 75, 24 80 C20 74, 19 59, 22 48 Z" />
            <path className="attack-map__land" d="M41 18 C48 14, 58 15, 64 19 C63 26, 55 31, 48 30 C44 27, 42 23, 41 18 Z" />
            <path className="attack-map__land" d="M46 37 C51 34, 58 38, 60 47 C56 58, 50 66, 45 71 C42 63, 43 48, 46 37 Z" />
            <path className="attack-map__land" d="M59 20 C69 15, 82 18, 89 25 C88 35, 78 40, 70 39 C64 35, 60 29, 59 20 Z" />
            <path className="attack-map__land" d="M77 64 C81 61, 87 64, 90 71 C87 77, 82 80, 77 78 C75 74, 75 68, 77 64 Z" />
            {items.map((item, index) => {
              const from = GLOBAL_POINTS[item.sourceRegion];
              const to = GLOBAL_POINTS[item.targetRegion];
              if (!from || !to) return null;
              return (
                <path
                  key={item.key}
                  className={`attack-map__arc ${index === activeIndex ? "is-active" : ""} attack-map__arc--${item.severity}`}
                  d={curvedPath(from, to)}
                  style={{ "--attack-delay": `${index * 180}ms` }}
                />
              );
            })}
            {Object.entries(GLOBAL_POINTS).map(([region, point]) => (
              <g key={region}>
                <circle
                  className={`attack-map__node ${activeItem?.targetRegion === region || activeItem?.sourceRegion === region ? "is-active" : ""}`}
                  cx={point.x}
                  cy={point.y}
                  r="1.8"
                />
                <text className="attack-map__label" x={point.x + 1.6} y={point.y - 1.8}>
                  {region}
                </text>
              </g>
            ))}
          </svg>
          <div className="attack-map__ticker">
            {activeItem ? (
              <Link className="attack-map__ticker-card" to={activeItem.to}>
                <span>{activeItem.type}</span>
                <strong>{activeItem.label}</strong>
                <small>
                  {activeItem.sourceRegion} to {activeItem.targetRegion}
                </small>
              </Link>
            ) : (
              <div className="attack-map__ticker-card">
                <span>Live activity</span>
                <strong>No active attack telemetry yet</strong>
                <small>New monitoring events and findings will appear here automatically.</small>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="attack-map__sidebar">
        <h3>Regional pressure</h3>
        <div className="attack-map__regions">
          {Object.entries(regionCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([region, count]) => (
              <div className="attack-map__region-row" key={region}>
                <span>{region}</span>
                <strong>{count}</strong>
              </div>
            ))}
          {!Object.keys(regionCounts).length ? <p className="empty-copy">No active regional activity to render.</p> : null}
        </div>
      </div>
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
            {summary.metrics.map((metric) => (
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
    "vuln-trends": { title: "Vulnerability Trends Over Time", render: () => <TargetSeverityPie breakdown={summary.target_severity_breakdown} /> },
    "global-attack-map": {
      title: "Global Live Attack Map",
      render: () => <GlobalAttackMap incidents={incidents} monitoringEvents={monitoringEvents} findings={findings} />,
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
        threatIntel.misp_events?.slice(0, 5).length
          ? threatIntel.misp_events.slice(0, 5).map((event) => ({
              key: event.id,
              label: event.name,
              value: event.description || `${event.indicator_count} indicators`,
              to: "/threat-intelligence",
            }))
          : threatIntel.top_feed.slice(0, 5).map((item) => ({
              key: item.finding_id,
              label: item.title,
              value: item.exploit_indicator,
              to: "/threat-intelligence",
            }))
      } emptyMessage="Configure MISP feeds to show the latest external threat events here." />,
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
        { key: "misp-status", label: "MISP status", value: `${threatIntel.misp_status || "not_configured"}`, numeric: threatIntel.misp_status === "connected" ? 1 : 0, to: "/threat-intelligence", tone: "#4fd1c5" },
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

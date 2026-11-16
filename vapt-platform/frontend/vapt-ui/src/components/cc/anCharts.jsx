import { useMemo, useRef } from "react";
import * as echarts from "echarts";
import { useEChart } from "./ccHooks";

const AXIS = { color: "#7f93ad", fontFamily: "IBM Plex Mono, monospace", fontSize: 11 };
const GRID_LINE = { lineStyle: { color: "rgba(92,225,255,0.08)" } };
const TOOLTIP = { backgroundColor: "#0b1730", borderColor: "#1f3a63", textStyle: { color: "#e6edf3" } };
const LEGEND = { top: 0, right: 0, itemWidth: 10, itemHeight: 6, textStyle: { color: "#9fb2c8", fontSize: 11 } };
const SEV_CSS = { critical: "#ff6b6b", high: "#ff9f5a", medium: "#f5d76e", low: "#8a99ab" };
const RISK = ["critical", "high", "medium", "low"];

const shortDate = (iso) => {
  const d = new Date(`${iso}T00:00:00`);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString([], { day: "2-digit", month: "short" });
};

/** Open backlog at the end of each bucket (line) with findings opened and closed (bars). */
export function BacklogChart({ labels, backlog }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    grid: { left: 40, right: 40, top: 30, bottom: 26 },
    tooltip: { trigger: "axis", ...TOOLTIP },
    legend: LEGEND,
    xAxis: { type: "category", data: labels.map(shortDate), axisLabel: AXIS, axisLine: { lineStyle: { color: "#1f3a63" } } },
    yAxis: [
      { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: GRID_LINE },
      { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: { show: false } },
    ],
    series: [
      { name: "Opened", type: "bar", yAxisIndex: 1, barMaxWidth: 14, itemStyle: { color: "rgba(255,159,90,0.55)" }, data: backlog.opened },
      { name: "Closed", type: "bar", yAxisIndex: 1, barMaxWidth: 14, itemStyle: { color: "rgba(61,220,151,0.7)" }, data: backlog.closed },
      {
        name: "Open backlog",
        type: "line",
        smooth: true,
        symbol: "circle",
        symbolSize: 5,
        lineStyle: { width: 2.5, color: "#5ce1ff", shadowColor: "#5ce1ff", shadowBlur: 10 },
        itemStyle: { color: "#5ce1ff" },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: "rgba(92,225,255,0.35)" },
            { offset: 1, color: "rgba(92,225,255,0.02)" },
          ]),
        },
        data: backlog.open,
      },
    ],
  }), [labels, backlog]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart an-chart--tall" role="img" aria-label="Open backlog over time with findings opened and closed" />;
}

/** SLA status per severity: within SLA, due within 7 days, overdue. */
export function SlaChart({ sla }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    grid: { left: 70, right: 16, top: 30, bottom: 10, containLabel: false },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...TOOLTIP },
    legend: LEGEND,
    xAxis: { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: GRID_LINE },
    yAxis: { type: "category", inverse: true, data: RISK, axisLabel: { ...AXIS, color: "#9fb2c8" }, axisLine: { lineStyle: { color: "#1f3a63" } } },
    series: [
      ["within", "Within SLA", "#3ddc97"],
      ["due_soon", "Due ≤ 7 days", "#f5d76e"],
      ["overdue", "Overdue", "#ff6b6b"],
    ].map(([key, name, color]) => ({
      name,
      type: "bar",
      stack: "sla",
      barMaxWidth: 18,
      itemStyle: { color },
      data: RISK.map((s) => sla[s]?.[key] || 0),
    })),
  }), [sla]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart an-chart--short" role="img" aria-label="SLA status by severity" />;
}

/** How long open findings have been waiting, stacked by severity. */
export function AgeChart({ age }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    grid: { left: 40, right: 12, top: 30, bottom: 26 },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...TOOLTIP },
    legend: LEGEND,
    xAxis: { type: "category", data: age.labels, axisLabel: AXIS, axisLine: { lineStyle: { color: "#1f3a63" } } },
    yAxis: { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: GRID_LINE },
    series: RISK.map((sev) => ({
      name: sev,
      type: "bar",
      stack: "age",
      barMaxWidth: 34,
      itemStyle: { color: SEV_CSS[sev] },
      data: age.series[sev] || [],
    })),
  }), [age]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart" role="img" aria-label="Open findings by age and severity" />;
}

/** Scans per bucket, completed vs failed. */
export function ScanActivityChart({ labels, series }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    grid: { left: 34, right: 12, top: 30, bottom: 26 },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, ...TOOLTIP },
    legend: LEGEND,
    xAxis: { type: "category", data: labels.map(shortDate), axisLabel: AXIS, axisLine: { lineStyle: { color: "#1f3a63" } } },
    yAxis: { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: GRID_LINE },
    series: [
      { name: "Completed", type: "bar", stack: "s", barMaxWidth: 16, itemStyle: { color: "#2e7bff" }, data: series.completed },
      { name: "Failed", type: "bar", stack: "s", barMaxWidth: 16, itemStyle: { color: "#ff6b6b" }, data: series.failed },
    ],
  }), [labels, series]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart" role="img" aria-label="Scans per period, completed and failed" />;
}

/** Radar of open configuration issues per control family. */
export function FamilyRadar({ families }) {
  const ref = useRef(null);
  const option = useMemo(() => {
    const max = Math.max(1, ...families.map((f) => f.open));
    return {
      tooltip: { trigger: "item", ...TOOLTIP },
      radar: {
        radius: "66%",
        center: ["50%", "54%"],
        indicator: families.map((f) => ({ name: f.label, max })),
        axisName: { color: "#9fb2c8", fontSize: 11 },
        splitArea: { areaStyle: { color: ["rgba(46,123,255,0.04)", "rgba(46,123,255,0.08)"] } },
        splitLine: { lineStyle: { color: "rgba(92,225,255,0.15)" } },
        axisLine: { lineStyle: { color: "rgba(92,225,255,0.2)" } },
      },
      series: [
        {
          type: "radar",
          name: "Open issues",
          symbolSize: 5,
          lineStyle: { color: "#5ce1ff", width: 2, shadowColor: "#5ce1ff", shadowBlur: 10 },
          itemStyle: { color: "#5ce1ff" },
          areaStyle: { color: "rgba(92,225,255,0.22)" },
          data: [{ value: families.map((f) => f.open), name: "Open issues" }],
        },
      ],
    };
  }, [families]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart an-chart--tall" role="img" aria-label="Open configuration issues per control family" />;
}

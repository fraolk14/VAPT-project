import { useMemo, useRef } from "react";
import * as echarts from "echarts";
import { useEChart } from "./ccHooks";

const AXIS = { color: "#7f93ad", fontFamily: "IBM Plex Mono, monospace", fontSize: 11 };
const GRID_LINE = { lineStyle: { color: "rgba(92,225,255,0.08)" } };
const RING_PALETTE = ["#5ce1ff", "#2e7bff", "#ff9f5a", "#f5d76e", "#3ddc97", "#a78bfa", "#4f6378"];
const SEV_CSS = { critical: "#ff6b6b", high: "#ff9f5a", medium: "#f5d76e", low: "#8a99ab", info: "#4f6378" };

/** Findings detected per time bucket, stacked by severity. Built from real detected_at values. */
export function DetectionTrend({ buckets }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    grid: { left: 36, right: 14, top: 26, bottom: 26 },
    tooltip: { trigger: "axis", backgroundColor: "#0b1730", borderColor: "#1f3a63", textStyle: { color: "#e6edf3" } },
    legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 6, textStyle: { color: "#9fb2c8", fontSize: 11 } },
    xAxis: { type: "category", boundaryGap: false, data: buckets.labels, axisLabel: AXIS, axisLine: { lineStyle: { color: "#1f3a63" } } },
    yAxis: { type: "value", minInterval: 1, axisLabel: AXIS, splitLine: GRID_LINE },
    series: ["critical", "high", "medium", "low"].map((sev) => ({
      name: sev,
      type: "line",
      stack: "sev",
      smooth: true,
      symbol: "none",
      lineStyle: { width: 1.5, color: SEV_CSS[sev] },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: `${SEV_CSS[sev]}aa` },
          { offset: 1, color: `${SEV_CSS[sev]}08` },
        ]),
      },
      emphasis: { focus: "series" },
      data: buckets.series[sev],
    })),
  }), [buckets]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart" role="img" aria-label="Findings detected over time, by severity" />;
}

/** Ring chart of the most common open issue types, with an HTML legend underneath. */
export function IssueRing({ items, total }) {
  const ref = useRef(null);
  const option = useMemo(() => ({
    tooltip: { trigger: "item", backgroundColor: "#0b1730", borderColor: "#1f3a63", textStyle: { color: "#e6edf3" } },
    title: {
      text: String(total),
      subtext: "issue types",
      left: "center",
      top: "36%",
      textStyle: { color: "#e6edf3", fontSize: 24, fontWeight: 700, fontFamily: "IBM Plex Sans" },
      subtextStyle: { color: "#7f93ad", fontSize: 11 },
    },
    series: [
      {
        type: "pie",
        radius: ["62%", "80%"],
        center: ["50%", "50%"],
        padAngle: 2,
        itemStyle: { borderRadius: 3 },
        label: { show: false },
        data: items.map((item, index) => ({ ...item, itemStyle: { color: RING_PALETTE[index % RING_PALETTE.length] } })),
      },
      {
        type: "pie",
        radius: ["86%", "88%"],
        center: ["50%", "50%"],
        silent: true,
        label: { show: false },
        data: [{ value: 1, itemStyle: { color: "rgba(92,225,255,0.25)" } }],
      },
    ],
  }), [items, total]);
  useEChart(ref, option);
  return (
    <>
      <div ref={ref} className="cc-chart cc-chart--ring" role="img" aria-label="Most common open issue types" />
      <ul className="cc-ring-legend">
        {items.map((item, index) => (
          <li key={item.name}>
            <span className="cc-swatch" style={{ background: RING_PALETTE[index % RING_PALETTE.length] }} />
            <span className="cc-ring-legend__name" title={item.name}>{item.name}</span>
            <span className="cc-mono">{item.value}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

/** Severity counts drawn as glowing cones (peaks). */
export function SeverityPeaks({ counts }) {
  const ref = useRef(null);
  const option = useMemo(() => {
    const sevs = ["critical", "high", "medium", "low", "info"];
    return {
      grid: { left: 8, right: 8, top: 28, bottom: 24 },
      tooltip: { trigger: "item", backgroundColor: "#0b1730", borderColor: "#1f3a63", textStyle: { color: "#e6edf3" } },
      xAxis: {
        type: "category",
        data: sevs,
        axisTick: { show: false },
        axisLine: { lineStyle: { color: "#1f3a63" } },
        axisLabel: { ...AXIS, color: "#9fb2c8" },
      },
      yAxis: { show: false },
      series: [
        {
          type: "pictorialBar",
          barCategoryGap: "-35%",
          symbol: "path://M0,10 L10,10 C5.5,10 5.5,5 5,0 C4.5,5 4.5,10 0,10 z",
          label: { show: true, position: "top", color: "#e6edf3", fontFamily: "IBM Plex Mono", fontSize: 12 },
          data: sevs.map((sev) => ({
            value: counts[sev] || 0,
            itemStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: SEV_CSS[sev] },
                { offset: 1, color: `${SEV_CSS[sev]}22` },
              ]),
              opacity: 0.95,
            },
          })),
        },
      ],
    };
  }, [counts]);
  useEChart(ref, option);
  return <div ref={ref} className="cc-chart" role="img" aria-label="Open issues by severity" />;
}

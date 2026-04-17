import { useEffect, useMemo, useState } from "react";

import api from "../api/client";

const MODES = [
  {
    key: "assistant",
    label: "Chat Assistant",
    description: "Ask concise technical questions about findings, prioritization, and next actions.",
    placeholder: "Example: Summarize the selected findings, explain the highest-risk issue, and recommend the best remediation order.",
    outcome: "Interactive operator guidance based on selected findings and current platform context.",
  },
  {
    key: "explain",
    label: "Vulnerability Explanation",
    description: "Translate scanner results into clear engineering language with impact and exploitation context.",
    placeholder: "Example: Explain this vulnerability for the engineering team and highlight how it could be exploited.",
    outcome: "Engineer-ready explanation with impact and technical interpretation.",
  },
  {
    key: "recommend",
    label: "Recommendations",
    description: "Generate practical remediation actions and validation steps.",
    placeholder: "Example: Provide the most effective remediation steps and validation plan for the selected findings.",
    outcome: "Action-oriented remediation guidance and validation sequencing.",
  },
  {
    key: "risk",
    label: "Risk Explanation",
    description: "Describe business and technical risk for triage meetings and stakeholder reviews.",
    placeholder: "Example: Explain the business impact, technical risk, and why these findings matter now.",
    outcome: "Risk narrative suitable for security and leadership review.",
  },
  {
    key: "compliance",
    label: "Compliance Guidance",
    description: "Map findings to controls and evidence expectations.",
    placeholder: "Example: Explain the compliance impact and what evidence should be captured after remediation.",
    outcome: "Control-aware guidance for audit and governance workflows.",
  },
  {
    key: "report",
    label: "Report Generation",
    description: "Create concise report-ready summaries for remediation and executive communication.",
    placeholder: "Example: Generate a concise report section covering the selected findings, priorities, and remediation status.",
    outcome: "Report-ready summary for formal deliverables and status updates.",
  },
];

function findingLabel(finding) {
  const target = finding.finding_metadata?.url || finding.finding_metadata?.host || finding.finding_metadata?.file || "target";
  return `${finding.title} · ${target}`;
}

function severityClass(severity) {
  return `pill pill--${(severity || "info").toLowerCase()}`;
}

function severityWeight(severity) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[(severity || "info").toLowerCase()] || 0;
}

function deriveStructuredInput(finding) {
  const metadata = finding?.finding_metadata || {};
  const target = metadata.url || metadata.host || metadata.file || "Unknown target";
  const assetType = finding?.source === "zap" ? "Web Application" : finding?.source === "openvas" ? "Host / Service" : "Mobile Application";
  const exposure = finding?.source === "openvas" && metadata.host ? "External" : finding?.source === "zap" ? "External" : "Internal";
  return {
    cve: finding?.cve_id || null,
    cvss: finding?.cvss_score || null,
    asset: {
      criticality: finding?.severity === "critical" ? "Critical" : finding?.severity === "high" ? "High" : "Medium",
      type: assetType,
      exposure,
    },
    vulnerability: finding?.title || "Vulnerability",
    scan_details: [finding?.evidence, finding?.remediation, target].filter(Boolean).join(" | "),
    exploit_available: ["critical", "high"].includes((finding?.severity || "").toLowerCase()),
    source: finding?.source || null,
    references: [finding?.cve_id].filter(Boolean),
  };
}

function renderStructuredResponse(mode, payload) {
  if (!payload) return "";
  if (mode === "risk") {
    return [
      "# Risk Prioritization",
      "",
      `Risk score: ${payload.risk_score}`,
      `Priority: ${payload.priority}`,
      "",
      payload.reason,
    ].join("\n");
  }
  if (mode === "explain") {
    return [
      "# Vulnerability Explanation",
      "",
      `Summary: ${payload.summary}`,
      "",
      `Impact: ${payload.impact}`,
      "",
      `Exploitation: ${payload.exploitation}`,
      "",
      `Technical details: ${payload.technical_details}`,
    ].join("\n");
  }
  if (mode === "recommend") {
    return [
      "# Recommendations",
      "",
      "Remediation steps:",
      ...(payload.remediation_steps || []).map((step, index) => `${index + 1}. ${step}`),
      "",
      `Configuration fix: ${payload.configuration_fix}`,
      "",
      `Patches: ${(payload.patches || []).join(", ") || "No direct patch guidance returned."}`,
    ].join("\n");
  }
  if (mode === "compliance") {
    return [
      "# Compliance Guidance",
      "",
      "Remediation steps:",
      ...(payload.remediation_steps || []).map((step, index) => `${index + 1}. ${step}`),
      "",
      `Configuration fix: ${payload.configuration_fix}`,
      "",
      "Capture remediation evidence, validation timestamps, and ownership updates after the fix is applied.",
    ].join("\n");
  }
  return "";
}

export default function AIRemediation({ findings, scans, compliance }) {
  const [mode, setMode] = useState("assistant");
  const [prompt, setPrompt] = useState("");
  const [selectedFindingIds, setSelectedFindingIds] = useState([]);
  const [response, setResponse] = useState("");
  const [status, setStatus] = useState("idle");
  const [finderOpen, setFinderOpen] = useState(false);
  const [finderQuery, setFinderQuery] = useState("");
  const [aiStatus, setAiStatus] = useState({
    available: true,
    provider: "local-fallback",
    model: "deterministic-local-engine",
    status: "fallback_ready",
    capabilities: [],
    setup_hint: "",
  });
  const [responseMeta, setResponseMeta] = useState({
    provider: "local-fallback",
    model: "deterministic-local-engine",
  });

  const activeMode = useMemo(
    () => MODES.find((item) => item.key === mode) || MODES[0],
    [mode],
  );

  const selectableFindings = useMemo(() => findings.slice(0, 40), [findings]);
  const filteredFindings = useMemo(() => {
    const query = finderQuery.trim().toLowerCase();
    if (!query) return selectableFindings;
    return selectableFindings.filter((finding) => {
      const haystack = `${finding.title} ${finding.cve_id || ""} ${finding.finding_metadata?.url || ""} ${finding.finding_metadata?.host || ""} ${finding.finding_metadata?.file || ""}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [finderQuery, selectableFindings]);
  const selectedFindings = useMemo(
    () => selectableFindings.filter((finding) => selectedFindingIds.includes(finding.id)),
    [selectableFindings, selectedFindingIds],
  );
  const leadFinding = useMemo(
    () => [...selectedFindings].sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity))[0] || null,
    [selectedFindings],
  );

  useEffect(() => {
    api.get("/ai/status").then((result) => {
      setAiStatus(result.data);
    }).catch(() => {
      setAiStatus({
        available: true,
        provider: "local-fallback",
        model: "deterministic-local-engine",
        status: "fallback_ready",
        capabilities: [],
        setup_hint: "AI status could not be loaded. Local remediation guidance remains available.",
      });
    });
  }, []);

  useEffect(() => {
    setPrompt(activeMode.placeholder);
  }, [activeMode]);

  const toggleFinding = (findingId) => {
    setSelectedFindingIds((current) => (
      current.includes(findingId)
        ? current.filter((item) => item !== findingId)
        : [...current, findingId]
    ));
  };

  const clearSelection = () => {
    setSelectedFindingIds([]);
    setFinderQuery("");
  };

  const runAssistant = async () => {
    setStatus("loading");
    try {
      if (mode === "assistant" || mode === "report") {
        const result = await api.post("/ai/assist", {
          mode,
          prompt,
          finding_ids: selectedFindingIds,
          context: {
            total_scans: scans.length,
            total_findings: findings.length,
            compliance_frameworks: Object.keys(compliance?.frameworks || {}),
          },
        });
        setResponse(result.data.content);
        setResponseMeta({
          provider: result.data.provider || "local-fallback",
          model: result.data.model || "deterministic-local-engine",
        });
      } else {
        if (!leadFinding) {
          setResponse("Select at least one finding to run this analysis mode.");
          setResponseMeta({ provider: "unavailable", model: "n/a" });
          setStatus("error");
          return;
        }
        const input = deriveStructuredInput(leadFinding);
        const endpoint =
          mode === "risk"
            ? "/ai/risk-score"
            : mode === "explain"
              ? "/ai/explain"
              : "/ai/remediation";
        const result = await api.post(endpoint, input);
        setResponse(renderStructuredResponse(mode, result.data.data));
        setResponseMeta({
          provider: result.data.provider || "local-fallback",
          model: result.data.model || "deterministic-local-engine",
        });
      }
      setStatus("ready");
    } catch (error) {
      setResponse(error?.response?.data?.detail || "AI remediation is unavailable right now.");
      setResponseMeta({
        provider: "unavailable",
        model: "n/a",
      });
      setStatus("error");
    }
  };

  return (
    <section className="section-grid">
      <section className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">AI-driven remediation</p>
            <h2>AI Remediation</h2>
          </div>
          <div className="ai-status">
            <span className={`pill ${aiStatus.provider === "gemini" ? "pill--critical" : "pill--info"}`}>
              {aiStatus.provider === "gemini" ? "Gemini Active" : "Fallback Guidance"}
            </span>
            <span>{aiStatus.model}</span>
          </div>
        </div>

        <div className="ai-remediation-shell">
          <section className="ai-remediation-primary">
            <div className="ai-command-bar">
              <div>
                <p className="eyebrow">Mode</p>
                <strong>{activeMode.label}</strong>
                <p className="empty-copy empty-copy--left">{activeMode.outcome}</p>
              </div>
              <button
                type="button"
                className="scan-action"
                onClick={() => setFinderOpen((current) => !current)}
              >
                {finderOpen ? "Hide finding selector" : "Choose findings"}
              </button>
            </div>

            <div className="subtabs">
              {MODES.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={mode === item.key ? "subtab is-active" : "subtab"}
                  onClick={() => setMode(item.key)}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="ai-mode-brief">
              <p className="eyebrow">Mode brief</p>
              <h3>{activeMode.label}</h3>
              <p>{activeMode.description}</p>
            </div>

            {finderOpen ? (
              <div className="ai-finder-panel">
                <div className="panel__header">
                  <div>
                    <p className="eyebrow">Selection category</p>
                    <h3>Finding selector</h3>
                  </div>
                  <div className="scan-actions">
                    <button type="button" className="scan-action" onClick={clearSelection}>Clear</button>
                    <button type="button" className="scan-action scan-action--resume" onClick={() => setFinderOpen(false)}>Done</button>
                  </div>
                </div>
                <input
                  className="scan-input"
                  value={finderQuery}
                  onChange={(event) => setFinderQuery(event.target.value)}
                  placeholder="Search by title, CVE, host, URL, or file"
                />
                <div className="ai-finder-list">
                  {filteredFindings.map((finding) => (
                    <label key={finding.id} className="ai-finder-item">
                      <input
                        type="checkbox"
                        checked={selectedFindingIds.includes(finding.id)}
                        onChange={() => toggleFinding(finding.id)}
                      />
                      <div className="ai-finder-item__copy">
                        <strong>{finding.title}</strong>
                        <p>{findingLabel(finding)}</p>
                      </div>
                      <span className={severityClass(finding.severity)}>{finding.severity || "info"}</span>
                    </label>
                  ))}
                  {!filteredFindings.length ? <p className="empty-copy">No findings match the current search.</p> : null}
                </div>
              </div>
            ) : null}

            <div className="ai-selection-summary">
              <div>
                <p className="eyebrow">Selected context</p>
                <strong>{selectedFindingIds.length} findings selected</strong>
                <p className="empty-copy empty-copy--left">
                  Only selected findings are used as analysis context for assistant, explanation, recommendations, risk, compliance, and report workflows.
                </p>
                {mode !== "assistant" && mode !== "report" && leadFinding ? (
                  <p className="empty-copy empty-copy--left">
                    Structured analysis currently uses the highest-priority selected finding as the primary context.
                  </p>
                ) : null}
              </div>
              <div className="chip-grid">
                {selectedFindings.slice(0, 4).map((finding) => (
                  <span key={finding.id} className="severity-chip">
                    {finding.title}
                  </span>
                ))}
                {selectedFindingIds.length > 4 ? <span className="severity-chip">+{selectedFindingIds.length - 4} more</span> : null}
              </div>
            </div>

            {aiStatus.setup_hint ? <p className="panel-note">{aiStatus.setup_hint}</p> : null}

            <div className="ai-workbench">
              <textarea
                className="scan-input ai-textarea ai-textarea--pro"
                value={prompt}
                onChange={(event) => setPrompt(event.target.value)}
                placeholder={activeMode.placeholder}
              />
              <div className="ai-workbench__actions">
                <div className="ai-overview-grid">
                  <article className="metric-card">
                    <span>Provider</span>
                    <strong>{aiStatus.provider}</strong>
                    <p>{aiStatus.status.replaceAll("_", " ")}</p>
                  </article>
                  <article className="metric-card">
                    <span>Scope</span>
                    <strong>{selectedFindingIds.length}</strong>
                    <p>Findings in current analysis context</p>
                  </article>
                  <article className="metric-card">
                    <span>Capabilities</span>
                    <strong>{aiStatus.capabilities.length || 6}</strong>
                    <p>{aiStatus.capabilities.slice(0, 3).join(", ") || "Explanation, remediation, reporting"}</p>
                  </article>
                </div>
                <button type="button" className="scan-action scan-action--resume ai-run-button" onClick={runAssistant}>
                  {status === "loading" ? "Analyzing..." : `Run ${activeMode.label}`}
                </button>
              </div>
            </div>
          </section>

          <section className="panel ai-response-panel">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Generated guidance</p>
                <h2>{activeMode.label} output</h2>
              </div>
              <div className="ai-status">
                <span className="topbar__user-label">Source</span>
                <strong>{responseMeta.provider}</strong>
              </div>
            </div>

            <div className="ai-response-stage">
              <div className="developer-code developer-code--block ai-response-copy">
                {response || "Run an AI workflow to generate focused vulnerability explanation, remediation guidance, risk analysis, compliance guidance, or report-ready content."}
              </div>
            </div>

            <div className="ai-response-meta">
              <div className="coverage-row">
                <span>Model</span>
                <strong>{responseMeta.model}</strong>
              </div>
              <div className="coverage-row">
                <span>Mode</span>
                <strong>{activeMode.label}</strong>
              </div>
              <div className="coverage-row">
                <span>Selected findings</span>
                <strong>{selectedFindingIds.length}</strong>
              </div>
            </div>
          </section>
        </div>
      </section>
    </section>
  );
}

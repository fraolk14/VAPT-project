import { useEffect, useMemo, useState } from "react";

import api from "../api/client";
import Card from "../components/Card";

function sourceLabel(source) {
  if (source === "openvas") return "Network Engine";
  if (source === "zap") return "Web Engine";
  if (source === "mobsf") return "Mobile Engine";
  return source;
}

export default function ThreatIntelligence({ threatIntel }) {
  const [filters, setFilters] = useState({
    severity: "all",
    source: "all",
    exploitedOnly: false,
    pageSize: 10,
    pageIndex: 0,
  });
  const [feedState, setFeedState] = useState({
    status: "idle",
    items: threatIntel.top_feed || [],
    total: threatIntel.top_feed?.length || 0,
  });

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.severity !== "all") params.set("severity", filters.severity);
    if (filters.source !== "all") params.set("source", filters.source);
    if (filters.exploitedOnly) params.set("exploited_only", "true");

    setFeedState((current) => ({ ...current, status: "loading" }));
    api.get(`/threat-intelligence/feed?${params.toString()}`).then((response) => {
      setFeedState({ status: "ready", items: response.data.items, total: response.data.total });
    }).catch(() => {
      setFeedState((current) => ({ ...current, status: "error" }));
    });
  }, [filters.severity, filters.source, filters.exploitedOnly]);

  useEffect(() => {
    setFilters((current) => ({ ...current, pageIndex: 0 }));
  }, [filters.pageSize, filters.severity, filters.source, filters.exploitedOnly]);

  const topMitre = useMemo(() => Object.entries(threatIntel.mitre_coverage || {}).slice(0, 6), [threatIntel.mitre_coverage]);
  const feedSources = useMemo(() => Object.entries(threatIntel.reference_coverage || {}), [threatIntel.reference_coverage]);
  const externalEvents = useMemo(() => threatIntel.external_events || [], [threatIntel.external_events]);
  const visibleItems = useMemo(
    () => feedState.items.slice(filters.pageIndex * filters.pageSize, filters.pageIndex * filters.pageSize + filters.pageSize),
    [feedState.items, filters.pageIndex, filters.pageSize]
  );
  const totalPages = Math.max(1, Math.ceil(feedState.items.length / filters.pageSize));

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">External threat context</p>
            <h2>Threat intelligence</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Enriched Findings" value={threatIntel.total_enriched} trend="Current findings mapped to external context" />
          <Card title="Exploit Available" value={threatIntel.exploit_available} trend="Likely public exploit path exists" />
          <Card title="Actively Exploited" value={threatIntel.actively_exploited} trend="Prioritize for immediate action" />
          <Card title="Feed Sources" value={feedSources.length || 0} trend="NVD, MITRE, CISA KEV, Exploit-DB coverage" />
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Open threat feeds</p>
            <h2>Latest external threats</h2>
          </div>
        </div>
        <div className="dashboard-toolbar threat-toolbar">
          <div className="threat-toolbar__summary"><span>Feed status</span><strong>{threatIntel.external_feed_status || threatIntel.misp_status}</strong></div>
          <div className="threat-toolbar__summary"><span>Latest events</span><strong>{externalEvents.length || 0}</strong></div>
          <div className="threat-toolbar__summary"><span>Sources</span><strong>MISP / URLhaus / CISA / NVD</strong></div>
        </div>
        <div className="coverage-list">
          {externalEvents.length ? externalEvents.map((event) => (
            <a key={event.id} className="coverage-row coverage-row--link" href={event.url || event.references?.[0] || "#"} target="_blank" rel="noreferrer">
              <span>
                <strong>{event.name}</strong>
                <p>{event.description || "Threat event published by the connected intelligence source."}</p>
                <p>{event.matched_targets?.length ? `Matched targets: ${event.matched_targets.slice(0, 3).join(", ")}` : "No direct target match yet"}</p>
              </span>
              <strong>{event.source} / {event.indicator_count || 0} indicators / {event.matched_findings} matched finding(s)</strong>
            </a>
          )) : <p className="empty-copy">External feed items will appear here from the connected open-source threat intelligence sources.</p>}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Threat coverage</p>
            <h2>Source and ATT&CK mapping</h2>
          </div>
        </div>
        <div className="threat-grid">
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Feed sources</p>
                <h2>External references</h2>
              </div>
            </div>
            <div className="coverage-list">
              {feedSources.length ? feedSources.map(([source, count]) => (
                <div className="coverage-row" key={source}>
                  <span>{source}</span>
                  <strong>{count}</strong>
                </div>
              )) : <p className="empty-copy">Reference coverage will appear as findings are enriched.</p>}
            </div>
          </div>
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">MITRE ATT&CK</p>
                <h2>Observed techniques</h2>
              </div>
            </div>
            <div className="coverage-list">
              {topMitre.length ? topMitre.map(([technique, count]) => (
                <div className="coverage-row" key={technique}>
                  <span>{technique}</span>
                  <strong>{count}</strong>
                </div>
              )) : <p className="empty-copy">Technique mappings will appear as findings are enriched.</p>}
            </div>
          </div>
        </div>
      </div>

      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Live threat feed</p>
            <h2>Enriched findings</h2>
          </div>
        </div>
        <div className="dashboard-toolbar threat-toolbar">
          <select className="scan-select" value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select className="scan-select" value={filters.source} onChange={(event) => setFilters((current) => ({ ...current, source: event.target.value }))}>
            <option value="all">All engines</option>
            <option value="openvas">Network Engine</option>
            <option value="zap">Web Engine</option>
            <option value="mobsf">Mobile Engine</option>
          </select>
          <select className="scan-select" value={filters.pageSize} onChange={(event) => setFilters((current) => ({ ...current, pageSize: Number(event.target.value) }))}>
            <option value={10}>10 per page</option>
            <option value={20}>20 per page</option>
          </select>
          <label className="widget-selector__item">
            <input type="checkbox" checked={filters.exploitedOnly} onChange={(event) => setFilters((current) => ({ ...current, exploitedOnly: event.target.checked }))} />
            <span>Actively exploited only</span>
          </label>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Finding</th>
                <th>Target</th>
                <th>Engine</th>
                <th>Exploit Indicator</th>
                <th>MITRE</th>
                <th>Sources</th>
              </tr>
            </thead>
            <tbody>
              {visibleItems.map((item) => (
                <tr key={item.finding_id}>
                  <td data-label="Finding">
                    <strong>{item.title}</strong>
                    <p>{item.cve_id || "Mapping resolved through behavior and CWE references"}</p>
                  </td>
                  <td data-label="Target">{item.target}</td>
                  <td data-label="Engine">{sourceLabel(item.source)}</td>
                  <td data-label="Exploit Indicator"><span className={`pill pill--${item.actively_exploited ? "critical" : item.exploit_available ? "medium" : "info"}`}>{item.exploit_indicator}</span></td>
                  <td data-label="MITRE">{item.mitre_attack.join(", ") || "Mapping in progress"}</td>
                  <td data-label="Sources">
                    <div className="coverage-list">
                      {item.references.slice(0, 3).map((reference) => (
                        <a key={reference} className="target-link" href={reference} target="_blank" rel="noreferrer">{reference}</a>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
              {feedState.status === "loading" ? <tr><td colSpan="6"><p className="empty-copy">Refreshing threat feed...</p></td></tr> : null}
              {feedState.status !== "loading" && visibleItems.length === 0 ? <tr><td colSpan="6"><p className="empty-copy">Threat enrichment will appear here as findings accumulate.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
        <div className="pagination-bar">
          <span>Showing {visibleItems.length ? filters.pageIndex * filters.pageSize + 1 : 0}-{Math.min((filters.pageIndex + 1) * filters.pageSize, feedState.items.length)} of {feedState.items.length}</span>
          <div className="scan-actions">
            <button type="button" className="scan-action" disabled={filters.pageIndex === 0} onClick={() => setFilters((current) => ({ ...current, pageIndex: Math.max(current.pageIndex - 1, 0) }))}>Previous</button>
            <span className="pagination-page">Page {filters.pageIndex + 1} of {totalPages}</span>
            <button type="button" className="scan-action" disabled={filters.pageIndex >= totalPages - 1} onClick={() => setFilters((current) => ({ ...current, pageIndex: Math.min(current.pageIndex + 1, totalPages - 1) }))}>Next</button>
          </div>
        </div>
      </div>
    </section>
  );
}

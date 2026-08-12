import { useEffect, useMemo, useState, useRef } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import ForceGraph2D from "react-force-graph-2d";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";

import { 
  FaGlobe, 
  FaSearch, 
  FaShieldAlt, 
  FaBug, 
  FaNetworkWired, 
  FaServer, 
  FaExclamationTriangle, 
  FaMapMarkerAlt,
  FaTimes,
  FaFileAlt
} from "react-icons/fa";

import api from "../api/client";
import Card from "../components/Card";

// Initialize Query Client for page-level state queries
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function sourceLabel(source) {
  if (source === "openvas") return "Network Engine";
  if (source === "zap") return "Web Engine";
  if (source === "mobsf") return "Mobile Engine";
  return source;
}

function ThreatIntelligenceContent({ threatIntel }) {
  const [targetSearch, setTargetSearch] = useState("");
  const [activeTarget, setActiveTarget] = useState("");

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

  // Query details for active target search
  const { data: targetData, isFetching: isSearching, error: searchError, refetch } = useQuery({
    queryKey: ["targetThreatIntel", activeTarget],
    queryFn: async () => {
      if (!activeTarget) return null;
      const res = await api.get(`/threat-intelligence/${encodeURIComponent(activeTarget)}`);
      return res.data;
    },
    enabled: !!activeTarget,
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

  const feedSources = useMemo(() => Object.entries(threatIntel.reference_coverage || {}), [threatIntel.reference_coverage]);
  const externalEvents = useMemo(() => threatIntel.external_events || [], [threatIntel.external_events]);
  const visibleItems = useMemo(
    () => feedState.items.slice(filters.pageIndex * filters.pageSize, filters.pageIndex * filters.pageSize + filters.pageSize),
    [feedState.items, filters.pageIndex, filters.pageSize]
  );
  const totalPages = Math.max(1, Math.ceil(feedState.items.length / filters.pageSize));

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    const query = targetSearch.trim();
    if (query) {
      setActiveTarget(query);
    }
  };

  // Convert target query details into graph representation for React-Force-Graph-2D
  const graphData = useMemo(() => {
    if (!targetData) return { nodes: [], links: [] };
    const nodes = [
      { id: "target", label: targetData.target, val: 30, color: "#9dd1ff" }
    ];
    const links = [];

    const sources = targetData.sources || {};
    Object.entries(sources).forEach(([srcKey, srcData]) => {
      if (!srcData) return;
      nodes.push({ id: srcKey, label: srcKey.toUpperCase(), val: 20, color: "#14b8a6" });
      links.push({ source: "target", target: srcKey });

      if (srcKey === "shodan" && Array.isArray(srcData.ports)) {
        srcData.ports.forEach((p) => {
          const portId = `port-${p}`;
          nodes.push({ id: portId, label: `Port ${p}`, val: 12, color: "#ffd27d" });
          links.push({ source: srcKey, target: portId });
        });
      }

      if (srcKey === "nvd" && Array.isArray(srcData.cves)) {
        srcData.cves.forEach((c) => {
          const cveId = `cve-${c.id}`;
          nodes.push({ id: cveId, label: c.id, val: 14, color: "#ff8c8c" });
          links.push({ source: srcKey, target: cveId });
        });
      }
    });

    return { nodes, links };
  }, [targetData]);

  const graphContainerRef = useRef(null);
  const [graphWidth, setGraphWidth] = useState(600);

  useEffect(() => {
    if (!graphContainerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      if (entries && entries[0]) {
        setGraphWidth(entries[0].contentRect.width || 600);
      }
    });
    observer.observe(graphContainerRef.current);
    return () => observer.disconnect();
  }, [targetData]);

  return (
    <div className="threat-intel-workspace" style={{ display: "grid", gap: "24px" }}>
      {/* Target Search Panel */}
      <div className="panel" style={{ padding: "20px" }}>
        <div className="panel__header">
          <div>
            <p className="eyebrow">Reputation & IOC lookup</p>
            <h2>Target threat search</h2>
          </div>
        </div>
        <form onSubmit={handleSearchSubmit} className="dashboard-toolbar" style={{ gridTemplateColumns: "1fr auto auto", marginTop: "12px" }}>
          <div style={{ position: "relative", width: "100%" }}>
            <FaSearch style={{ position: "absolute", left: "16px", top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
            <input 
              type="text" 
              className="scan-input" 
              placeholder="Enter target IP, host, or domain (e.g. example.com)..." 
              value={targetSearch} 
              onChange={(e) => setTargetSearch(e.target.value)}
              style={{ paddingLeft: "42px", width: "100%" }}
            />
          </div>
          <button type="submit" className="scan-action scan-action--resume" disabled={isSearching}>
            {isSearching ? "Searching..." : "Lookup target"}
          </button>
          {activeTarget && (
            <button type="button" className="scan-action scan-action--cancel" onClick={() => { setActiveTarget(""); setTargetSearch(""); }}>
              <FaTimes /> Clear lookup
            </button>
          )}
        </form>
      </div>

      {/* Target Detailed Intelligence Section */}
      <AnimatePresence mode="wait">
        {activeTarget && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3 }}
            style={{ display: "grid", gap: "24px" }}
          >
            {isSearching ? (
              <div className="panel" style={{ padding: "40px", textAlign: "center" }}>
                <p className="empty-copy">Retrieving real-time threat data logs...</p>
              </div>
            ) : searchError ? (
              <div className="panel" style={{ padding: "30px", border: "1px solid rgba(239, 68, 68, 0.4)" }}>
                <h2>Search Error</h2>
                <p className="empty-copy">Unable to connect to the target intelligence database.</p>
              </div>
            ) : targetData ? (
              <>
                {/* Geolocation & Risk Dial Panel */}
                <div className="section-grid" style={{ gridTemplateColumns: "1fr 2fr", gap: "24px" }}>
                  {/* Risk score panel */}
                  <div className="panel" style={{ padding: "24px", display: "grid", placeItems: "center" }}>
                    <div style={{ width: "160px", height: "160px", margin: "0 auto" }}>
                      <CircularProgressbar
                        value={targetData.overallRiskScore || 0}
                        text={`${targetData.overallRiskScore || 0}%`}
                        styles={buildStyles({
                          textColor: "#f4f7fb",
                          pathColor: targetData.overallRiskScore >= 75 ? "#ef4444" : targetData.overallRiskScore >= 50 ? "#f59e0b" : "#06b6d4",
                          trailColor: "rgba(148, 163, 184, 0.12)",
                          textSize: "16px",
                        })}
                      />
                    </div>
                    <div style={{ textAlign: "center", marginTop: "16px" }}>
                      <span className="eyebrow" style={{ display: "block" }}>Overall target score</span>
                      <strong style={{ fontSize: "1.3rem" }}>
                        {targetData.overallRiskScore >= 75 ? "Critical threat exposure" : targetData.overallRiskScore >= 50 ? "Moderate exposure" : "Unexposed / Benign"}
                      </strong>
                    </div>
                  </div>

                  {/* Geolocation metadata */}
                  <div className="panel" style={{ padding: "24px" }}>
                    <div className="panel__header" style={{ marginBottom: "16px" }}>
                      <div>
                        <p className="eyebrow">Geolocation routing</p>
                        <h2>Asset target location</h2>
                      </div>
                    </div>
                    <div className="metrics-grid">
                      <Card 
                        title="ASN handle" 
                        value={targetData.geolocation?.asn || "N/A"} 
                        trend={targetData.geolocation?.asn ? "Registered Autonomous System" : "No ASN mapping"} 
                      />
                      <Card 
                        title="Country location" 
                        value={targetData.geolocation?.country || "N/A"} 
                        trend={targetData.geolocation?.countryCode ? `Code: ${targetData.geolocation.countryCode}` : "No geo mapping"} 
                      />
                      <Card 
                        title="City resolved" 
                        value={targetData.geolocation?.city || "N/A"} 
                        trend="City level approximation" 
                      />
                    </div>
                  </div>
                </div>

                {/* Sources Details Panel */}
                <div className="panel" style={{ padding: "24px" }}>
                  <div className="panel__header" style={{ marginBottom: "16px" }}>
                    <div>
                      <p className="eyebrow">Raw threat intelligence logs</p>
                      <h2>External API sources</h2>
                    </div>
                  </div>
                  <div className="section-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: "18px" }}>
                    {/* VirusTotal */}
                    <div className="panel" style={{ padding: "16px", background: "rgba(15, 23, 42, 0.4)" }}>
                      <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "10px" }}>
                        <FaShieldAlt style={{ color: "#06b6d4" }} />
                        <strong style={{ textTransform: "uppercase" }}>VirusTotal</strong>
                      </div>
                      {targetData.sources?.virustotal ? (
                        <div className="coverage-list" style={{ gap: "4px" }}>
                          <div className="coverage-row"><span>Reputation</span><strong>{targetData.sources.virustotal.reputation}</strong></div>
                          <div className="coverage-row"><span>Malicious</span><strong>{targetData.sources.virustotal.maliciousVotes}</strong></div>
                          <div className="coverage-row"><span>Harmless</span><strong>{targetData.sources.virustotal.harmlessVotes}</strong></div>
                        </div>
                      ) : (
                        <p className="empty-copy">No VirusTotal records found.</p>
                      )}
                    </div>

                    {/* AbuseIPDB */}
                    <div className="panel" style={{ padding: "16px", background: "rgba(15, 23, 42, 0.4)" }}>
                      <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "10px" }}>
                        <FaExclamationTriangle style={{ color: "#f59e0b" }} />
                        <strong style={{ textTransform: "uppercase" }}>AbuseIPDB</strong>
                      </div>
                      {targetData.sources?.abuseipdb ? (
                        <div className="coverage-list" style={{ gap: "4px" }}>
                          <div className="coverage-row"><span>Confidence score</span><strong>{targetData.sources.abuseipdb.abuseConfidenceScore}%</strong></div>
                          <div className="coverage-row"><span>Total reports</span><strong>{targetData.sources.abuseipdb.totalReports}</strong></div>
                        </div>
                      ) : (
                        <p className="empty-copy">No AbuseIPDB records found.</p>
                      )}
                    </div>

                    {/* GreyNoise */}
                    <div className="panel" style={{ padding: "16px", background: "rgba(15, 23, 42, 0.4)" }}>
                      <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "10px" }}>
                        <FaGlobe style={{ color: "#6366f1" }} />
                        <strong style={{ textTransform: "uppercase" }}>GreyNoise</strong>
                      </div>
                      {targetData.sources?.greynoise ? (
                        <div className="coverage-list" style={{ gap: "4px" }}>
                          <div className="coverage-row"><span>Classification</span><strong>{targetData.sources.greynoise.classification}</strong></div>
                          <div className="coverage-row"><span>Tags</span><strong>{(targetData.sources.greynoise.tags || []).join(", ") || "n/a"}</strong></div>
                        </div>
                      ) : (
                        <p className="empty-copy">No GreyNoise records found.</p>
                      )}
                    </div>
                  </div>

                  <div className="section-grid" style={{ gridTemplateColumns: "repeat(2, 1fr)", gap: "18px", marginTop: "18px" }}>
                    {/* Shodan */}
                    <div className="panel" style={{ padding: "16px", background: "rgba(15, 23, 42, 0.4)" }}>
                      <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "10px" }}>
                        <FaServer style={{ color: "#10b981" }} />
                        <strong style={{ textTransform: "uppercase" }}>Shodan ports & services</strong>
                      </div>
                      {targetData.sources?.shodan ? (
                        <div className="coverage-list" style={{ gap: "4px" }}>
                          <div className="coverage-row"><span>Open ports</span><strong>{(targetData.sources.shodan.ports || []).join(", ") || "None"}</strong></div>
                          <div className="coverage-row"><span>Exposed services</span><strong>{(targetData.sources.shodan.services || []).join(", ") || "None"}</strong></div>
                          <div className="coverage-row"><span>SSL Issuer</span><strong>{targetData.sources.shodan.sslInfo?.issuer || "n/a"}</strong></div>
                        </div>
                      ) : (
                        <p className="empty-copy">No Shodan exposed ports records found.</p>
                      )}
                    </div>

                    {/* AlienVault */}
                    <div className="panel" style={{ padding: "16px", background: "rgba(15, 23, 42, 0.4)" }}>
                      <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "10px" }}>
                        <FaBug style={{ color: "#ec4899" }} />
                        <strong style={{ textTransform: "uppercase" }}>AlienVault pulses</strong>
                      </div>
                      {targetData.sources?.alienvault ? (
                        <div className="coverage-list" style={{ gap: "4px" }}>
                          <div className="coverage-row"><span>Active malware families</span><strong>{(targetData.sources.alienvault.malwareFamilies || []).join(", ") || "None recorded"}</strong></div>
                          <div className="coverage-row"><span>Pulses matching target</span><strong>{targetData.sources.alienvault.pulses?.length || 0}</strong></div>
                        </div>
                      ) : (
                        <p className="empty-copy">No AlienVault threat pulses matching target.</p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Threat Landscape Graph (React-Force-Graph-2D) */}
                {graphData.nodes.length > 0 && (
                  <div ref={graphContainerRef} className="panel" style={{ padding: "24px", overflow: "hidden" }}>
                    <div className="panel__header" style={{ marginBottom: "16px" }}>
                      <div>
                        <p className="eyebrow">Threat topology analysis</p>
                        <h2>Attack vector graph</h2>
                      </div>
                    </div>
                    <div style={{ width: "100%", background: "#060a12", borderRadius: "18px", overflow: "hidden" }}>
                      <ForceGraph2D
                        graphData={graphData}
                        width={graphWidth}
                        height={340}
                        nodeColor={(node) => node.color}
                        nodeVal={(node) => node.val}
                        linkLabel={() => ""}
                        linkWidth={1.5}
                        linkColor={() => "rgba(148, 163, 184, 0.2)"}
                        nodeCanvasObject={(node, ctx, globalScale) => {
                          const label = node.label;
                          const fontSize = 11 / globalScale;
                          ctx.font = `${fontSize}px sans-serif`;
                          ctx.fillStyle = node.color;
                          ctx.beginPath();
                          ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI, false);
                          ctx.fill();
                          ctx.fillStyle = "#cbd5e1";
                          ctx.fillText(label, node.x + 8, node.y + 3);
                        }}
                      />
                    </div>
                  </div>
                )}

                {/* NVD CVE vulnerabilities List */}
                <div className="panel" style={{ padding: "24px" }}>
                  <div className="panel__header" style={{ marginBottom: "16px" }}>
                    <div>
                      <p className="eyebrow">National Vulnerability Database</p>
                      <h2>Target CVE list</h2>
                    </div>
                  </div>
                  <div className="table-wrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>CVE ID</th>
                          <th>CVSS Score</th>
                          <th>Severity</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {targetData.sources?.nvd?.cves?.length ? (
                          targetData.sources.nvd.cves.map((cve) => (
                            <tr key={cve.id}>
                              <td style={{ fontWeight: 600, color: "#ff8c8c" }}>{cve.id}</td>
                              <td><strong>{cve.score}</strong></td>
                              <td>
                                <span className={`pill pill--${cve.severity.toLowerCase()}`}>
                                  {cve.severity}
                                </span>
                              </td>
                              <td className="details-cell">{cve.description}</td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="4" className="empty-copy">No CVEs matching target resolved in NVD database.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Correlated Findings list */}
                <div className="panel" style={{ padding: "24px" }}>
                  <div className="panel__header" style={{ marginBottom: "16px" }}>
                    <div>
                      <p className="eyebrow">Cross source correlation</p>
                      <h2>Correlated VAPT findings</h2>
                    </div>
                  </div>
                  <div className="table-wrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Source</th>
                          <th>Type</th>
                          <th>Severity</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {targetData.correlatedFindings?.length ? (
                          targetData.correlatedFindings.map((finding, idx) => (
                            <tr key={`${finding.source}-${idx}`}>
                              <td style={{ fontWeight: 600 }}>{finding.source}</td>
                              <td>{finding.type}</td>
                              <td>
                                <span className={`pill pill--${finding.severity.toLowerCase()}`}>
                                  {finding.severity}
                                </span>
                              </td>
                              <td>{finding.description}</td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="4" className="empty-copy">No correlated findings recorded for this target yet.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            ) : (
              <div className="panel" style={{ padding: "30px", textAlign: "center" }}>
                <p className="empty-copy">No data available for target "{activeTarget}". Ensure it matches an asset or active threat target.</p>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Default Feed Panels */}
      {!activeTarget && (
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
              <div className="threat-toolbar__summary"><span>Sources</span><strong>abuse.ch / URLhaus / CISA / NVD</strong></div>
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
        </section>
      )}
    </div>
  );
}

export default function ThreatIntelligence(props) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThreatIntelligenceContent {...props} />
    </QueryClientProvider>
  );
}

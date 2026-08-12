import { useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import { feature } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";

import api from "../api/client";
import Card from "../components/Card";

const worldFeatures = feature(worldAtlas, worldAtlas.objects.countries).features;

function geoCentroid(feature) {
  let cx = 0;
  let cy = 0;
  let len = 0;
  if (!feature.geometry) return [0, 0];
  const processPolygon = (polygon) => {
    polygon.forEach((ring) => {
      ring.forEach((pt) => {
        cx += pt[0];
        cy += pt[1];
        len++;
      });
    });
  };
  if (feature.geometry.type === "Polygon") {
    processPolygon(feature.geometry.coordinates);
  } else if (feature.geometry.type === "MultiPolygon") {
    feature.geometry.coordinates.forEach(processPolygon);
  }
  return len ? [cx / len, cy / len] : [0, 0];
}

function buildCountryLookup() {
  return Object.fromEntries(
    worldFeatures.map((item) => {
      const centroid = geoCentroid(item);
      return [item.properties.name, { feature: item, centroid }];
    })
  );
}

const countryLookup = buildCountryLookup();

const COUNTRY_ALIAS_MAP = {
  "united states": "United States of America",
  "usa": "United States of America",
  "us": "United States of America",
  "united kingdom": "United Kingdom",
  "uk": "United Kingdom",
  "great britain": "United Kingdom",
  "russia": "Russia",
  "russian federation": "Russia",
  "south korea": "South Korea",
  "korea": "South Korea",
  "republic of korea": "South Korea",
  "north korea": "Dem. Rep. Korea",
  "democratic people's republic of korea": "Dem. Rep. Korea",
  "bosnia and herzegovina": "Bosnia and Herz.",
  "central african republic": "Central African Rep.",
  "dominican republic": "Dominican Rep.",
  "equatorial guinea": "Eq. Guinea",
  "south sudan": "S. Sudan",
  "western sahara": "W. Sahara",
  "solomon islands": "Solomon Is.",
  "falkland islands": "Falkland Is.",
  "ivory coast": "Côte d'Ivoire",
  "cote d'ivoire": "Côte d'Ivoire",
  "eswatini": "eSwatini",
  "swaziland": "eSwatini",
  "czech republic": "Czechia",
  "united arab emirates": "United Arab Emirates",
  "uae": "United Arab Emirates",
};

const geoCache = {};

function getCountryGeo(countryName) {
  if (!countryName) return null;
  if (geoCache[countryName]) return geoCache[countryName];

  if (countryLookup[countryName]) {
    geoCache[countryName] = countryLookup[countryName];
    return countryLookup[countryName];
  }

  const lower = countryName.trim().toLowerCase();
  const alias = COUNTRY_ALIAS_MAP[lower];
  if (alias && countryLookup[alias]) {
    geoCache[countryName] = countryLookup[alias];
    return countryLookup[alias];
  }

  for (const [atlasName, data] of Object.entries(countryLookup)) {
    const atlasLower = atlasName.toLowerCase();
    if (atlasLower === lower || atlasLower.includes(lower) || lower.includes(atlasLower)) {
      geoCache[countryName] = data;
      return data;
    }
  }
  return null;
}

function normalizeCountryName(name) {
  if (!name) return "";
  const geo = getCountryGeo(name);
  return geo ? geo.feature.properties.name : name;
}

function backendCountryName(name) {
  if (name === "United States of America") return "United States";
  return name;
}

function severityClass(severity) {
  if (!severity) return "info";
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

function parseFlowTime(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default function GlobalAttackMap() {
  const [state, setState] = useState({ status: "loading", data: null });
  const [windowKey, setWindowKey] = useState("24h");
  const [selectedCountry, setSelectedCountry] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [destinationFilter, setDestinationFilter] = useState("");

  // REAL API Dashboard Data
  const [dashboardData, setDashboardData] = useState({
    time_range: "24h",
    summary: { attacks_today: 0, active_flows: 0, attack_intensity: "Low" },
    top_countries: [],
    attacks_over_time: [],
    targeted_industries: [],
    malware_intelligence: [],
  });
  const [loadingDashboard, setLoadingDashboard] = useState(true);

  const globeRef = useRef();
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 480 });

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      if (!entries || !entries[0]) return;
      const { width, height } = entries[0].contentRect;
      setDimensions({ width, height: height || 480 });
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // 1. Fetch Globe flow data
  useEffect(() => {
    let ignore = false;

    const loadGlobeData = () => {
      api
        .get("/threat-intelligence/attack-map")
        .then((response) => {
          if (ignore) return;
          setState({ status: "ready", data: response.data });
          const firstCountry = response.data?.most_attacked_24h?.[0]?.country;
          if (firstCountry) {
            setSelectedCountry((current) => current || firstCountry);
          }
        })
        .catch(() => {
          if (ignore) return;
          setState({ status: "error", data: null });
        });
    };

    loadGlobeData();
    const interval = window.setInterval(loadGlobeData, 30000);
    return () => {
      ignore = true;
      window.clearInterval(interval);
    };
  }, []);

  // 2. Fetch Dashboard Real API Data when windowKey changes
  useEffect(() => {
    let ignore = false;
    setLoadingDashboard(true);

    api
      .get("/api/v1/attack-map/data", { params: { time_range: windowKey } })
      .then((response) => {
        if (ignore) return;
        setDashboardData(response.data);
      })
      .catch((err) => {
        console.error("Failed to load attack map dashboard data:", err);
      })
      .finally(() => {
        if (!ignore) setLoadingDashboard(false);
      });

    return () => {
      ignore = true;
    };
  }, [windowKey]);

  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.controls().autoRotate = true;
      globeRef.current.controls().autoRotateSpeed = 1.2;
    }
  }, [state.status]);

  const flows = state.data?.flows || [];

  const countryOptions = useMemo(() => {
    const keys = Object.keys(state.data?.countries || {});
    if (keys.length) return keys.sort((a, b) => a.localeCompare(b));
    const unique = new Set();
    flows.forEach((flow) => {
      if (flow?.source_country) unique.add(flow.source_country);
      if (flow?.target_country) unique.add(flow.target_country);
    });
    return Array.from(unique).sort((a, b) => a.localeCompare(b));
  }, [state.data, flows]);

  const filteredFlows = useMemo(() => {
    if (!flows.length) return [];
    const hours = windowKey === "1h" ? 1 : windowKey === "12h" ? 12 : windowKey === "1month" ? 720 : 24;
    const threshold = Date.now() - hours * 60 * 60 * 1000;
    const recent = flows.filter((flow) => {
      const time = parseFlowTime(flow.timestamp);
      return time ? time.getTime() >= threshold : false;
    });
    const windowed = recent.length ? recent : flows;
    const byCountries = windowed.filter((flow) => {
      const matchesSource = !sourceFilter || flow.source_country === sourceFilter;
      const matchesDestination = !destinationFilter || flow.target_country === destinationFilter;
      return matchesSource && matchesDestination;
    });
    return sourceFilter || destinationFilter ? byCountries : windowed;
  }, [flows, windowKey, sourceFilter, destinationFilter]);

  const [hoverArc, setHoverArc] = useState(null);

  // PRESERVED: Globe 3D links calculation
  const globeLinks = useMemo(() => {
    return filteredFlows
      .map((flow) => {
        const sourceGeo = getCountryGeo(flow.source_country);
        const targetGeo = getCountryGeo(flow.target_country);
        if (!sourceGeo?.centroid || !targetGeo?.centroid) return null;

        let color = ["rgba(54, 174, 255, 0.4)", "rgba(54, 174, 255, 0.8)"];
        if (flow.severity === "critical" || flow.severity === "high") {
          color = ["rgba(255, 76, 76, 0.5)", "rgba(255, 76, 76, 1)"];
        } else if (flow.severity === "medium") {
          color = ["rgba(255, 170, 0, 0.5)", "rgba(255, 170, 0, 1)"];
        }

        return {
          id: flow.id,
          startLat: sourceGeo.centroid[1],
          startLng: sourceGeo.centroid[0],
          endLat: targetGeo.centroid[1],
          endLng: targetGeo.centroid[0],
          color: color,
          flow: flow,
        };
      })
      .filter(Boolean)
      .slice(0, 300);
  }, [filteredFlows]);

  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeModal, setActiveModal] = useState(null);
  const [selectedIndustry, setSelectedIndustry] = useState("");
  const [selectedMalware, setSelectedMalware] = useState("");

  const countryDetail = selectedCountry ? state.data?.countries?.[selectedCountry] : null;
  const industryCompanies = selectedIndustry ? state.data?.companies_by_industry?.[selectedIndustry] || [] : [];
  const malwareIndicators = selectedMalware ? state.data?.indicators_by_malware?.[selectedMalware] || [] : [];

  const handleCountryClick = (country) => {
    setSelectedCountry(country);
    setActiveModal("countryDetail");
    if (globeRef.current) globeRef.current.controls().autoRotate = false;
  };

  const handleIndustryClick = (industry) => {
    setSelectedIndustry(industry);
    setActiveModal("industryDetail");
  };

  const handleMalwareClick = (malwareType) => {
    setSelectedMalware(malwareType);
    setActiveModal("malwareDetail");
  };

  const intensityColor = useMemo(() => {
    const intensity = (dashboardData.summary?.attack_intensity || "").toLowerCase();
    if (intensity === "critical") return "#ef4444";
    if (intensity === "high") return "#f97316";
    if (intensity === "medium") return "#eab308";
    return "#10b981";
  }, [dashboardData.summary?.attack_intensity]);

  return (
    <section className="attack-map-workspace">
      <div className={`attack-map-page attack-map-page--primary ${isFullscreen ? "attack-map-fullscreen" : ""}`}>
        
        {/* TOP BAR / TIME FILTER TOOLBAR */}
        <div
          className="panel"
          style={{
            background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.85))",
            border: "1px solid rgba(148, 163, 184, 0.15)",
            borderRadius: "16px",
            padding: "18px 24px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "16px",
            marginBottom: "16px",
          }}
        >
          <div>
            <span style={{ color: "#38bdf8", fontSize: "0.75rem", fontWeight: "700", textTransform: "uppercase", letterSpacing: "1px" }}>
              Enterprise Threat Intelligence
            </span>
            <h1 style={{ fontSize: "1.4rem", fontWeight: "700", color: "#f8fafc", margin: "2px 0 0 0" }}>
              Global Attack Map & Security Telemetry Dashboard
            </h1>
          </div>

          {/* Time Filter Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ color: "#94a3b8", fontSize: "0.82rem", marginRight: "4px" }}>Time Window:</span>
            {[
              { label: "1h", value: "1h" },
              { label: "12h", value: "12h" },
              { label: "24h", value: "24h" },
              { label: "1 Month", value: "1month" },
            ].map((tf) => (
              <button
                key={tf.value}
                type="button"
                className={`scan-action ${windowKey === tf.value ? "scan-action--active" : ""}`}
                onClick={() => setWindowKey(tf.value)}
                style={{
                  padding: "6px 14px",
                  borderRadius: "8px",
                  fontWeight: "600",
                  fontSize: "0.82rem",
                  cursor: "pointer",
                  border: windowKey === tf.value ? "1px solid #38bdf8" : "1px solid rgba(148, 163, 184, 0.2)",
                  background: windowKey === tf.value ? "rgba(56, 189, 248, 0.15)" : "rgba(30, 41, 59, 0.5)",
                  color: windowKey === tf.value ? "#38bdf8" : "#cbd5e1",
                }}
              >
                {tf.label}
              </button>
            ))}
          </div>
        </div>

        {/* SECTION 1: LIVE ATTACK STATS CARDS */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px", marginBottom: "16px" }}>
          <div className="panel" style={{ padding: "16px 20px" }}>
            <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Attacks Today ({dashboardData.time_range})</span>
            <strong style={{ display: "block", fontSize: "1.7rem", color: "#38bdf8", marginTop: "4px" }}>
              {loadingDashboard ? "..." : dashboardData.summary?.attacks_today ?? 0}
            </strong>
          </div>

          <div className="panel" style={{ padding: "16px 20px" }}>
            <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Active Threat Flows</span>
            <strong style={{ display: "block", fontSize: "1.7rem", color: "#f43f5e", marginTop: "4px" }}>
              {loadingDashboard ? "..." : dashboardData.summary?.active_flows ?? 0}
            </strong>
          </div>

          <div className="panel" style={{ padding: "16px 20px" }}>
            <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>Attack Intensity Level</span>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "6px" }}>
              <span
                style={{
                  padding: "4px 12px",
                  borderRadius: "6px",
                  background: `${intensityColor}22`,
                  border: `1px solid ${intensityColor}66`,
                  color: intensityColor,
                  fontWeight: "700",
                  fontSize: "0.95rem",
                  textTransform: "uppercase",
                }}
              >
                {loadingDashboard ? "..." : dashboardData.summary?.attack_intensity || "Low"}
              </span>
            </div>
          </div>
        </div>

        {/* MAIN STAGE WITH UNTOUCHED 3D GLOBE COMPONENT */}
        <div className={`panel attack-map-stage ${isFullscreen ? "panel--fullscreen" : ""}`} style={isFullscreen ? { position: "fixed", inset: 0, zIndex: 99999, height: "100vh", width: "100vw", background: "#0b0f19", padding: "20px", overflowY: "auto", overflowX: "hidden", boxSizing: "border-box" } : {}}>
          <div className="panel__header">
            <div>
              <p className="eyebrow">3D Interactive Telemetry Sphere</p>
              <h2>Global Attack Map Arc Visualizer</h2>
            </div>
            <div className="scan-actions">
              <select className="scan-select" value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                <option value="">All source countries</option>
                {countryOptions.map((country) => <option key={`src-${country}`} value={country}>{country}</option>)}
              </select>
              <select className="scan-select" value={destinationFilter} onChange={(event) => setDestinationFilter(event.target.value)}>
                <option value="">All destination countries</option>
                {countryOptions.map((country) => <option key={`dst-${country}`} value={country}>{country}</option>)}
              </select>
              <button type="button" className="scan-action" onClick={() => { setSourceFilter(""); setDestinationFilter(""); }}>
                Clear filter
              </button>
              <button type="button" className={`scan-action ${isFullscreen ? "scan-action--active" : ""}`} onClick={() => setIsFullscreen(!isFullscreen)}>
                {isFullscreen ? "Exit Fullscreen" : "Full Screen Globe"}
              </button>
            </div>
          </div>

          {/* UNTOUCHED 3D GLOBE CONTAINER */}
          <div ref={containerRef} className="world-map-shell world-map-shell--immersive" style={{ height: isFullscreen ? "calc(100vh - 140px)" : "480px", minHeight: "350px", position: "relative", overflow: "hidden" }}>
            <Globe
              ref={globeRef}
              width={dimensions.width}
              height={dimensions.height}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              arcsData={globeLinks}
              arcColor={(d) => (d === hoverArc ? ["#ff4c4c", "#ffff55"] : d.color)}
              arcDashLength={0.4}
              arcDashGap={0.2}
              arcDashAnimateTime={(d) => (d === hoverArc ? 1000 : 2500)}
              arcStroke={(d) => (d === hoverArc ? 2.5 : 0.9)}
              arcLabel={(d) => `
                <div style="background: rgba(15, 23, 42, 0.96); border: 1px solid #334155; padding: 10px 14px; border-radius: 8px; color: white; font-size: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.6); max-width: 320px;">
                   <div style="font-weight: 700; color: #38bdf8; margin-bottom: 4px; font-size: 13px;">${d.flow.attack_type}</div>
                   <div style="font-size: 11px; color: #f8fafc;">Target Org: <b>${d.flow.company_name || 'Unclassified'}</b></div>
                   <div style="font-size: 11px; color: #cbd5e1; margin-top: 2px;">Destination IP: <b>${d.flow.destination_ip ? `${d.flow.destination_ip}:${d.flow.destination_port || 443}` : 'N/A'}</b></div>
                   <div style="font-size: 11px; color: #cbd5e1; margin-top: 2px;">Malware Family: <span style="color: #f43f5e; font-weight: 600;">${d.flow.malware_family || d.flow.malware_type || 'Unclassified'}</span></div>
                   ${d.flow.threat_url ? `<div style="font-size: 10px; color: #94a3b8; margin-top: 3px; word-break: break-all;">URL: ${d.flow.threat_url}</div>` : ''}
                   <div style="font-size: 11px; color: #94a3b8; margin-top: 3px;">Vector: ${d.flow.source_country} ➔ ${d.flow.target_country}</div>
                   <div style="font-size: 10px; margin-top: 6px; display: flex; gap: 6px; align-items: center;">
                     <span style="background: ${d.flow.severity === 'critical' ? '#ef4444' : '#f59e0b'}; padding: 2px 6px; border-radius: 4px; color: white; font-weight: bold; text-transform: uppercase;">${d.flow.severity}</span>
                     <span style="background: #1e293b; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-weight: 600;">Score: ${d.flow.ip_reputation || 85}/100</span>
                   </div>
                </div>
              `}
              onArcHover={(arc) => setHoverArc(arc)}
              onArcClick={(arc) => {
                if (arc?.flow?.target_country) {
                  handleCountryClick(arc.flow.target_country);
                }
              }}
              onGlobeClick={() => {
                if (globeRef.current) globeRef.current.controls().autoRotate = false;
              }}
              polygonsData={worldFeatures}
              polygonCapColor={() => "rgba(20, 20, 30, 0.6)"}
              polygonSideColor={() => "rgba(10, 10, 20, 0.4)"}
              polygonStrokeColor={() => "#1e293b"}
              onPolygonClick={(polygon) => {
                const name = backendCountryName(polygon.properties.name);
                handleCountryClick(name);
              }}
              polygonLabel={({ properties: d }) => `
                <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid #334155; padding: 6px 10px; border-radius: 4px; color: white; font-size: 12px;">
                   <b>${d.name}</b> (Click for attack details)
                </div>
              `}
            />

            <div className="world-map__overlay world-map__overlay--left" style={{ position: "absolute", top: 20, left: 20, zIndex: 10 }}>
              <div className="world-map__overlay-card" style={{ cursor: "pointer" }} onClick={() => setActiveModal("activeFlows")}>
                <span>Visible flows</span>
                <strong>{globeLinks.length}</strong>
                <small>{windowKey} view (Click to view all)</small>
              </div>
              <div className="world-map__overlay-card" style={{ cursor: "pointer" }} onClick={() => setActiveModal("attacksToday")}>
                <span>Attacks today</span>
                <strong>{dashboardData.summary?.attacks_today || 0}</strong>
                <small>Live telemetry</small>
              </div>
            </div>

            <div className="world-map__ticker" style={{ position: "absolute", bottom: 20, right: 20, width: "340px", zIndex: 10 }}>
              {globeLinks.length > 0 ? (
                <div className="world-map__ticker-card" style={{ cursor: "pointer" }} onClick={() => handleCountryClick(globeLinks[0].flow.target_country)}>
                  <span>{globeLinks[0].flow.attack_type}</span>
                  <strong>{globeLinks[0].flow.source_country} to {globeLinks[0].flow.target_country}</strong>
                  <small>{globeLinks[0].flow.company_name ? `Target: ${globeLinks[0].flow.company_name} — ` : ""}{globeLinks[0].flow.title}</small>
                </div>
              ) : (
                <div className="world-map__ticker-card">
                  <span>Live flow</span>
                  <strong>No active flow available yet</strong>
                  <small>Threat intelligence, incidents, and findings will populate here automatically.</small>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* SURROUNDING DASHBOARD WIDGETS (MOST ATTACKED COUNTRIES, TARGETED INDUSTRIES, MALWARE INTEL) */}
        <div className="attack-map-page__rail" style={{ resize: "horizontal", overflow: "auto" }}>
          
          {/* WIDGET 2: MOST ATTACKED COUNTRIES (TOP 5) */}
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Top 5 Target Countries</p>
                <h2>Most Attacked Countries ({windowKey})</h2>
              </div>
            </div>
            <div className="coverage-list">
              {loadingDashboard ? (
                <p className="empty-copy">Loading telemetry data...</p>
              ) : dashboardData.top_countries && dashboardData.top_countries.length > 0 ? (
                dashboardData.top_countries.map((item, idx) => (
                  <div
                    className="coverage-row coverage-row--link"
                    key={`country-${item.country}-${idx}`}
                    onClick={() => handleCountryClick(item.country)}
                    style={{ cursor: "pointer", display: "flex", flexDirection: "column", gap: "6px" }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                      <span style={{ color: "#f8fafc", fontWeight: "600", display: "flex", alignItems: "center", gap: "8px" }}>
                        <span style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", padding: "2px 6px", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "monospace" }}>
                          {item.code}
                        </span>
                        {item.country}
                      </span>
                      <strong style={{ color: "#38bdf8" }}>{item.percentage}%</strong>
                    </div>
                    {/* Progress Bar */}
                    <div style={{ width: "100%", height: "4px", background: "rgba(148, 163, 184, 0.15)", borderRadius: "2px", overflow: "hidden" }}>
                      <div style={{ width: `${Math.min(item.percentage, 100)}%`, height: "100%", background: "#38bdf8", borderRadius: "2px" }} />
                    </div>
                  </div>
                ))
              ) : (
                <p className="empty-copy">No attacks detected</p>
              )}
            </div>
          </div>

          {/* WIDGET 4: TARGETED INDUSTRIES */}
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Sector Distribution</p>
                <h2>Targeted Industries ({windowKey})</h2>
              </div>
            </div>
            <div className="coverage-list">
              {loadingDashboard ? (
                <p className="empty-copy">Loading sector telemetry...</p>
              ) : dashboardData.targeted_industries && dashboardData.targeted_industries.length > 0 ? (
                dashboardData.targeted_industries.map((item, idx) => (
                  <div
                    className="coverage-row coverage-row--link"
                    key={`ind-${item.industry}-${idx}`}
                    onClick={() => handleIndustryClick(item.industry)}
                    style={{ cursor: "pointer" }}
                  >
                    <span>{item.industry}</span>
                    <strong style={{ color: "#f43f5e" }}>{item.attacks} attack{item.attacks === 1 ? "" : "s"}</strong>
                  </div>
                ))
              ) : (
                <p className="empty-copy">No targeted industry telemetry</p>
              )}
            </div>
          </div>

          {/* WIDGET 5: MALWARE INTELLIGENCE */}
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Threat Feeds & Botnets</p>
                <h2>Malware Intelligence ({windowKey})</h2>
              </div>
            </div>
            <div className="coverage-list">
              {loadingDashboard ? (
                <p className="empty-copy">Loading malware intelligence...</p>
              ) : dashboardData.malware_intelligence && dashboardData.malware_intelligence.length > 0 ? (
                dashboardData.malware_intelligence.map((item, idx) => (
                  <div
                    className="coverage-row coverage-row--link"
                    key={`mal-${item.name}-${idx}`}
                    onClick={() => handleMalwareClick(item.name)}
                    style={{ cursor: "pointer", display: "flex", flexDirection: "column", gap: "4px" }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ color: "#f8fafc", fontWeight: "700" }}>{item.name}</span>
                      <span className={`pill pill--${severityClass(item.severity)}`}>{item.severity}</span>
                    </div>
                    <small style={{ color: "#94a3b8", fontSize: "0.78rem" }}>{item.description}</small>
                  </div>
                ))
              ) : (
                <p className="empty-copy">No malware intelligence available</p>
              )}
            </div>
          </div>

          {/* TIMELINE: ATTACKS OVER TIME */}
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Time Series Frequency</p>
                <h2>Attacks Over Time ({windowKey})</h2>
              </div>
            </div>
            <div className="coverage-list">
              {loadingDashboard ? (
                <p className="empty-copy">Loading time series data...</p>
              ) : dashboardData.attacks_over_time && dashboardData.attacks_over_time.length > 0 ? (
                dashboardData.attacks_over_time.map((item, idx) => (
                  <div className="coverage-row" key={`timeline-${item.timestamp}-${idx}`}>
                    <span style={{ fontSize: "0.8rem", fontFamily: "monospace", color: "#cbd5e1" }}>
                      {new Date(item.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                    </span>
                    <strong style={{ color: "#38bdf8" }}>{item.count} event{item.count === 1 ? "" : "s"}</strong>
                  </div>
                ))
              ) : (
                <p className="empty-copy">No attack timeline data</p>
              )}
            </div>
          </div>

        </div>
      </div>

      {/* DRILL-DOWN MODALS (PRESERVED) */}
      {activeModal === "countryDetail" && countryDetail ? (
        <div className="country-modal-backdrop" onClick={() => setActiveModal(null)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "1000px", width: "90%" }}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Country drill-down</p>
                <h2>{selectedCountry} — Live Threat Profile</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setActiveModal(null)} aria-label="Close modal">
                ✕
              </button>
            </div>
            <div className="country-detail-grid">
              <div className="metrics-grid metrics-grid--compact">
                <Card title="Total activity" value={countryDetail.attack_count} trend="Inbound and outbound events" />
                <Card title="Inbound" value={countryDetail.target_count} trend="Attacks targeting this country" />
                <Card title="Outbound" value={countryDetail.source_count} trend="Flows originating from this country" />
              </div>
              <div className="threat-grid">
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Attack types</p><h2>Executed against {selectedCountry}</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_attack_types?.length ? countryDetail.top_attack_types.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value} hits</strong></div>;
                    }) : <p className="empty-copy">No attack-type telemetry yet.</p>}
                  </div>
                </div>
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Source countries</p><h2>Who is attacking {selectedCountry}</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_sources?.length ? countryDetail.top_sources.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value} flows</strong></div>;
                    }) : <p className="empty-copy">No upstream source telemetry yet.</p>}
                  </div>
                </div>
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Targeted companies</p><h2>Sectors & Orgs</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_industries?.length ? countryDetail.top_industries.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value} targets</strong></div>;
                    }) : <p className="empty-copy">No industry telemetry yet.</p>}
                  </div>
                </div>
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Malware</p><h2>Observed malware types</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_malware?.length ? countryDetail.top_malware.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value}</strong></div>;
                    }) : <p className="empty-copy">No malware family mapping yet.</p>}
                  </div>
                </div>
              </div>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Attack Vector</th>
                      <th>Targeted Company</th>
                      <th>Source Country</th>
                      <th>Target Country</th>
                      <th>Severity</th>
                      <th>Feed Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {countryDetail.latest_flows.length ? countryDetail.latest_flows.map((flow) => (
                      <tr key={flow.id}>
                        <td data-label="Time">{new Date(flow.timestamp).toLocaleString()}</td>
                        <td data-label="Attack">
                          <strong>{flow.attack_type}</strong>
                          <p>{flow.title}</p>
                        </td>
                        <td data-label="Company">{flow.company_name || flow.target_label || "Unknown organization"}</td>
                        <td data-label="Source">{flow.source_country}</td>
                        <td data-label="Target">{flow.target_country}</td>
                        <td data-label="Severity"><span className={`pill pill--${severityClass(flow.severity)}`}>{flow.severity}</span></td>
                        <td data-label="Feed">{flow.ti_source || "Live Feed"}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="7" className="empty-cell">
                          No live flow records for this country yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {activeModal === "industryDetail" ? (
        <div className="country-modal-backdrop" onClick={() => setActiveModal(null)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "800px", width: "90%" }}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Targeted Companies</p>
                <h2>{selectedIndustry} Industry — Real Target Companies</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setActiveModal(null)}>✕</button>
            </div>
            <div className="coverage-list" style={{ marginTop: "15px" }}>
              {industryCompanies.length ? industryCompanies.map((item, idx) => (
                <div className="coverage-row" key={`${item.company_name}-${idx}`}>
                  <span><strong>{item.company_name}</strong></span>
                  <strong>{item.attacks} active attacks targeted</strong>
                </div>
              )) : <p className="empty-copy">No company targets recorded for {selectedIndustry} yet.</p>}
            </div>
          </div>
        </div>
      ) : null}

      {activeModal === "malwareDetail" ? (
        <div className="country-modal-backdrop" onClick={() => setActiveModal(null)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "900px", width: "90%" }}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Malware Intelligence</p>
                <h2>{selectedMalware} — Active Malware Execution & Indicators</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setActiveModal(null)}>✕</button>
            </div>
            <div className="table-wrap" style={{ marginTop: "15px" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Threat Name / Indicator</th>
                    <th>Targeted Organization</th>
                    <th>Vector</th>
                    <th>Severity</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {malwareIndicators.length ? malwareIndicators.map((item, idx) => (
                    <tr key={`${item.id}-${idx}`}>
                      <td>{new Date(item.timestamp).toLocaleString()}</td>
                      <td><strong>{item.title}</strong></td>
                      <td>{item.company_name || "Target Organization"}</td>
                      <td>{item.source_country} ➔ {item.target_country}</td>
                      <td><span className={`pill pill--${severityClass(item.severity)}`}>{item.severity}</span></td>
                      <td>{item.ti_source || "URLhaus / CISA"}</td>
                    </tr>
                  )) : (
                    <tr><td colSpan="6" className="empty-cell">No active malware execution indicators for {selectedMalware}.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}

      {activeModal === "attacksToday" ? (
        <div className="country-modal-backdrop" onClick={() => setActiveModal(null)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "1000px", width: "90%" }}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Telemetry Stream</p>
                <h2>Today's Real-time Threat Events ({dashboardData.summary?.attacks_today || 0})</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setActiveModal(null)}>✕</button>
            </div>
            <div className="table-wrap" style={{ marginTop: "15px" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Attack Type</th>
                    <th>Targeted Company</th>
                    <th>Origin</th>
                    <th>Destination</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.slice(0, 40).map((flow) => (
                    <tr key={flow.id}>
                      <td>{new Date(flow.timestamp).toLocaleString()}</td>
                      <td><strong>{flow.attack_type}</strong><p>{flow.title}</p></td>
                      <td>{flow.company_name || "Organization"}</td>
                      <td>{flow.source_country}</td>
                      <td>{flow.target_country}</td>
                      <td><span className={`pill pill--${severityClass(flow.severity)}`}>{flow.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}

      {activeModal === "activeFlows" ? (
        <div className="country-modal-backdrop" onClick={() => setActiveModal(null)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "1100px", width: "95%" }}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Active Threat Trajectories</p>
                <h2>Global Attack Arcs ({flows.length} Active Feeds)</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setActiveModal(null)}>✕</button>
            </div>
            <div className="table-wrap" style={{ marginTop: "15px" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Flow ID</th>
                    <th>Source ➔ Target</th>
                    <th>Destination IP:Port</th>
                    <th>Targeted Company</th>
                    <th>Malware Family</th>
                    <th>Threat URL / Details</th>
                    <th>Reputation</th>
                    <th>Feed</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.slice(0, 60).map((flow) => (
                    <tr key={flow.id}>
                      <td><code>{flow.id}</code></td>
                      <td><strong>{flow.source_country} ➔ {flow.target_country}</strong></td>
                      <td><strong>{flow.destination_ip ? `${flow.destination_ip}:${flow.destination_port || 443}` : "N/A"}</strong></td>
                      <td>{flow.company_name}</td>
                      <td><span style={{ color: "#f43f5e", fontWeight: 600 }}>{flow.malware_family || flow.malware_type || "Unclassified"}</span></td>
                      <td><small>{flow.threat_url || flow.title}</small></td>
                      <td><span className="pill pill--info">{flow.ip_reputation || 85}/100</span></td>
                      <td>{flow.ti_source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

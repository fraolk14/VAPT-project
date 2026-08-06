import { useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import { feature } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";

import api from "../api/client";
import Card from "../components/Card";

const worldFeatures = feature(worldAtlas, worldAtlas.objects.countries).features;

// Quick centroid lookup for all countries using topojson features
function geoCentroid(feature) {
  let cx = 0;
  let cy = 0;
  let len = 0;
  if (!feature.geometry) return [0, 0];
  const processPolygon = (polygon) => {
    polygon.forEach(ring => {
      ring.forEach(pt => { cx += pt[0]; cy += pt[1]; len++; });
    });
  }
  if (feature.geometry.type === 'Polygon') {
    processPolygon(feature.geometry.coordinates);
  } else if (feature.geometry.type === 'MultiPolygon') {
    feature.geometry.coordinates.forEach(processPolygon);
  }
  return len ? [cx/len, cy/len] : [0,0];
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

function normalizeCountryName(name) {
  if (!name) return "";
  if (name === "United States") return "United States of America";
  return name;
}

function backendCountryName(name) {
  if (name === "United States of America") return "United States";
  return name;
}

function severityClass(severity) {
  if (severity === "critical" || severity === "high") return "critical";
  if (severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "info";
}

function parseFlowTime(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function metricRows(items, keyField, labelField = keyField) {
  return items?.length ? (
    items.map((item) => (
      <div className="coverage-row" key={`${item[keyField]}-${item.attacks}`}>
        <span>{item[labelField]}</span>
        <strong>{item.attacks}</strong>
      </div>
    ))
  ) : (
    <p className="empty-copy">Awaiting more live telemetry.</p>
  );
}

export default function GlobalAttackMap() {
  const [state, setState] = useState({ status: "loading", data: null });
  const [windowKey, setWindowKey] = useState("24h");
  const [selectedCountry, setSelectedCountry] = useState("");
  const [detailOpen, setDetailOpen] = useState(false);
  const [sourceFilter, setSourceFilter] = useState("");
  const [destinationFilter, setDestinationFilter] = useState("");

  const globeRef = useRef();

  useEffect(() => {
    let ignore = false;

    const load = () => {
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

    load();
    const interval = window.setInterval(load, 30000);
    return () => {
      ignore = true;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
      if (globeRef.current) {
          globeRef.current.controls().autoRotate = true;
          globeRef.current.controls().autoRotateSpeed = 1.2;
      }
  }, [state.status])

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


  const leaderboard = useMemo(() => {
    if (!state.data) return [];
    if (windowKey === "1h") return state.data.most_attacked_1h;
    if (windowKey === "12h") return state.data.most_attacked_12h;
    return state.data.most_attacked_24h;
  }, [state.data, windowKey]);

  const filteredFlows = useMemo(() => {
    if (!flows.length) return [];
    const hours = windowKey === "1h" ? 1 : windowKey === "12h" ? 12 : 24;
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

  const filteredAttackTypes = useMemo(() => {
    if (!sourceFilter && !destinationFilter) return [];
    const counter = new Map();
    filteredFlows.forEach((flow) => {
      const key = flow.attack_type || "Unknown";
      counter.set(key, (counter.get(key) || 0) + 1);
    });
    return Array.from(counter.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([attack_type, attacks]) => ({ attack_type, attacks }));
  }, [filteredFlows, sourceFilter, destinationFilter]);

  // Construct links for react-globe.gl based on the filtered flows
  const globeLinks = useMemo(() => {
    return filteredFlows.map(flow => {
       const sourceCoords = countryLookup[normalizeCountryName(flow.source_country)]?.centroid;
       const targetCoords = countryLookup[normalizeCountryName(flow.target_country)]?.centroid;
       if (!sourceCoords || !targetCoords) return null;

       let color = "rgba(54, 174, 255, 0.8)"; // Default low/info
       if (flow.severity === "critical" || flow.severity === "high") color = "rgba(255, 76, 76, 0.9)";
       else if (flow.severity === "medium") color = "rgba(255, 170, 0, 0.9)";

       return {
           startLat: sourceCoords[1],
           startLng: sourceCoords[0],
           endLat: targetCoords[1],
           endLng: targetCoords[0],
           color: color,
           flow: flow
       };
    }).filter(Boolean).slice(0, 300); // Limit rendered links
  }, [filteredFlows]);


  const countryDetail = selectedCountry
    ? state.data?.countries?.[selectedCountry] || {
        country: selectedCountry,
        attack_count: 0,
        source_count: 0,
        target_count: 0,
        top_attack_types: [],
        top_sources: [],
        top_industries: [],
        top_malware: [],
        latest_flows: [],
      }
    : null;


  return (
    <section className="attack-map-workspace">
      <div className="attack-map-page attack-map-page--primary">
        <div className="panel attack-map-stage">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Live simulation</p>
              <h2>Threat flows across the globe</h2>
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
            </div>
          </div>

          <div className="world-map-shell world-map-shell--immersive" style={{ height: "600px", position: "relative" }}>
              <Globe
                  ref={globeRef}
                  globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                  arcsData={globeLinks}
                  arcColor={'color'}
                  arcDashLength={() => Math.random()}
                  arcDashGap={() => Math.random()}
                  arcDashAnimateTime={() => Math.random() * 4000 + 500}
                  onGlobeClick={({ lat, lng }) => {
                     // Simple heuristic: if clicking generally close to a country
                     // Real implementations might do raycasting or click detection on polygons.
                     // For now, we will just stop rotation when interacted with.
                     if (globeRef.current) globeRef.current.controls().autoRotate = false;
                  }}
                  polygonsData={worldFeatures}
                  polygonCapColor={() => 'rgba(20, 20, 30, 0.6)'}
                  polygonSideColor={() => 'rgba(10, 10, 20, 0.4)'}
                  polygonStrokeColor={() => '#111'}
                  onPolygonClick={(polygon) => {
                     const name = backendCountryName(polygon.properties.name);
                     setSelectedCountry(name);
                     setDetailOpen(true);
                     if (globeRef.current) globeRef.current.controls().autoRotate = false;
                  }}
                  polygonLabel={({ properties: d }) => `
                    <div style="background: rgba(0,0,0,0.8); padding: 5px; border-radius: 4px; color: white;">
                       <b>${d.name}</b>
                    </div>
                  `}
              />

            <div className="world-map__overlay world-map__overlay--left" style={{ position: "absolute", top: 20, left: 20, zIndex: 10 }}>
              <div className="world-map__overlay-card">
                <span>Visible flows</span>
                <strong>{globeLinks.length}</strong>
                <small>{windowKey} view</small>
              </div>
              <div className="world-map__overlay-card">
                <span>Attacks today</span>
                <strong>{state.data?.daily_attack_count || 0}</strong>
                <small>Continuously refreshed</small>
              </div>
            </div>

            <div className="world-map__ticker" style={{ position: "absolute", bottom: 20, left: 20, right: 20, zIndex: 10 }}>
              {globeLinks.length > 0 ? (
                <div className="world-map__ticker-card">
                  <span>{globeLinks[0].flow.attack_type}</span>
                  <strong>{globeLinks[0].flow.source_country} to {globeLinks[0].flow.target_country}</strong>
                  <small>{globeLinks[0].flow.company_name ? `${globeLinks[0].flow.company_name}: ` : ""}{globeLinks[0].flow.title}</small>
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

        <div className="attack-map-page__rail">
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Global attack intelligence</p>
                <h2>Live attack map</h2>
              </div>
              <div className="dashboard-toolbar">
                <button type="button" className={`scan-action ${windowKey === "1h" ? "scan-action--active" : ""}`} onClick={() => setWindowKey("1h")}>1 hour</button>
                <button type="button" className={`scan-action ${windowKey === "12h" ? "scan-action--active" : ""}`} onClick={() => setWindowKey("12h")}>12 hours</button>
                <button type="button" className={`scan-action ${windowKey === "24h" ? "scan-action--active" : ""}`} onClick={() => setWindowKey("24h")}>24 hours</button>
              </div>
            </div>
            <div className="metrics-grid metrics-grid--compact">
              <Card title="Attacks Today" value={state.data?.daily_attack_count || 0} trend="Live counter for today" />
              <Card title="Active Flows" value={state.data?.active_flow_count || 0} trend="Country-to-country attack arcs" />
              <Card title="Most Attacked" value={leaderboard?.[0]?.country || "Awaiting data"} trend={leaderboard?.[0] ? `${leaderboard[0].attacks} hits` : "No recent activity"} />
              <Card title="Selected Country" value={selectedCountry || "No country selected"} trend={countryDetail ? `${countryDetail.target_count} inbound / ${countryDetail.source_count} outbound` : "Click a country"} />
            </div>
            <div className="coverage-list">
              {(sourceFilter || destinationFilter) ? (
                <>
                  <div className="coverage-row"><span>Filtered source</span><strong>{sourceFilter || "Any"}</strong></div>
                  <div className="coverage-row"><span>Filtered destination</span><strong>{destinationFilter || "Any"}</strong></div>
                  {filteredAttackTypes.length ? filteredAttackTypes.map((item) => (
                    <div className="coverage-row" key={item.attack_type}>
                      <span>{item.attack_type}</span>
                      <strong>{item.attacks}</strong>
                    </div>
                  )) : <p className="empty-copy">No flows match the selected country filter yet.</p>}
                </>
              ) : (
                <p className="empty-copy">Select a source or destination country to see which attack types are active.</p>
              )}
            </div>
          </div>
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Most attacked countries</p>
                <h2>{windowKey} leaderboard</h2>
              </div>
            </div>
            <div className="coverage-list">
              {metricRows(leaderboard, "country")}
            </div>
          </div>
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Targeted industries</p>
                <h2>Industry heat</h2>
              </div>
            </div>
            <div className="coverage-list">
              {metricRows((state.data?.most_targeted_industries || []).map((item) => ({ ...item, country: item.industry })), "country")}
            </div>
          </div>
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Malware intelligence</p>
                <h2>Top malware types</h2>
              </div>
            </div>
            <div className="coverage-list">
              {metricRows((state.data?.top_malware_types || []).map((item) => ({ ...item, country: item.malware_type })), "country")}
            </div>
          </div>
        </div>
      </div>
      {detailOpen && countryDetail ? (
        <div className="country-modal-backdrop" onClick={() => setDetailOpen(false)}>
          <div className="country-modal panel" onClick={(event) => event.stopPropagation()}>
            <div className="panel__header">
              <div>
                <p className="eyebrow">Country drill-down</p>
                <h2>{selectedCountry}</h2>
              </div>
              <button type="button" className="sidebar__toggle" onClick={() => setDetailOpen(false)} aria-label="Close country details">
                x
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
                  <div className="panel__header"><div><p className="eyebrow">Attack types</p><h2>What is happening here</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_attack_types?.length ? countryDetail.top_attack_types.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value}</strong></div>;
                    }) : <p className="empty-copy">No attack-type telemetry yet.</p>}
                  </div>
                </div>
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Source countries</p><h2>Who is hitting this country</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_sources?.length ? countryDetail.top_sources.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value}</strong></div>;
                    }) : <p className="empty-copy">No upstream source telemetry yet.</p>}
                  </div>
                </div>
                <div className="panel panel--embedded">
                  <div className="panel__header"><div><p className="eyebrow">Industries</p><h2>Most targeted sectors</h2></div></div>
                  <div className="coverage-list">
                    {countryDetail.top_industries?.length ? countryDetail.top_industries.map((item, index) => {
                      const [label, value] = Object.entries(item)[0];
                      return <div className="coverage-row" key={`${label}-${index}`}><span>{label}</span><strong>{value}</strong></div>;
                    }) : <p className="empty-copy">No industry targeting telemetry yet.</p>}
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
                      <th>Attack</th>
                      <th>Company</th>
                      <th>Source</th>
                      <th>Target</th>
                      <th>Industry</th>
                      <th>Severity</th>
                      <th>Feed</th>
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
                        <td data-label="Industry">{flow.industry || "Unclassified"}</td>
                        <td data-label="Severity"><span className={`pill pill--${severityClass(flow.severity)}`}>{flow.severity}</span></td>
                        <td data-label="Feed">{flow.ti_source || "Internal telemetry"}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="8" className="empty-cell">
                          No live flow records for this country yet. Keep the map running or adjust the source/destination filter.
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
    </section>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import { geoCentroid, geoInterpolate, geoOrthographic, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";

import api from "../api/client";
import Card from "../components/Card";

const DEFAULT_WIDTH = 980;
const DEFAULT_HEIGHT = 520;
const worldFeatures = feature(worldAtlas, worldAtlas.objects.countries).features;

function severityClass(severity) {
  if (severity === "critical" || severity === "high") return "critical";
  if (severity === "medium") return "medium";
  if (severity === "low") return "low";
  return "info";
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

function globeArcPath(projection, fromLonLat, toLonLat) {
  if (!projection || !fromLonLat || !toLonLat) return "";
  const interpolate = geoInterpolate(fromLonLat, toLonLat);
  const points = [];
  for (let step = 0; step <= 1.00001; step += 1 / 42) {
    const value = interpolate(step);
    const projected = projection(value);
    if (!projected) continue;
    points.push(projected);
  }
  if (points.length < 2) return "";
  return points.reduce((path, [x, y], index) => (index === 0 ? `M ${x} ${y}` : `${path} L ${x} ${y}`), "");
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
  const [activeFlowIndex, setActiveFlowIndex] = useState(0);
  const [rotation, setRotation] = useState([-18, -14]);
  const [zoom, setZoom] = useState(1.18);
  const [autoRotate, setAutoRotate] = useState(true);
  const [sourceFilter, setSourceFilter] = useState("");
  const [destinationFilter, setDestinationFilter] = useState("");
  const [mapSize, setMapSize] = useState({ width: DEFAULT_WIDTH, height: DEFAULT_HEIGHT });
  const mapShellRef = useRef(null);
  const dragStateRef = useRef(null);
  const movedRef = useRef(false);
  const pointerIdRef = useRef(null);
  const pointerElementRef = useRef(null);

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
    if (!mapShellRef.current) return undefined;
    if (typeof ResizeObserver === "undefined") return undefined;
    const element = mapShellRef.current;
    const ro = new ResizeObserver((entries) => {
      const rect = entries?.[0]?.contentRect;
      if (!rect) return;
      const width = Math.max(540, Math.floor(rect.width));
      const height = Math.max(420, Math.floor(rect.height));
      setMapSize((current) => (current.width === width && current.height === height ? current : { width, height }));
    });
    ro.observe(element);
    return () => ro.disconnect();
  }, []);

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

  useEffect(() => {
    if (!flows.length) return undefined;
    const interval = window.setInterval(() => {
      setActiveFlowIndex((current) => (current + 1) % flows.length);
    }, 2200);
    return () => window.clearInterval(interval);
  }, [flows]);

  useEffect(() => {
    if (!autoRotate) return undefined;
    const interval = window.setInterval(() => {
      setRotation((current) => [((current[0] || 0) + 0.35) % 360, current[1]]);
    }, 70);
    return () => window.clearInterval(interval);
  }, [autoRotate]);

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

  const projection = useMemo(
    () =>
      geoOrthographic()
        .scale((mapSize.width / 2.35) * zoom)
        .translate([mapSize.width / 2, mapSize.height / 2])
        .rotate([-(rotation[0] || 0), rotation[1] || -14, 0])
        .clipAngle(90)
        .precision(0.5),
    [rotation, zoom, mapSize]
  );

  const pathGenerator = useMemo(() => geoPath(projection), [projection]);

  const renderedFlows = useMemo(
    () =>
      filteredFlows
        .map((flow, index) => {
          const sourceCoords = countryLookup[normalizeCountryName(flow.source_country)]?.centroid;
          const targetCoords = countryLookup[normalizeCountryName(flow.target_country)]?.centroid;
          if (!sourceCoords || !targetCoords) return null;
          const arc = globeArcPath(projection, sourceCoords, targetCoords);
          const source = projection(sourceCoords);
          const target = projection(targetCoords);
          if (!source || !target || !arc) return null;
          return { ...flow, arc, sourcePoint: source, targetPoint: target, isActive: index === activeFlowIndex };
        })
        .filter(Boolean)
        .slice(0, 220),
    [filteredFlows, activeFlowIndex, projection]
  );

  const handlePointerDown = (event) => {
    movedRef.current = false;
    pointerIdRef.current = event.pointerId;
    pointerElementRef.current = event.currentTarget;
    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // ignore capture issues
    }
    dragStateRef.current = {
      x: event.clientX,
      y: event.clientY,
      rotation,
    };
    setAutoRotate(false);
  };

  const handlePointerMove = (event) => {
    if (!dragStateRef.current) return;
    const dx = event.clientX - dragStateRef.current.x;
    const dy = event.clientY - dragStateRef.current.y;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) movedRef.current = true;
    setRotation([
      dragStateRef.current.rotation[0] + dx * 0.28,
      Math.max(-60, Math.min(60, dragStateRef.current.rotation[1] + dy * 0.18)),
    ]);
  };

  const handlePointerUp = () => {
    if (pointerIdRef.current !== null) {
      try {
        pointerElementRef.current?.releasePointerCapture(pointerIdRef.current);
      } catch {
        // ignore
      }
    }
    pointerIdRef.current = null;
    pointerElementRef.current = null;
    dragStateRef.current = null;
  };

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
  const activeFlow = renderedFlows.find((flow) => flow.isActive) || renderedFlows[0];

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
              <button type="button" className={`scan-action ${autoRotate ? "scan-action--active" : ""}`} onClick={() => setAutoRotate((current) => !current)}>
                {autoRotate ? "Pause rotate" : "Auto rotate"}
              </button>
              <button type="button" className="scan-action" onClick={() => setZoom((current) => Math.max(0.8, Number((current - 0.1).toFixed(2))))}>Zoom out</button>
              <button type="button" className="scan-action" onClick={() => setZoom((current) => Math.min(2.2, Number((current + 0.1).toFixed(2))))}>Zoom in</button>
              <button type="button" className="scan-action" onClick={() => { setRotation([-18, -14]); setAutoRotate(false); }}>Reset view</button>
            </div>
          </div>
          <div ref={mapShellRef} className="world-map-shell world-map-shell--immersive" onWheel={(event) => {
            event.preventDefault();
            setZoom((current) => {
              const next = event.deltaY > 0 ? current - 0.08 : current + 0.08;
              return Math.max(0.8, Math.min(2.2, Number(next.toFixed(2))));
            });
          }}>
            <svg
              className="world-map world-map--immersive"
              viewBox={`0 0 ${mapSize.width} ${mapSize.height}`}
              role="img"
              aria-label="Global live attack globe"
              onPointerDown={handlePointerDown}
              onPointerMove={handlePointerMove}
              onPointerUp={handlePointerUp}
              onPointerLeave={handlePointerUp}
            >
              <defs>
                <radialGradient id="globeGlow" cx="50%" cy="42%" r="64%">
                  <stop offset="0%" stopColor="rgba(54, 174, 255, 0.18)" />
                  <stop offset="100%" stopColor="rgba(6, 15, 25, 0)" />
                </radialGradient>
              </defs>
              <circle cx={mapSize.width / 2} cy={mapSize.height / 2} r={Math.min(mapSize.width, mapSize.height) / 2.32} className="world-map__sphere" />
              <circle cx={mapSize.width / 2} cy={mapSize.height / 2} r={Math.min(mapSize.width, mapSize.height) / 2.29} fill="url(#globeGlow)" />
              <g className="world-map__countries">
                {worldFeatures.map((country) => {
                  const countryName = backendCountryName(country.properties.name);
                  const detail = state.data?.countries?.[countryName];
                  const isSelected = selectedCountry === countryName;
                  const tone = detail?.target_count ? "has-attacks" : "";
                  return (
                    <path
                      key={country.id}
                      d={pathGenerator(country)}
                      className={`world-map__country ${tone} ${isSelected ? "is-selected" : ""}`}
                      onPointerDown={handlePointerDown}
                      onPointerMove={handlePointerMove}
                      onPointerUp={handlePointerUp}
                      onPointerLeave={handlePointerUp}
                      onClick={() => {
                        if (movedRef.current) return;
                        setSelectedCountry(countryName);
                        setDetailOpen(true);
                      }}
                    />
                  );
                })}
              </g>
              <g className="world-map__flows">
                {renderedFlows.map((flow, index) => (
                  <path
                    key={flow.id}
                    d={flow.arc}
                    className={`world-map__flow world-map__flow--${severityClass(flow.severity)} ${flow.isActive ? "is-active" : ""}`}
                    style={{ "--flow-delay": `${index * 42}ms` }}
                  />
                ))}
              </g>
              <g className="world-map__points">
                {renderedFlows.flatMap((flow) => [
                  <circle
                    key={`${flow.id}-source`}
                    cx={flow.sourcePoint[0]}
                    cy={flow.sourcePoint[1]}
                    r="2.7"
                    className={`world-map__point world-map__point--source ${flow.isActive ? "is-active" : ""}`}
                  />,
                  <circle
                    key={`${flow.id}-target`}
                    cx={flow.targetPoint[0]}
                    cy={flow.targetPoint[1]}
                    r="3.1"
                    className={`world-map__point world-map__point--target ${flow.isActive ? "is-active" : ""}`}
                  />,
                ])}
              </g>
            </svg>
            <div className="world-map__overlay world-map__overlay--left">
              <div className="world-map__overlay-card">
                <span>Visible flows</span>
                <strong>{renderedFlows.length}</strong>
                <small>{windowKey} view</small>
              </div>
              <div className="world-map__overlay-card">
                <span>Attacks today</span>
                <strong>{state.data?.daily_attack_count || 0}</strong>
                <small>Continuously refreshed</small>
              </div>
            </div>
            <div className="world-map__overlay world-map__overlay--right">
              <div className="world-map__overlay-card">
                <span>Data sources</span>
                <strong>{[...new Set(renderedFlows.map((flow) => flow.ti_source || "Internal"))].slice(0, 3).join(", ") || "Internal"}</strong>
                <small>Hybrid threat intelligence</small>
              </div>
              <div className="world-map__overlay-card">
                <span>Interaction</span>
                <strong>Drag to rotate</strong>
                <small>Wheel to zoom, click countries for drill-down</small>
              </div>
            </div>
            <div className="world-map__ticker">
              {activeFlow ? (
                <div className="world-map__ticker-card">
                  <span>{activeFlow.attack_type}</span>
                  <strong>{activeFlow.source_country} to {activeFlow.target_country}</strong>
                  <small>{activeFlow.company_name ? `${activeFlow.company_name}: ` : ""}{activeFlow.title}</small>
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
          <div className="panel panel--embedded">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Operational summary</p>
                <h2>Live counter</h2>
              </div>
            </div>
            <div className="coverage-list">
              <div className="coverage-row"><span>Visible country flows</span><strong>{renderedFlows.length}</strong></div>
              <div className="coverage-row"><span>Total attack records</span><strong>{state.data?.active_flow_count || 0}</strong></div>
              <div className="coverage-row"><span>Selected country</span><strong>{selectedCountry || "None"}</strong></div>
              <div className="coverage-row"><span>Rotation</span><strong>{Math.round(rotation[0])} / {Math.round(rotation[1])}</strong></div>
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

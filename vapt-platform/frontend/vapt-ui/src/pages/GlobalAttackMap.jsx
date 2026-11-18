import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import * as THREE from "three";
import { feature } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";

import api from "../api/client";
import "../commandcenter.css";
import "../scans.css";
import "../targets.css";
import "../attackmap.css";

const WORLD = feature(worldAtlas, worldAtlas.objects.countries).features;
// Offline globe surface (no remote texture): deep-ocean colour with a faint glow.
const OCEAN = new THREE.MeshPhongMaterial({ color: 0x041a3a, emissive: 0x020b1d, shininess: 8, transparent: true, opacity: 0.96 });
const REFRESH_MS = 5 * 60 * 1000;
const TICK_MS = 4000;
const KIND = {
  attacker: { label: "Attacking source", color: "#ff6b6b", arc: ["rgba(255,107,107,0.05)", "rgba(255,107,107,0.9)"] },
  c2: { label: "Botnet C2", color: "#c084fc", arc: ["rgba(192,132,252,0.05)", "rgba(192,132,252,0.95)"] },
  malware: { label: "Malware IOC", color: "#f5d76e", arc: ["rgba(245,215,110,0.05)", "rgba(245,215,110,0.95)"] },
};
const INFOCON = { green: "#3ddc97", yellow: "#f5d76e", orange: "#ff9f5a", red: "#ff6b6b" };

// ip-api country names → world-atlas names
const COUNTRY_ALIASES = {
  "united states": "United States of America",
  "the netherlands": "Netherlands",
  "russian federation": "Russia",
  "south korea": "South Korea",
  "republic of korea": "South Korea",
  "czech republic": "Czechia",
  "bosnia and herzegovina": "Bosnia and Herz.",
  "dominican republic": "Dominican Rep.",
  "central african republic": "Central African Rep.",
  "ivory coast": "Côte d'Ivoire",
  "hong kong": "China",
};
const atlasName = (name) => COUNTRY_ALIASES[String(name || "").toLowerCase()] || name;

// world-atlas name -> ISO 3166-1 alpha-2, from the browser's own region names plus the
// abbreviations world-atlas uses. Northern Cyprus and Somaliland have no ISO code.
const ATLAS_CC = (() => {
  const map = {
    "w. sahara": "EH", "united states of america": "US", "dem. rep. congo": "CD", "dominican rep.": "DO",
    "falkland is.": "FK", "fr. s. antarctic lands": "TF", "côte d'ivoire": "CI", "central african rep.": "CF",
    "congo": "CG", "eq. guinea": "GQ", "palestine": "PS", "myanmar": "MM", "turkey": "TR", "solomon is.": "SB",
    "bosnia and herz.": "BA", "macedonia": "MK", "trinidad and tobago": "TT", "s. sudan": "SS",
  };
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "region" });
    for (let a = 65; a <= 90; a += 1) {
      for (let b = 65; b <= 90; b += 1) {
        const code = String.fromCharCode(a, b);
        try {
          const n = dn.of(code);
          if (n && n !== code && !map[n.toLowerCase()]) map[n.toLowerCase()] = code;
        } catch { /* not a region */ }
      }
    }
  } catch { /* old browser: aliases only */ }
  return map;
})();
const ccOf = (name) => ATLAS_CC[String(name || "").toLowerCase()] || "";

const when = (iso) => {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

const fmt = (n) => {
  const v = Number(n) || 0;
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)}B`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return String(v);
};

const ago = (iso, now) => {
  if (!iso) return "";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
};

function downloadBlocklist(sources, name) {
  const rows = [["ip", "type", "country", "city", "network", "reports", "targets", "last_seen", "feed"]];
  sources.forEach((s) => rows.push([s.ip, KIND[s.kind]?.label || s.kind, s.country, s.city, s.asn, s.reports, s.targets, s.last_seen, s.feed]));
  const csv = rows.map((r) => r.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function GlobalAttackMap() {
  const globeRef = useRef(null);
  const shellRef = useRef(null);
  const rootRef = useRef(null);
  const [size, setSize] = useState({ width: 800, height: 560 });
  const [windowKey, setWindowKey] = useState("7d");
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [kind, setKind] = useState("all");
  const [country, setCountry] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);
  const [tick, setTick] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [fullscreen, setFullscreen] = useState(false);
  const [detail, setDetail] = useState(null); // { cc, name, status, data }
  const [activity, setActivity] = useState({}); // ip -> per-source DShield activity

  const load = useCallback(async () => {
    try {
      const res = await api.get("/threat-intelligence/live-map", { params: { window: windowKey } });
      setData(res.data);
      setStatus("ready");
    } catch {
      setStatus((s) => (s === "ready" ? "ready" : "error"));
    }
  }, [windowKey]);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const id = window.setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [load]);

  // Ticker + clock
  useEffect(() => {
    const id = window.setInterval(() => {
      setTick((t) => t + 1);
      setNow(Date.now());
    }, TICK_MS);
    return () => window.clearInterval(id);
  }, []);

  // Globe sizing
  useEffect(() => {
    const el = shellRef.current;
    if (!el) return undefined;
    const ro = new ResizeObserver(() => setSize({ width: el.clientWidth, height: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === rootRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const home = data?.home;

  const visible = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.sources.filter((s) => (kind === "all" || s.kind === kind || (kind === "c2" && s.kind === "malware"))
      && (!country || s.country === country)
      && (!q || `${s.ip} ${s.asn} ${s.city} ${s.country}`.toLowerCase().includes(q)));
  }, [data, kind, country, query]);

  const featured = visible.length ? visible[tick % Math.min(visible.length, 40)] : null;

  // Globe layers
  const maxReports = useMemo(() => Math.max(1, ...visible.map((s) => s.reports)), [visible]);
  const points = useMemo(() => visible.map((s) => ({
    ...s,
    size: s.kind === "attacker" ? 0.12 + Math.log10(1 + s.reports) / Math.log10(1 + maxReports) * 0.5 : 0.35,
  })), [visible, maxReports]);
  const arcs = useMemo(() => {
    if (!home) return [];
    return visible.slice(0, 160).map((s, i) => ({
      ...s,
      startLat: s.lat,
      startLng: s.lon,
      endLat: home.lat,
      endLng: home.lon,
      delay: (i % 20) * 350,
    }));
  }, [visible, home]);
  const victimsByCc = data?.victims_by_country || {};
  const worldWithBox = useMemo(() => WORLD.map((f) => {
    if (f.bbox) return f;
    let minX = 180; let minY = 90; let maxX = -180; let maxY = -90;
    const walk = (c) => {
      if (typeof c[0] === "number") {
        minX = Math.min(minX, c[0]); maxX = Math.max(maxX, c[0]); minY = Math.min(minY, c[1]); maxY = Math.max(maxY, c[1]);
      } else c.forEach(walk);
    };
    walk(f.geometry.coordinates);
    return { ...f, bbox: [minX, minY, maxX, maxY] };
  }), []);
  const countryVolume = useMemo(() => {
    const m = {};
    (data?.countries || []).forEach((c) => { m[atlasName(c.country)] = c; });
    return m;
  }, [data]);
  const maxCountry = useMemo(() => Math.max(1, ...Object.values(countryVolume).map((c) => c.reports || c.sources)), [countryVolume]);
  const rings = useMemo(() => {
    const r = home ? [{ lat: home.lat, lng: home.lon, color: "#5ce1ff", speed: 2, max: 6 }] : [];
    if (featured) r.push({ lat: featured.lat, lng: featured.lon, color: KIND[featured.kind].color, speed: 3, max: 4 });
    return r;
  }, [home, featured]);

  useEffect(() => {
    const g = globeRef.current;
    if (!g) return;
    const controls = g.controls();
    controls.autoRotate = !selected && !country && !detail;
    controls.autoRotateSpeed = 0.45;
    if (home && !selected && !country && !detail) g.pointOfView({ lat: home.lat + 12, lng: home.lon - 25, altitude: 2.3 }, 1200);
  }, [home, selected, country, detail]);

  const focus = (lat, lng) => globeRef.current?.pointOfView({ lat, lng, altitude: 1.6 }, 900);

  const loadDetail = useCallback(async (cc, name) => {
    setDetail({ cc, name, status: "loading", data: null });
    try {
      const res = await api.get(`/threat-intelligence/live-map/country/${cc}`, { params: { window: windowKey } });
      setDetail((d) => (d && d.cc === cc ? { cc, name: res.data.country || name, status: "ready", data: res.data } : d));
    } catch (err) {
      const code = err?.response?.status;
      const reason = code === 401 || code === 403
        ? "Your session has ended. Sign in again to load country details."
        : code
          ? `The server couldn't build the details (HTTP ${code}${err.response?.data?.detail ? `: ${err.response.data.detail}` : ""}).`
          : "Couldn't reach the VAPT server. Check your connection and try again.";
      setDetail((d) => (d && d.cc === cc ? { ...d, status: "error", reason } : d));
    }
  }, [windowKey]);

  // Reload the open country when the time window changes (loadDetail changes with windowKey).
  useEffect(() => {
    if (detail?.cc && detail.status !== "loading") loadDetail(detail.cc, detail.name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadDetail]);

  // Clicking any country opens its detail, whether or not attacks originate there
  // (it may still have organisations claimed by ransomware groups).
  const pickCountry = (name, polygon) => {
    const c = (data?.countries || []).find((x) => x.country === name || atlasName(x.country) === name);
    const cc = c?.cc || ccOf(name);
    setSelected(null);
    if (c) {
      setCountry(c.country);
      focus(c.lat, c.lon);
    } else {
      setCountry("");
      if (polygon?.bbox) focus((polygon.bbox[1] + polygon.bbox[3]) / 2, (polygon.bbox[0] + polygon.bbox[2]) / 2);
    }
    if (cc) loadDetail(cc, c?.country || name);
    else setDetail({ cc: "", name, status: "nocode", data: null });
  };

  const closeCountry = () => {
    setCountry("");
    setDetail(null);
  };

  const pickSource = (s) => {
    setSelected(s);
    focus(s.lat, s.lon);
    if (s.kind === "attacker" && !activity[s.ip]) {
      setActivity((a) => ({ ...a, [s.ip]: { status: "loading" } }));
      api.get(`/threat-intelligence/live-map/source/${s.ip}`)
        .then((res) => setActivity((a) => ({ ...a, [s.ip]: { status: "ready", ...res.data } })))
        .catch(() => setActivity((a) => ({ ...a, [s.ip]: { status: "error" } })));
    }
  };

  const toggleFullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else rootRef.current?.requestFullscreen?.();
  };

  const countryRows = data?.countries || [];
  const c2 = (data?.sources || []).filter((s) => s.kind !== "attacker");
  const allC2Feed = data?.feeds?.feodo;

  return (
    <div ref={rootRef} className={`cc am${fullscreen ? " cc--fullscreen" : ""}`}>
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Global Threat Map</h1>
        </div>
        <div className="cc-top__tools">
          <div className="cc-range" role="group" aria-label="Last seen within">
            {[["24h", "24 hr"], ["7d", "7 days"], ["30d", "30 days"]].map(([k, l]) => (
              <button key={k} type="button" aria-pressed={windowKey === k} onClick={() => setWindowKey(k)}>{l}</button>
            ))}
          </div>
          <span className="cc-clock">{data ? `feeds ${ago(data.generated_at, now)} · auto-refresh 5 min` : "connecting…"}</span>
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
          <button type="button" className="cc-btn" onClick={toggleFullscreen}>{fullscreen ? "Exit full screen" : "Full screen"}</button>
        </div>
      </header>

      <div className="cc-kpis">
        <div className="cc-kpi cc-kpi--hot"><span>Active attack sources</span><strong>{data?.summary.attackers ?? "—"}</strong></div>
        <div className="cc-kpi"><span>Source countries</span><strong>{data?.summary.countries ?? "—"}</strong></div>
        <div className="cc-kpi"><span>Attack reports</span><strong>{data ? fmt(data.summary.reports) : "—"}</strong></div>
        <div className="cc-kpi"><span>Botnet C2 servers</span><strong>{data?.summary.c2 ?? "—"}</strong></div>
        <div className="cc-kpi am-infocon" style={{ "--ic": INFOCON[data?.infocon] || "#8ea3bd" }}>
          <span>Internet threat level</span><strong>{data?.infocon ? data.infocon.toUpperCase() : "—"}</strong>
        </div>
        <div className="cc-kpi"><span>Most targeted port</span><strong>{data?.top_ports?.[0] ? `${data.top_ports[0].port}` : "—"}</strong></div>
      </div>

      <div className="am-layout">
        <section className="cc-panel am-globe-panel" aria-label="Live threat globe">
          <header className="cc-panel__head">
            <h2>Live attack sources → {home ? `${home.city || home.country}` : "your network"}</h2>
            <div className="am-filters">
              <div className="cc-range" role="group" aria-label="Source type">
                {[["all", "All"], ["attacker", "Attackers"], ["c2", "Botnet / malware"]].map(([k, l]) => (
                  <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}>{l}</button>
                ))}
              </div>
              <label>
                <span className="cc-sr">Search IP, network or city</span>
                <input type="search" className="so-input am-search" placeholder="Search IP, network, city" value={query} onChange={(e) => setQuery(e.target.value)} />
              </label>
              {(country || selected || detail) && (
                <button type="button" className="cc-btn" onClick={() => { closeCountry(); setSelected(null); }}>
                  Clear {detail?.name || country || "selection"}
                </button>
              )}
            </div>
          </header>

          <div ref={shellRef} className="am-globe">
            {status === "error" && !data ? (
              <p className="cc-empty am-globe__msg">Couldn't reach the threat feeds. The server needs internet access to SANS ISC and abuse.ch.</p>
            ) : (
              <Globe
                ref={globeRef}
                width={size.width}
                height={size.height}
                backgroundColor="rgba(0,0,0,0)"
                showAtmosphere
                atmosphereColor="#2e7bff"
                atmosphereAltitude={0.18}
                globeMaterial={OCEAN}
                polygonsData={worldWithBox}
                polygonAltitude={(f) => (countryVolume[f.properties.name] ? 0.012 : 0.006)}
                polygonCapColor={(f) => {
                  const c = countryVolume[f.properties.name];
                  if (!c) return "rgba(20, 44, 82, 0.85)";
                  const t = Math.log10(1 + (c.reports || c.sources)) / Math.log10(1 + maxCountry);
                  return `rgba(255, ${Math.round(140 - t * 90)}, ${Math.round(110 - t * 70)}, ${0.35 + t * 0.5})`;
                }}
                polygonSideColor={() => "rgba(46, 123, 255, 0.15)"}
                polygonStrokeColor={(f) => {
                  const cc = ccOf(f.properties.name);
                  if (detail && detail.cc && cc === detail.cc) return "#ffffff";
                  return victimsByCc[cc] ? "rgba(245, 215, 110, 0.9)" : "rgba(92, 225, 255, 0.35)";
                }}
                polygonLabel={(f) => {
                  const c = countryVolume[f.properties.name];
                  const v = victimsByCc[ccOf(f.properties.name)];
                  return `<div class="am-tip"><b>${f.properties.name}</b>${c ? `<br/>${c.sources} attack sources · ${fmt(c.reports)} reports` : "<br/>No reported attack sources"}${v ? `<br/>${v} organisation${v === 1 ? "" : "s"} claimed by ransomware (48 h)` : ""}<br/><i>Click for details</i></div>`;
                }}
                onPolygonClick={(f) => pickCountry(f.properties.name, f)}
                pointsData={points}
                pointLat="lat"
                pointLng="lon"
                pointAltitude={(d) => (selected && d.ip === selected.ip ? 0.08 : 0.02)}
                pointRadius="size"
                pointColor={(d) => (selected && d.ip === selected.ip ? "#ffffff" : KIND[d.kind].color)}
                pointLabel={(d) => `<div class="am-tip"><b>${d.ip}</b><br/>${KIND[d.kind].label}${d.malware ? ` · ${d.malware}` : ""}<br/>${[d.city, d.country].filter(Boolean).join(", ")}<br/>${d.asn || ""}${d.reports ? `<br/>${fmt(d.reports)} reports · ${d.targets} targets` : ""}</div>`}
                onPointClick={(d) => pickSource(d)}
                arcsData={arcs}
                arcColor={(d) => (featured && d.ip === featured.ip ? ["rgba(255,255,255,0.2)", "#ffffff"] : KIND[d.kind].arc)}
                arcStroke={(d) => (featured && d.ip === featured.ip ? 0.9 : 0.35)}
                arcAltitudeAutoScale={0.45}
                arcDashLength={0.35}
                arcDashGap={1.2}
                arcDashInitialGap={(d) => (d.delay / 1000) % 2}
                arcDashAnimateTime={2600}
                arcsTransitionDuration={0}
                ringsData={rings}
                ringColor={(d) => (t) => `${d.color}${Math.round((1 - t) * 255).toString(16).padStart(2, "0")}`}
                ringMaxRadius="max"
                ringPropagationSpeed="speed"
                ringRepeatPeriod={1400}
                labelsData={home ? [{ lat: home.lat, lng: home.lon, text: "Your network" }] : []}
                labelText="text"
                labelSize={1.1}
                labelDotRadius={0.5}
                labelColor={() => "#5ce1ff"}
                labelResolution={2}
              />
            )}

            {featured && (
              <button type="button" className="am-ticker" onClick={() => pickSource(featured)} aria-live="polite">
                <span className="am-ticker__kind" style={{ color: KIND[featured.kind].color }}>● {KIND[featured.kind].label}{featured.malware ? ` · ${featured.malware}` : ""}</span>
                <strong className="cc-mono">{featured.ip}</strong>
                <span>{[featured.city, featured.country].filter(Boolean).join(", ")} · {featured.asn}</span>
                {featured.reports > 0 && <span className="cc-muted">{fmt(featured.reports)} reports against {featured.targets} targets · last seen {featured.last_seen}</span>}
              </button>
            )}

            <ul className="am-legend" aria-label="Legend">
              {Object.entries(KIND).map(([k, v]) => <li key={k}><span style={{ background: v.color }} />{v.label}</li>)}
              <li><span style={{ background: "#5ce1ff" }} />Your network</li>
              <li><span className="am-legend__outline" />Ransomware victims (48 h)</li>
            </ul>
          </div>
          <p className="am-note">{data?.note}</p>
        </section>

        <aside className="am-rail">
          {selected && (
            <section className="cc-panel am-detail" aria-label="Selected source">
              <header className="cc-panel__head">
                <h2>Source detail</h2>
                <button type="button" className="cc-icon" aria-label="Close source detail" onClick={() => setSelected(null)}>×</button>
              </header>
              <p className="am-detail__ip cc-mono">{selected.ip}</p>
              <dl className="ti-facts">
                <div><dt>Type</dt><dd>{KIND[selected.kind].label}{selected.malware ? ` · ${selected.malware}` : ""}</dd></div>
                <div><dt>Location</dt><dd>{[selected.city, selected.country].filter(Boolean).join(", ")}</dd></div>
                <div><dt>Network</dt><dd>{selected.asn || "—"}</dd></div>
                <div><dt>Feed</dt><dd>{selected.feed}</dd></div>
                {selected.reports > 0 && <div><dt>Reports</dt><dd className="cc-mono">{selected.reports.toLocaleString()}</dd></div>}
                {selected.targets > 0 && <div><dt>Targets hit</dt><dd className="cc-mono">{selected.targets}</dd></div>}
                <div><dt>First seen</dt><dd>{selected.first_seen || "—"}</dd></div>
                <div><dt>Last seen</dt><dd>{selected.last_seen || "—"}</dd></div>
              </dl>
              {selected.kind === "attacker" && (() => {
                const act = activity[selected.ip];
                if (!act || act.status === "loading") return <p className="cc-muted am-sub">Loading what this source attacked…</p>;
                if (act.status === "error" || !act.available) return <p className="cc-muted am-sub">DShield has no per-port log for this source right now.</p>;
                return (
                  <div className="am-activity">
                    <h3>What it attacked</h3>
                    <ul className="am-types">
                      {act.attack_types.slice(0, 5).map((t) => <li key={t.type}><span>{t.type}</span><span className="cc-mono">{fmt(t.hits)}</span></li>)}
                    </ul>
                    <p className="cc-muted am-sub">
                      Ports: {act.ports.map((p) => `${p.port}${p.service ? ` ${p.service}` : ""}`).join(", ")}
                      {act.distinct_ports > act.ports.length ? ` +${act.distinct_ports - act.ports.length} more` : ""} · last activity {when(act.last_activity)}
                    </p>
                    <p className="cc-muted am-sub">Targets were SANS DShield sensors. Attack type is inferred from the ports hit.</p>
                  </div>
                );
              })()}
              <div className="ti-drawer__actions">
                <a className="cc-btn" href={`https://isc.sans.edu/ipinfo/${encodeURIComponent(selected.ip)}`} target="_blank" rel="noreferrer">SANS ISC record</a>
                <a className="cc-btn" href={`https://www.abuseipdb.com/check/${encodeURIComponent(selected.ip)}`} target="_blank" rel="noreferrer">AbuseIPDB</a>
              </div>
            </section>
          )}

          {detail && (
            <section className="cc-panel am-country" aria-label={`${detail.name} details`}>
              <header className="cc-panel__head">
                <h2>{detail.name}{detail.cc ? <span className="cc-muted am-cc"> {detail.cc}</span> : null}</h2>
                <div className="am-head-actions">
                  {country && <button type="button" className="cc-btn" onClick={() => downloadBlocklist(visible, `blocklist_${country.replace(/\W+/g, "_")}.csv`)}>Blocklist CSV</button>}
                  <button type="button" className="cc-icon" aria-label="Close country details" onClick={closeCountry}>×</button>
                </div>
              </header>

              {detail.status === "loading" && <p className="cc-muted am-sub">Pulling live attack logs and published victims for {detail.name}…</p>}
              {detail.status === "error" && (
                <p className="cc-empty">
                  {detail.reason}{" "}
                  <button type="button" className="am-linkbtn" onClick={() => loadDetail(detail.cc, detail.name)}>Retry</button>
                </p>
              )}
              {detail.status === "nocode" && <p className="cc-empty">{detail.name} has no ISO country code, so the feeds can't be queried for it.</p>}

              {detail.status === "ready" && (() => {
                const out = detail.data.outbound;
                const inn = detail.data.inbound;
                const maxType = Math.max(1, ...out.attack_types.map((t) => t.hits));
                return (
                  <>
                    <h3 className="am-h3">Attacks launched from {detail.name}</h3>
                    {out.attackers ? (
                      <>
                        <p className="cc-muted am-sub">
                          {out.attackers} active source{out.attackers === 1 ? "" : "s"} · {fmt(out.reports)} reports ({detail.data.window}) · top {out.examined} examined
                          {out.research_scanners ? ` (${out.research_scanners} known research scanner${out.research_scanners === 1 ? "" : "s"})` : ""}
                        </p>
                        <ol className="cc-bars am-typebars">
                          {out.attack_types.slice(0, 6).map((t) => (
                            <li key={t.type}>
                              <span className="cc-bars__name am-ellipsis" title={t.type}>{t.type}</span>
                              <div className="cc-bars__track" aria-hidden="true"><span className="cc-fill--critical" style={{ width: `${(t.hits / maxType) * 100}%` }} /></div>
                              <span className="cc-bars__value">{t.sources} IP{t.sources === 1 ? "" : "s"}</span>
                            </li>
                          ))}
                        </ol>
                        <ul className="cc-list am-scroll am-srcs">
                          {out.top_sources.map((s) => {
                            const src = (data?.sources || []).find((x) => x.ip === s.ip);
                            return (
                              <li key={s.ip}>
                                <span className="cc-dot" style={{ background: KIND.attacker.color }} />
                                <span className="am-src">
                                  <button type="button" className="ti-name cc-mono" onClick={() => src && pickSource(src)}>{s.ip}</button>
                                  <span className="cc-muted am-ellipsis" title={s.network}>{s.network}</span>
                                  <span className="am-chips">
                                    {s.research_scanner
                                      ? <span className="am-chip am-chip--research">Research scanner (internet survey)</span>
                                      : s.attack_types.map((t) => <span key={t} className="am-chip">{t}</span>)}
                                  </span>
                                  {s.ports.length > 0 && <span className="cc-muted am-sub">ports {s.ports.map((p) => p.port).join(", ")}{s.distinct_ports > s.ports.length ? ` +${s.distinct_ports - s.ports.length}` : ""} · {when(s.last_activity)}</span>}
                                </span>
                              </li>
                            );
                          })}
                        </ul>
                        <p className="am-note am-note--tight">{out.type_note} {out.destination_note}</p>
                      </>
                    ) : <p className="cc-muted am-sub">No attack sources from {detail.name} in the {detail.data.window} window.</p>}

                    {out.botnets.length > 0 && (
                      <>
                        <h3 className="am-h3">Botnet C2 servers hosted here</h3>
                        <ul className="cc-list">
                          {out.botnets.map((b) => <li key={b.family}><span className="cc-dot" style={{ background: KIND.c2.color }} /><span>{b.family}</span><span className="cc-muted cc-right">{b.servers} server{b.servers === 1 ? "" : "s"}</span></li>)}
                        </ul>
                      </>
                    )}

                    <h3 className="am-h3">Organisations attacked in {detail.name}</h3>
                    {inn.victims.length ? (
                      <>
                        <p className="cc-muted am-sub">{inn.total} claimed by ransomware groups · {inn.scope}</p>
                        <ul className="cc-list am-scroll am-victims">
                          {inn.victims.map((v) => (
                            <li key={`${v.victim}-${v.group}-${v.discovered}`}>
                              <span className="cc-dot" style={{ background: "#f5d76e" }} />
                              <span className="am-src">
                                {v.url ? <a className="ti-name" href={v.url} target="_blank" rel="noreferrer">{v.victim}</a> : <strong>{v.victim}</strong>}
                                <span className="cc-muted">{[v.sector, v.website].filter(Boolean).join(" · ") || "Sector not published"}</span>
                                <span className="am-chips"><span className="am-chip am-chip--group">Ransomware: {v.group}</span><span className="cc-muted am-sub">claimed {when(v.discovered)}</span></span>
                              </span>
                            </li>
                          ))}
                        </ul>
                      </>
                    ) : <p className="cc-muted am-sub">No organisations in {detail.name} have been claimed by ransomware groups in the last 12 months.</p>}
                    <p className="am-note am-note--tight">{inn.note} Source: ransomware.live.</p>
                  </>
                );
              })()}
            </section>
          )}

          <section className="cc-panel" aria-label="Top source countries">
            <header className="cc-panel__head"><h2>Top source countries</h2><span className="cc-muted">click to focus</span></header>
            <ol className="cc-bars">
              {countryRows.slice(0, 8).map((c) => (
                <li key={c.country}>
                  <button type="button" className="cc-bars__name am-linkbtn" onClick={() => pickCountry(c.country)}>{c.country}</button>
                  <div className="cc-bars__track" aria-hidden="true">
                    <span className="cc-fill--critical" style={{ width: `${(c.reports / Math.max(1, countryRows[0]?.reports || 1)) * 100}%` }} />
                  </div>
                  <span className="cc-bars__value">{fmt(c.reports)}</span>
                </li>
              ))}
              {!countryRows.length && <li className="cc-muted">{status === "loading" ? "Loading feeds…" : "No sources in this window."}</li>}
            </ol>
          </section>

          <section className="cc-panel" aria-label="Most targeted ports">
            <header className="cc-panel__head"><h2>Most targeted ports</h2><span className="cc-muted">DShield sensors</span></header>
            <ul className="cc-list">
              {(data?.top_ports || []).slice(0, 8).map((p) => (
                <li key={p.port}>
                  <span className="cc-mono am-port">{p.port}</span>
                  <span>{p.service || "—"}</span>
                  <span className="cc-muted cc-right">{fmt(p.records)} hits · {fmt(p.sources)} sources</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="cc-panel" aria-label="Top source networks">
            <header className="cc-panel__head"><h2>Top source networks</h2></header>
            <ul className="cc-list">
              {(data?.networks || []).slice(0, 7).map((n) => (
                <li key={n.asn}>
                  <span className="am-ellipsis" title={n.asn}>{n.asn}</span>
                  <span className="cc-muted cc-right">{n.sources} IPs · {fmt(n.reports)}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className="cc-panel" aria-label="Botnet command and control">
            <header className="cc-panel__head"><h2>Botnet C2 servers</h2><span className="cc-muted">Feodo Tracker</span></header>
            {c2.length ? (
              <ul className="cc-list">
                {c2.slice(0, 8).map((s) => (
                  <li key={s.id}>
                    <span className="cc-dot" style={{ background: KIND[s.kind].color }} />
                    <button type="button" className="ti-name cc-mono" onClick={() => pickSource(s)}>{s.ip}</button>
                    <span className="cc-muted am-ellipsis">{s.malware} · {s.country}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="cc-empty">
                No active C2 servers in this window{allC2Feed?.count ? ` (${allC2Feed.count} tracked, last online earlier)` : ""}. Try 30 days.
              </p>
            )}
          </section>

          <section className="cc-panel" aria-label="Feed status">
            <header className="cc-panel__head">
              <h2>Feeds</h2>
              <button type="button" className="cc-btn" disabled={!visible.length} onClick={() => downloadBlocklist(visible, "threat_blocklist.csv")}>Blocklist CSV</button>
            </header>
            <ul className="cc-list">
              {Object.entries(data?.feeds || {}).map(([name, f]) => (
                <li key={name} className="am-feed">
                  <span className={`cc-dot cc-dot--${f.status === "connected" ? "healthy" : f.status === "needs_key" ? "medium" : "down"}`} />
                  <span>
                    <strong>{{ dshield: "SANS ISC / DShield", feodo: "abuse.ch Feodo Tracker", threatfox: "abuse.ch ThreatFox", ransomware_live: "ransomware.live" }[name] || name}</strong>
                    <span className="cc-muted am-feed__detail">{f.status === "connected" ? `${f.count} records · ${f.detail}` : f.detail}</span>
                  </span>
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </div>
  );
}

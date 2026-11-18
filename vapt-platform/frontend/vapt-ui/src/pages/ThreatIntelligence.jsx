import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import api from "../api/client";
import TodayIntel from "../components/TodayIntel";
import "../misconfig.css";
import "../commandcenter.css";
import "../scans.css";
import "../targets.css";
import "../attackmap.css";
import "../intel.css";

const pct = (v, digits = 1) => (v == null ? "—" : `${(v * 100).toFixed(digits)}%`);
const VERDICT = {
  malicious: { label: "Malicious", tone: "bad" },
  suspicious: { label: "Suspicious", tone: "warn" },
  clean: { label: "No known bad reputation", tone: "good" },
  unknown: { label: "Not enough data", tone: "info" },
};
const RISKY = new Set([21, 23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 27017]);

function EpssBar({ value, percentile }) {
  if (value == null) return <span className="cc-muted">no score</span>;
  const tone = value >= 0.5 ? "bad" : value >= 0.1 ? "warn" : "ok";
  return (
    <div className="ti-epss" title={`EPSS ${pct(value, 2)} · percentile ${pct(percentile, 0)}`}>
      <div className="ti-epss__track" aria-hidden="true"><span className={`ti-epss__fill ti-epss__fill--${tone}`} style={{ width: `${Math.max(2, value * 100)}%` }} /></div>
      <span className="cc-mono">{pct(value)}</span>
    </div>
  );
}

function Lookup({ initial }) {
  const [query, setQuery] = useState(initial || "");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const run = useCallback(async (value) => {
    const q = (value ?? query).trim();
    if (!q) return;
    setBusy(true);
    setError("");
    try {
      const res = await api.get("/threat-intelligence/lookup", { params: { q } });
      if (res.data.error) {
        setError(res.data.error);
        setResult(null);
      } else {
        setResult(res.data);
      }
    } catch {
      setError("The lookup failed. Check the API's internet access and try again.");
    } finally {
      setBusy(false);
    }
  }, [query]);

  useEffect(() => {
    if (initial) {
      const id = window.setTimeout(() => run(initial), 0);
      return () => window.clearTimeout(id);
    }
    return undefined;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial]);

  const v = result ? VERDICT[result.verdict.level] : null;
  const idb = result?.internetdb;
  const gn = result?.greynoise;
  const ds = result?.dshield;

  return (
    <section className="cc-panel ti-lookup" aria-label="Indicator lookup">
      <header className="cc-panel__head"><h2>Indicator lookup</h2><span className="cc-muted">IP or domain</span></header>
      <form className="ti-lookup__form" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <label className="so-search">
          <span className="cc-sr">IP address or domain</span>
          <input type="search" placeholder="e.g. 79.124.49.114 or example.com" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <button type="submit" className="so-launch-btn ti-lookup__go" disabled={busy || !query.trim()}>{busy ? "Checking…" : "Check"}</button>
      </form>
      {busy && <p className="cc-muted">Querying Shodan InternetDB, GreyNoise, SANS ISC and your own data…</p>}
      {error && <p className="so-error" role="alert">{error}</p>}

      {result && (
        <div className="ti-result" aria-live="polite">
          <div className={`ti-verdict ti-verdict--${v.tone}`}>
            <span>VERDICT</span>
            <strong>{result.verdict.text}</strong>
          </div>
          {result.verdict.reasons.length > 0 ? (
            <ul className="ti-reasons">
              {result.verdict.reasons.map((r) => <li key={r.text} className={`ti-reason ti-reason--${r.tone}`}>{r.text}</li>)}
            </ul>
          ) : <p className="cc-muted">No source reported anything notable about this indicator.</p>}

          <dl className="ti-facts">
            <div><dt>{result.kind === "domain" ? "Resolves to" : "Address"}</dt><dd className="cc-mono">{result.resolved.join(", ") || "—"}</dd></div>
            {result.reverse_dns && <div><dt>Reverse DNS</dt><dd className="cc-mono">{result.reverse_dns}</dd></div>}
            {result.geo && <div><dt>Location</dt><dd>{[result.geo.city, result.geo.country].filter(Boolean).join(", ")}</dd></div>}
            {(result.geo?.asn || ds?.network) && <div><dt>Network</dt><dd>{result.geo?.asn || ds?.network}</dd></div>}
            {result.geo?.hosting != null && <div><dt>Hosting / proxy</dt><dd>{result.geo.hosting ? "Hosting provider" : "Not hosting"}{result.geo.proxy ? " · proxy/VPN" : ""}</dd></div>}
            {ds?.abuse_contact && <div><dt>Abuse contact</dt><dd className="cc-mono">{ds.abuse_contact}</dd></div>}
          </dl>

          {idb && (
            <div className="ti-block">
              <h3>Shodan InternetDB</h3>
              {idb.not_seen ? <p className="cc-muted">Not seen by Shodan.</p> : (
                <>
                  <div className="ti-chips">
                    {(idb.ports || []).map((p) => <span key={p} className={`ti-chip${RISKY.has(p) ? " ti-chip--risky" : ""}`}>{p}</span>)}
                    {!idb.ports?.length && <span className="cc-muted">No open ports recorded.</span>}
                  </div>
                  {(idb.hostnames || []).length > 0 && <p className="cc-muted cc-mono">{idb.hostnames.slice(0, 6).join(", ")}</p>}
                  {(idb.tags || []).length > 0 && <p className="cc-muted">Tags: {idb.tags.join(", ")}</p>}
                </>
              )}
              {result.host_cves.length > 0 && (
                <ul className="ti-cvelist">
                  {result.host_cves.slice(0, 10).map((c) => (
                    <li key={c.cve}>
                      <a className="cc-mono" href={`https://nvd.nist.gov/vuln/detail/${c.cve}`} target="_blank" rel="noreferrer">{c.cve}</a>
                      {c.kev && <span className="ti-badge-kev">KEV</span>}
                      {c.ransomware && <span className="ti-badge-ransom">Ransomware</span>}
                      <span className="cc-muted cc-right">EPSS {pct(c.epss)}</span>
                    </li>
                  ))}
                  {result.host_cves.length > 10 && <li className="cc-muted">…and {result.host_cves.length - 10} more</li>}
                </ul>
              )}
            </div>
          )}

          {gn && (
            <div className="ti-block">
              <h3>GreyNoise</h3>
              <p>
                {gn.noise ? "Seen scanning the internet" : "Not seen scanning"}
                {gn.riot ? " · known benign service" : ""}
                {gn.classification && gn.classification !== "unknown" ? ` · classified ${gn.classification}` : ""}
                {gn.last_seen ? ` · last seen ${gn.last_seen}` : ""}
                {gn.link && <> · <a href={gn.link} target="_blank" rel="noreferrer">details</a></>}
              </p>
            </div>
          )}

          {(result.virustotal || result.abuseipdb || result.otx) && (
            <div className="ti-block">
              <h3>Additional sources</h3>
              {result.virustotal && <p>VirusTotal: {result.virustotal.malicious} malicious, {result.virustotal.suspicious} suspicious · <a href={result.virustotal.link} target="_blank" rel="noreferrer">report</a></p>}
              {result.abuseipdb && <p>AbuseIPDB: {result.abuseipdb.score}% confidence, {result.abuseipdb.reports} reports</p>}
              {result.otx && <p>AlienVault OTX: {result.otx.pulses} pulses</p>}
            </div>
          )}

          <div className="ti-block">
            <h3>In your environment</h3>
            {result.environment.assets.length === 0 && result.environment.findings.length === 0 ? (
              <p className="cc-muted">Not one of your targets, and no findings reference it.</p>
            ) : (
              <>
                {result.environment.assets.map((a) => <p key={a.id}>Target <strong>{a.name}</strong> ({a.criticality})</p>)}
                <ul className="cc-list">
                  {result.environment.findings.slice(0, 8).map((f) => (
                    <li key={f.id}>
                      <span className={`nw-sev nw-sev--${f.severity}`}>{f.severity}</span>
                      <Link to={`/findings/${f.id}`} className="ti-name am-ellipsis">{f.title}</Link>
                    </li>
                  ))}
                </ul>
                {result.environment.findings.length > 8 && <Link className="cc-btn" to={`/findings?target=${encodeURIComponent(result.query)}`}>All {result.environment.findings.length} findings</Link>}
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export default function ThreatIntelligence() {
  const [searchParams] = useSearchParams();
  const [exposure, setExposure] = useState(null);
  const [kev, setKev] = useState(null);
  const [sources, setSources] = useState([]);
  const [filter, setFilter] = useState("all");
  const [kevDays, setKevDays] = useState(30);
  const [kevEnvOnly, setKevEnvOnly] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [e, s] = await Promise.all([api.get("/threat-intelligence/exposure"), api.get("/threat-intelligence/sources")]);
      setExposure(e.data);
      setSources(s.data);
    } catch {
      setError("Couldn't load threat intelligence. The API needs internet access to CISA and FIRST.");
    }
  }, []);

  useEffect(() => {
    const id = window.setTimeout(load, 0);
    return () => window.clearTimeout(id);
  }, [load]);

  useEffect(() => {
    api.get("/threat-intelligence/kev/recent", { params: { days: kevDays } }).then((r) => setKev(r.data)).catch(() => setKev(null));
  }, [kevDays]);

  const rows = useMemo(() => {
    const all = exposure?.cves || [];
    if (filter === "possible") return all.filter((r) => r.confirmed === false);
    const list = all.filter((r) => r.confirmed !== false);
    if (filter === "kev") return list.filter((r) => r.kev);
    if (filter === "epss") return list.filter((r) => (r.epss || 0) >= 0.1);
    return list;
  }, [exposure, filter]);

  const kevItems = (kev?.items || []).filter((i) => !kevEnvOnly || i.in_environment);
  const s = exposure?.summary;

  return (
    <div className="cc ti-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Threat Intelligence</h1>
        </div>
        <div className="cc-top__tools">
          {exposure && <span className="cc-clock">CISA KEV {exposure.kev_version || "—"} · {exposure.kev_size.toLocaleString()} exploited CVEs</span>}
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
          <Link className="cc-btn" to="/attack-map">Global threat map</Link>
        </div>
      </header>

      <div className="cc-kpis">
        <div className="cc-kpi"><span>CVEs in your environment</span><strong>{s?.distinct_cves ?? "—"}</strong></div>
        <div className="cc-kpi cc-kpi--hot"><span>Actively exploited (KEV)</span><strong>{s?.in_kev ?? "—"}</strong></div>
        <div className="cc-kpi cc-kpi--hot"><span>Used by ransomware</span><strong>{s?.ransomware ?? "—"}</strong></div>
        <div className="cc-kpi"><span>EPSS ≥ 10%</span><strong>{s?.high_epss ?? "—"}</strong></div>
        <div className="cc-kpi"><span>Findings with a CVE</span><strong>{s ? `${s.findings_with_cve}/${s.open_findings}` : "—"}</strong></div>
      </div>

      {error && <p className="so-error" role="alert">{error}</p>}

      <TodayIntel focusCve={searchParams.get("cve") || ""} focusTab={searchParams.get("today") || ""} />

      <div className="ti-layout">
        <section className="cc-panel ti-exposure" aria-label="Exploitation priority">
          <header className="cc-panel__head">
            <h2>Fix first: exploitation priority</h2>
            <div className="cc-range" role="group" aria-label="Filter CVEs">
              {[["all", "Confirmed CVEs"], ["kev", "Actively exploited"], ["epss", "EPSS ≥ 10%"], ["possible", `Unconfirmed${s?.possible_cves ? ` (${s.possible_cves})` : ""}`]].map(([k, l]) => (
                <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>
              ))}
            </div>
          </header>
          <p className="cc-muted ti-explain">
            Ranked by real-world evidence: CVEs on CISA's Known Exploited Vulnerabilities list first, then by EPSS — the
            probability of exploitation in the next 30 days. Severity alone doesn't decide the order.
            {filter === "possible"
              ? " These CVEs are only suggested by an exposed port or service — the version wasn't confirmed, so verify before acting. They aren't counted in the totals above."
              : " Only CVEs confirmed by a version match or a scanner check are counted."}
          </p>
          <div className="so-table-wrap">
            <table className="so-table ti-table">
              <thead>
                <tr><th scope="col">CVE</th><th scope="col">Exploitation</th><th scope="col">EPSS (30 d)</th><th scope="col">CVSS</th><th scope="col">Affected</th></tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.cve}>
                    <td>
                      <a className="cc-mono ti-cve" href={`https://nvd.nist.gov/vuln/detail/${r.cve}`} target="_blank" rel="noreferrer">{r.cve}</a>
                      <div className="so-sub ti-cvetitle">{r.kev?.name || r.title}</div>
                    </td>
                    <td>
                      {r.confirmed === false && <div className="ti-kevcell"><span className="ti-badge-unconfirmed" title="Matched on port or service only; version not confirmed">Unconfirmed · port-based</span></div>}
                      {r.kev ? (
                        <div className="ti-kevcell">
                          <span className="ti-badge-kev">Exploited in the wild</span>
                          {r.kev.ransomware && <span className="ti-badge-ransom">Ransomware</span>}
                          <span className="so-sub">CISA due {r.kev.due_date}</span>
                        </div>
                      ) : <span className="cc-muted">No confirmed exploitation</span>}
                    </td>
                    <td><EpssBar value={r.epss} percentile={r.epss_percentile} /></td>
                    <td className="cc-mono">{r.cvss || "—"}</td>
                    <td>
                      <Link to={`/findings?search=${encodeURIComponent(r.confirmed === false ? r.targets[0] || "" : r.cve)}`} className="ti-name">{r.targets.length} target{r.targets.length === 1 ? "" : "s"}</Link>
                      <div className="so-sub cc-mono am-ellipsis" title={r.targets.join(", ")}>{r.targets.slice(0, 2).join(", ")}{r.targets.length > 2 ? "…" : ""}</div>
                    </td>
                  </tr>
                ))}
                {!rows.length && <tr><td colSpan={5} className="cc-empty so-empty">{!exposure ? "Loading…" : filter === "possible" ? "No unconfirmed CVE matches." : "No confirmed CVEs match this filter."}</td></tr>}
              </tbody>
            </table>
          </div>
        </section>

        <Lookup initial={searchParams.get("q") || ""} />
      </div>

      <div className="ti-layout">
        <section className="cc-panel ti-kev" aria-label="New in CISA KEV">
          <header className="cc-panel__head">
            <h2>New in CISA KEV</h2>
            <div className="ti-kev__tools">
              <div className="cc-range" role="group" aria-label="Added within">
                {[7, 30, 90].map((d) => <button key={d} type="button" aria-pressed={kevDays === d} onClick={() => setKevDays(d)}>{d} days</button>)}
              </div>
              <label className="cc-check"><input type="checkbox" checked={kevEnvOnly} onChange={(e) => setKevEnvOnly(e.target.checked)} />In my environment</label>
            </div>
          </header>
          <ul className="ti-kevlist">
            {kevItems.slice(0, 40).map((i) => (
              <li key={i.cve} className={i.in_environment ? "is-env" : ""}>
                <div className="ti-kevlist__head">
                  <a className="cc-mono ti-cve" href={`https://nvd.nist.gov/vuln/detail/${i.cve}`} target="_blank" rel="noreferrer">{i.cve}</a>
                  <span className="so-sub">added {i.date_added}</span>
                  {i.ransomware && <span className="ti-badge-ransom">Ransomware</span>}
                  {i.in_environment && <span className="ti-badge-env">In your environment</span>}
                </div>
                <strong>{i.vendor} {i.product}</strong> — {i.name}
                <p className="cc-muted">{i.description}</p>
              </li>
            ))}
            {kev && !kevItems.length && <li className="cc-muted">{kevEnvOnly ? "None of these affect your environment." : "No additions in this period."}</li>}
            {!kev && <li className="cc-muted">Loading the KEV catalog…</li>}
          </ul>
        </section>

        <section className="cc-panel ti-sources" aria-label="Intelligence sources">
          <header className="cc-panel__head"><h2>Sources</h2></header>
          <ul className="cc-list">
            {sources.map((src) => (
              <li key={src.name} className="am-feed">
                <span className={`cc-dot cc-dot--${src.status === "connected" || src.status === "configured" ? "healthy" : src.status === "needs_key" ? "medium" : "down"}`} />
                <span>
                  <strong>{src.name}</strong>
                  <span className="cc-muted am-feed__detail">{src.status === "needs_key" ? `Optional · ${src.detail}` : src.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}

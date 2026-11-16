import { useCallback, useEffect, useState } from "react";

import api from "../api/client";

const fmtStamp = (iso) => (iso ? new Date(iso).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false }) : "—");
const fmtDay = (iso) => (iso ? new Date(`${iso.slice(0, 10)}T12:00:00`).toLocaleDateString([], { weekday: "short", day: "2-digit", month: "short" }) : "—");
const isToday = (iso) => Boolean(iso) && iso.slice(0, 10) === new Date().toISOString().slice(0, 10);
const nvdLink = (cve) => `https://nvd.nist.gov/vuln/detail/${cve}`;
const msLink = (cve) => `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`;

function Status({ source }) {
  if (!source) return null;
  if (source.status === "connected") return null;
  return <p className="so-warn">{source.status === "stale" ? "Showing the last good copy: " : ""}{source.note || "Source unavailable."}</p>;
}

function Flags({ row }) {
  return (
    <>
      {row.in_environment ? <span className="ti-badge-env">In your environment</span> : null}
      {row.in_kev ? <span className="ti-badge-kev">CISA KEV</span> : null}
    </>
  );
}

function MsRow({ r }) {
  return (
    <li>
      <div className="ti-kevlist__head">
        <a className="cc-mono ti-cve" href={msLink(r.cve)} target="_blank" rel="noreferrer">{r.cve}</a>
        {r.exploited ? <span className="ti-badge-kev">Exploited in the wild</span> : null}
        {r.disclosed ? <span className="ti-badge-ransom">Publicly disclosed</span> : null}
        {r.severity ? <span className={`mc-sev mc-sev--${r.severity === "Critical" ? "critical" : r.severity === "Important" ? "high" : r.severity === "Moderate" ? "medium" : "low"}`}>{r.severity}</span> : null}
        {r.cvss != null ? <span className="cc-mono so-sub">CVSS {r.cvss}</span> : null}
        <Flags row={r} />
      </div>
      <strong>{r.title}</strong>
      <p className="cc-muted">{r.family ? `${r.family} · ` : ""}{r.impact?.join(" · ")}{r.last_revised ? ` · revised ${fmtDay(r.last_revised)}` : ""}</p>
    </li>
  );
}

/** Today's vulnerability news from CISA KEV, Microsoft MSRC and NVD. */
export default function TodayIntel() {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("kev");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get("/threat-intelligence/today", { timeout: 120000 });
      setData(r.data);
      setError("");
    } catch {
      setError("Couldn't load today's feeds. The API needs internet access to CISA, Microsoft and NVD.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const timer = window.setInterval(() => { if (!document.hidden) load(); }, 30 * 60 * 1000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [load]);

  const kev = data?.kev;
  const ms = data?.microsoft;
  const nvd = data?.nvd;
  const kevToday = (kev?.items || []).filter((i) => isToday(i.date_added)).length;
  const msToday = (ms?.revised_today?.length || 0) + (ms?.published_today?.length || 0);

  return (
    <section className="cc-panel ti-today" aria-label="Vulnerability news today">
      <header className="cc-panel__head">
        <h2>Today · {new Date().toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" })}</h2>
        <div className="ti-kev__tools">
          {data ? <span className="cc-muted so-sub">Checked {fmtStamp(data.generated_at)}</span> : null}
          <button type="button" className="cc-btn" onClick={load} disabled={loading}>{loading ? "Checking…" : "Refresh"}</button>
        </div>
      </header>

      <div className="cc-range ti-today__tabs" role="tablist" aria-label="Source">
        {[
          ["kev", `CISA KEV${kev ? ` · ${kevToday} today` : ""}`],
          ["microsoft", `Microsoft${ms?.release ? ` ${ms.release}` : ""}${msToday ? ` · ${msToday} updated today` : ""}`],
          ["nvd", `New CVEs · 24 h${nvd?.total != null ? ` · ${nvd.total}` : ""}`],
        ].map(([k, l]) => (
          <button key={k} type="button" role="tab" aria-selected={tab === k} aria-pressed={tab === k} onClick={() => setTab(k)}>{l}</button>
        ))}
      </div>

      {error ? <p className="so-error" role="alert">{error}</p> : null}
      {loading && !data ? <p className="cc-empty">Checking CISA, Microsoft and NVD… the first check can take up to a minute.</p> : null}

      {data && tab === "kev" ? (
        <>
          <p className="cc-muted ti-explain">
            Catalog {kev.version || "—"}{kev.released ? `, released ${fmtStamp(kev.released)}` : ""}. Entries added in the last {kev.days} days: these are being exploited in the wild now.
          </p>
          <ul className="ti-kevlist">
            {kev.items.map((i) => (
              <li key={i.cve} className={i.in_environment ? "is-env" : ""}>
                <div className="ti-kevlist__head">
                  <a className="cc-mono ti-cve" href={nvdLink(i.cve)} target="_blank" rel="noreferrer">{i.cve}</a>
                  <span className={isToday(i.date_added) ? "ti-badge-kev" : "so-sub"}>{isToday(i.date_added) ? "Added today" : `Added ${fmtDay(i.date_added)}`}</span>
                  {i.ransomware ? <span className="ti-badge-ransom">Ransomware</span> : null}
                  {i.in_environment ? <span className="ti-badge-env">In your environment</span> : null}
                </div>
                <strong>{i.vendor} {i.product}</strong> — {i.name}
                <p className="cc-muted">{i.action} Federal deadline {i.due_date}.</p>
              </li>
            ))}
            {!kev.items.length ? <li className="cc-empty">CISA hasn't added anything in the last {kev.days} days.</li> : null}
          </ul>
        </>
      ) : null}

      {data && tab === "microsoft" ? (
        <>
          <Status source={ms} />
          {ms?.release ? (
            <>
              <p className="cc-muted ti-explain">
                {ms.title}: released {fmtStamp(ms.released)}, last revised {fmtStamp(ms.revised)}. {ms.total} Microsoft vulnerabilities — {ms.counts?.Critical || 0} critical, {ms.counts?.Important || 0} important.
                {ms.third_party_total ? ` Another ${ms.third_party_total} are open-source or Chromium fixes Microsoft republishes for components it ships (${ms.third_party_top.map(([n, c]) => `${n} ${c}`).join(", ")}); they're not listed here.` : ""}
              </p>
              <h3 className="an-subhead">Zero-days (exploited in the wild)</h3>
              <ul className="ti-kevlist">
                {ms.exploited.map((r) => <MsRow key={r.cve} r={r} />)}
                {!ms.exploited.length ? <li className="cc-empty">None flagged as exploited in this release.</li> : null}
              </ul>
              {ms.disclosed.length ? (
                <>
                  <h3 className="an-subhead">Publicly disclosed before a fix</h3>
                  <ul className="ti-kevlist">{ms.disclosed.map((r) => <MsRow key={r.cve} r={r} />)}</ul>
                </>
              ) : null}
              {msToday ? (
                <>
                  <h3 className="an-subhead">Published or revised today</h3>
                  <ul className="ti-kevlist">{[...ms.published_today, ...ms.revised_today].map((r) => <MsRow key={`t-${r.cve}`} r={r} />)}</ul>
                </>
              ) : null}
              <h3 className="an-subhead">Critical</h3>
              <ul className="ti-kevlist">{ms.critical.map((r) => <MsRow key={`c-${r.cve}`} r={r} />)}</ul>
            </>
          ) : null}
        </>
      ) : null}

      {data && tab === "nvd" ? (
        <>
          <Status source={nvd} />
          {nvd?.status === "connected" || nvd?.status === "stale" ? (
            <>
              <p className="cc-muted ti-explain">
                {nvd.total} CVEs published in the last {nvd.hours} hours: {nvd.critical} critical and {nvd.high} high so far
                {nvd.unscored ? `, ${nvd.unscored} not scored yet` : ""}. Most-severe first. Top publishers: {nvd.by_source.slice(0, 4).map(([s, c]) => `${s} (${c})`).join(", ")}.
              </p>
              <ul className="ti-kevlist">
                {nvd.top.map((i) => (
                  <li key={i.cve} className={i.in_environment ? "is-env" : ""}>
                    <div className="ti-kevlist__head">
                      <a className="cc-mono ti-cve" href={nvdLink(i.cve)} target="_blank" rel="noreferrer">{i.cve}</a>
                      {i.severity ? <span className={`mc-sev mc-sev--${i.severity}`}>{i.severity}</span> : <span className="so-sub">Not scored yet</span>}
                      {i.cvss != null ? <span className="cc-mono so-sub">CVSS {i.cvss}</span> : null}
                      <span className="so-sub">{fmtStamp(i.published)}</span>
                      {i.in_environment ? <span className="ti-badge-env">In your environment</span> : null}
                    </div>
                    <p>{i.description}</p>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

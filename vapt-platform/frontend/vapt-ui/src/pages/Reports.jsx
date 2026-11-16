import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import api from "../api/client";
import "../commandcenter.css";
import "../scans.css";
import "../reports.css";

const SETTINGS_KEY = "vapt_report_studio_v1";
const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };
const SEV_CVSS = { critical: "9.0 – 10.0", high: "7.0 – 8.9", medium: "4.0 – 6.9", low: "0.1 – 3.9", info: "0.0" };
const MODES = [
  { key: "executive", label: "Executive", audience: "Leadership & clients", text: "Risk rating, key numbers and priorities. No technical detail." },
  { key: "technical", label: "Technical", audience: "Engineers fixing issues", text: "Everything, plus full evidence, affected URLs and remediation per issue." },
  { key: "compliance", label: "Compliance", audience: "Auditors & GRC", text: "Findings mapped to NIST 800-53 and ISO 27001 controls." },
];
const PREVIEW_ROWS = 40;
const PREVIEW_DETAILS = 6;

const DEFAULTS = {
  mode: "executive",
  scanId: "all",
  targets: [],
  startDate: "",
  endDate: "",
  includeResolved: false,
  includeInfo: false,
  includeCves: true,
  includeRemediation: true,
  includeEvidence: true,
  includeCompliance: true,
  includeDetails: false,
  reportTitle: "",
  preparedFor: "",
  authorName: "",
  classification: "Confidential",
  version: "1.0",
};

function loadSettings() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(SETTINGS_KEY) || "null");
    return saved ? { ...DEFAULTS, ...saved, targets: [] } : DEFAULTS;
  } catch {
    return DEFAULTS;
  }
}

const fmtDate = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" });
};
const period = (meta) => (meta?.period_start && meta?.period_end ? `${fmtDate(meta.period_start)} – ${fmtDate(meta.period_end)}` : "—");

const errorText = (err, fallback) => {
  if (err?.response?.status === 403) return "You don't have permission to change branding. Ask an analyst or admin.";
  const detail = err?.response?.data?.detail;
  return typeof detail === "string" ? detail : fallback;
};

function toRequest(s, format = "pdf") {
  return {
    mode: s.mode,
    format,
    scan_id: s.scanId === "all" ? null : s.scanId,
    targets: s.targets,
    start_date: s.startDate || null,
    end_date: s.endDate || null,
    include_resolved: s.includeResolved,
    include_info: s.includeInfo,
    include_cves: s.includeCves,
    include_remediation: s.includeRemediation,
    include_evidence: s.includeEvidence,
    include_compliance: s.includeCompliance,
    include_details: s.includeDetails,
    report_title: s.reportTitle || null,
    prepared_for: s.preparedFor || null,
    author_name: s.authorName || null,
    classification: s.classification,
    version: s.version || "1.0",
  };
}

// ---------- preview document ----------

function SevChip({ sev }) {
  return <span className={`rp-chip rp-chip--${sev}`}>{SEV_LABEL[sev]}</span>;
}

function Page({ children, meta, number, cover = false }) {
  return (
    <article className={`rp-page${cover ? " rp-page--cover" : ""}`}>
      {cover ? (
        <div className="rp-cover-band"><span>{meta.classification.toUpperCase()}</span></div>
      ) : (
        <header className="rp-page__head">
          <strong>{meta.organization}</strong>
          <span>{meta.title}</span>
        </header>
      )}
      <div className="rp-page__body">{children}</div>
      <footer className="rp-page__foot">
        <span>{cover ? `${meta.classification} — prepared by ${meta.organization}. Do not distribute without permission.` : meta.classification.toUpperCase()}</span>
        {!cover && <span>Page {number}</span>}
      </footer>
    </article>
  );
}

function ReportDocument({ model, logoUrl }) {
  const { meta, summary, options: o } = model;
  const peak = Math.max(1, ...SEV.map((s) => summary.counts[s]));
  // Page and section numbers depend on which optional sections are present.
  const hasDetails = o.include_details && model.issues.length > 0;
  const hasCompliance = o.include_compliance && model.issues.length > 0;
  const num = {
    control: 2,
    scope: 3,
    summary: 4,
    details: 5,
    compliance: hasDetails ? 6 : 5,
    appendix: 5 + (hasDetails ? 1 : 0) + (hasCompliance ? 1 : 0),
  };
  const sectionNo = { details: 4, compliance: hasDetails ? 5 : 4 };

  return (
    <div className="rp-doc">
      <Page meta={meta} number={1} cover>
        {logoUrl && <img className="rp-cover-logo" src={logoUrl} alt={`${meta.organization} logo`} />}
        <h1 className="rp-cover-title">{meta.title}</h1>
        {meta.prepared_for && <p className="rp-cover-sub">Prepared for <strong>{meta.prepared_for}</strong></p>}
        <p className="rp-cover-sub">Prepared by {meta.organization}</p>
        <table className="rp-kv">
          <tbody>
            <tr><th>Report type</th><td>{model.mode[0].toUpperCase() + model.mode.slice(1)}</td></tr>
            <tr><th>Assessment period</th><td>{period(meta)}</td></tr>
            <tr><th>Overall risk</th><td><strong>{summary.rating}</strong></td></tr>
            <tr><th>Author</th><td>{meta.author}</td></tr>
            <tr><th>Version / date</th><td>{meta.version} · {fmtDate(meta.generated_at)}</td></tr>
          </tbody>
        </table>
      </Page>

      <Page meta={meta} number={num.control}>
        <h2>Document control</h2>
        <table className="rp-table">
          <thead><tr><th>Field</th><th>Value</th></tr></thead>
          <tbody>
            <tr><td>Title</td><td>{meta.title}</td></tr>
            <tr><td>Prepared for</td><td>{meta.prepared_for || "—"}</td></tr>
            <tr><td>Prepared by</td><td>{meta.author}, {meta.organization}</td></tr>
            <tr><td>Classification</td><td>{meta.classification}</td></tr>
            <tr><td>Version</td><td>{meta.version}</td></tr>
            <tr><td>Generated</td><td>{fmtDate(meta.generated_at)}</td></tr>
          </tbody>
        </table>

        <h2>1. Executive summary</h2>
        <div className={`rp-rating rp-rating--${summary.rating.toLowerCase().split(" ")[0]}`}>
          <span>OVERALL RISK</span>
          <strong>{summary.rating.toUpperCase()}</strong>
        </div>
        <p>{summary.narrative}</p>
        <div className="rp-kpis">
          {[["Issues", summary.issues], ["Targets", summary.targets], ["Critical", summary.counts.critical], ["High", summary.counts.high], ["Medium", summary.counts.medium]].map(([k, v]) => (
            <div key={k}><strong>{v}</strong><span>{k.toUpperCase()}</span></div>
          ))}
        </div>
        <h3>Issues by severity</h3>
        <div className="rp-bars">
          {SEV.map((s) => (
            <div key={s} className="rp-bars__row">
              <span>{SEV_LABEL[s]}</span>
              <div className="rp-bars__track"><div className={`rp-bars__fill rp-chip--${s}`} style={{ width: `${(summary.counts[s] / peak) * 100}%` }} /></div>
              <strong>{summary.counts[s]}</strong>
            </div>
          ))}
        </div>
        {model.recommendations.length > 0 && (
          <>
            <h3>Priority recommendations</h3>
            <table className="rp-table">
              <thead><tr><th>ID</th><th>Issue</th><th>Severity</th><th>{o.include_remediation ? "Recommended action" : "Target"}</th></tr></thead>
              <tbody>
                {model.recommendations.map((r) => (
                  <tr key={r.id}>
                    <td className="rp-id">{r.id}</td>
                    <td>{r.title}<div className="rp-muted">{r.target}</div></td>
                    <td><SevChip sev={r.severity} /></td>
                    <td>{o.include_remediation ? r.action : r.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Page>

      <Page meta={meta} number={num.scope}>
        <h2>2. Scope and methodology</h2>
        <p>
          Assessment window: <strong>{period(meta)}</strong>.
          {model.scan && <> Scope limited to scan <strong>{model.scan.name}</strong> ({model.scan.target}).</>}
        </p>
        {summary.engines.length > 0 && <p>Tools used: {summary.engines.join(", ")}.</p>}
        {model.targets.length > 0 && (
          <table className="rp-table rp-table--num">
            <thead><tr><th>Target</th><th>Issues</th><th>Crit.</th><th>High</th><th>Med.</th><th>Low</th><th>Highest</th></tr></thead>
            <tbody>
              {model.targets.slice(0, 25).map((t) => (
                <tr key={t.target}>
                  <td>{t.target}</td><td>{t.issues}</td><td>{t.counts.critical}</td><td>{t.counts.high}</td><td>{t.counts.medium}</td><td>{t.counts.low}</td>
                  <td><SevChip sev={t.highest} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {model.targets.length > 25 && <p className="rp-muted">…and {model.targets.length - 25} more targets in the exported report.</p>}
        <h3>Limitations</h3>
        <ul>{model.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
      </Page>

      <Page meta={meta} number={num.summary}>
        <h2>3. Findings summary</h2>
        {model.issues.length ? (
          <table className="rp-table">
            <thead><tr><th>ID</th><th>Issue</th><th>Target</th><th>Severity</th><th>CVSS</th>{o.include_cves && <th>CVE</th>}</tr></thead>
            <tbody>
              {model.issues.slice(0, PREVIEW_ROWS).map((g) => (
                <tr key={g.id}>
                  <td className="rp-id">{g.id}</td><td>{g.title}</td><td className="rp-mono">{g.target}</td>
                  <td><SevChip sev={g.severity} /></td><td>{g.cvss ? g.cvss.toFixed(1) : "—"}</td>
                  {o.include_cves && <td className="rp-mono">{g.cves.slice(0, 2).join(", ") || "—"}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p>No issues in the selected scope.</p>}
        {model.issues.length > PREVIEW_ROWS && <p className="rp-muted">Preview shows the first {PREVIEW_ROWS} of {model.issues.length} issues; the export contains all of them.</p>}
      </Page>

      {hasDetails && (
        <Page meta={meta} number={num.details}>
          <h2>{sectionNo.details}. Detailed findings</h2>
          {model.issues.slice(0, PREVIEW_DETAILS).map((g) => (
            <section key={g.id} className="rp-detail">
              <h3>{g.id} · {g.title}</h3>
              <table className="rp-kv rp-kv--grid">
                <tbody>
                  <tr><th>Severity</th><td><SevChip sev={g.severity} /></td><th>CVSS</th><td>{g.cvss ? g.cvss.toFixed(1) : "—"}</td></tr>
                  <tr><th>Target</th><td className="rp-mono">{g.target}</td><th>Occurrences</th><td>{g.occurrences}</td></tr>
                  <tr><th>Detected by</th><td>{g.engines.join(", ") || "—"}</td><th>Status</th><td>{g.status.replace(/_/g, " ")}</td></tr>
                  {o.include_cves && g.cves.length > 0 && <tr><th>CVE</th><td colSpan={3} className="rp-mono">{g.cves.join(", ")}</td></tr>}
                </tbody>
              </table>
              <h4>Description</h4>
              <p>{g.description || "No description provided by the scanner."}</p>
              {o.include_evidence && g.evidence && (<><h4>Evidence</h4><pre className="rp-pre">{g.evidence}</pre></>)}
              {g.urls.length > 0 && (<><h4>Affected locations</h4><p className="rp-muted rp-mono">{g.urls.slice(0, 6).join(", ")}{g.urls.length > 6 ? ` … +${g.urls.length - 6}` : ""}</p></>)}
              {o.include_remediation && (<><h4>Remediation</h4><p>{g.remediation || "No remediation guidance provided by the scanner."}</p></>)}
              {o.include_compliance && <p className="rp-muted">Controls: NIST {g.controls.nist.join(", ")} · ISO 27001 {g.controls.iso.join(", ")}</p>}
            </section>
          ))}
          {model.issues.length > PREVIEW_DETAILS && <p className="rp-muted">Preview shows {PREVIEW_DETAILS} of {model.issues.length} detailed findings; the export contains all of them.</p>}
        </Page>
      )}

      {hasCompliance && (
        <Page meta={meta} number={num.compliance}>
          <h2>{sectionNo.compliance}. Control mapping</h2>
          <p>Findings are mapped to controls by finding type. This mapping is indicative and supports remediation planning; it is not a formal compliance audit or attestation.</p>
          {[["nist", "NIST SP 800-53 Rev. 5"], ["iso", "ISO/IEC 27001:2022 Annex A"]].map(([fw, label]) => (
            <div key={fw}>
              <h3>{label}</h3>
              <table className="rp-table">
                <thead><tr><th>Control</th><th>Highest severity</th><th>Related issues</th><th>Targets</th></tr></thead>
                <tbody>
                  {model.compliance[fw].map((c) => (
                    <tr key={c.control}>
                      <td className="rp-id">{c.control}</td><td><SevChip sev={c.highest} /></td>
                      <td className="rp-mono">{c.issues.slice(0, 8).join(", ")}{c.issues.length > 8 ? " …" : ""}</td>
                      <td>{c.targets.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </Page>
      )}

      <Page meta={meta} number={num.appendix}>
        <h2>Appendix A. Risk rating method</h2>
        <p>Each issue is rated by the scanner's severity, aligned with CVSS v3 score bands. The overall risk equals the most severe open issue in scope.</p>
        <table className="rp-table">
          <thead><tr><th>Rating</th><th>CVSS range</th></tr></thead>
          <tbody>{SEV.map((s) => <tr key={s}><td><SevChip sev={s} /></td><td>{SEV_CVSS[s]}</td></tr>)}</tbody>
        </table>
      </Page>
    </div>
  );
}

// ---------- page ----------

export default function Reports({ canBrand = true }) {
  const [settings, setSettings] = useState(loadSettings);
  const [model, setModel] = useState(null);
  const [allTargets, setAllTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [updating, setUpdating] = useState(false);
  const [previewError, setPreviewError] = useState("");
  const [exporting, setExporting] = useState(null);
  const [notice, setNotice] = useState(null);
  const [branding, setBranding] = useState({ company_name: "", logo_uploaded: false });
  const [orgName, setOrgName] = useState("");
  const [logoUrl, setLogoUrl] = useState(null);
  const [zoom, setZoom] = useState(0.8);
  const [fullscreen, setFullscreen] = useState(false);
  const [targetQuery, setTargetQuery] = useState("");
  const fileRef = useRef(null);
  const requestId = useRef(0);

  const set = (key) => (value) => setSettings((s) => ({ ...s, [key]: value }));

  // Remember report details between visits (per browser).
  useEffect(() => {
    try {
      const { targets, ...rest } = settings; // eslint-disable-line no-unused-vars
      window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(rest));
    } catch {
      // storage unavailable; settings simply aren't remembered
    }
  }, [settings]);

  const loadLogo = useCallback(async () => {
    try {
      const res = await api.get("/reports/branding/logo", { responseType: "blob" });
      setLogoUrl((old) => {
        if (old) URL.revokeObjectURL(old);
        return URL.createObjectURL(res.data);
      });
    } catch {
      setLogoUrl((old) => {
        if (old) URL.revokeObjectURL(old);
        return null;
      });
    }
  }, []);

  useEffect(() => {
    api.get("/reports/branding").then((res) => {
      setBranding(res.data);
      setOrgName(res.data.company_name || "");
      if (res.data.logo_uploaded) loadLogo();
    }).catch(() => {});
    api.get("/scans/").then((res) => {
      setScans((res.data || []).filter((s) => String(s.status).toLowerCase() === "completed"));
    }).catch(() => {});
  }, [loadLogo]);

  // Live preview: debounce settings changes, ignore out-of-order responses.
  useEffect(() => {
    const id = ++requestId.current;
    const timer = window.setTimeout(async () => {
      setUpdating(true);
      try {
        const res = await api.post("/reports/studio/preview", toRequest(settings));
        if (id !== requestId.current) return;
        setModel(res.data);
        setPreviewError("");
        if (!settings.targets.length) setAllTargets(res.data.targets.map((t) => t.target));
      } catch {
        if (id === requestId.current) setPreviewError("Couldn't build the preview. Check the API and try again.");
      } finally {
        if (id === requestId.current) setUpdating(false);
      }
    }, 450);
    return () => window.clearTimeout(timer);
  }, [settings]);

  useEffect(() => {
    if (!fullscreen) return undefined;
    const onKey = (e) => { if (e.key === "Escape") setFullscreen(false); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [fullscreen]);

  const exportReport = async (format) => {
    setExporting(format);
    try {
      const res = await api.post("/reports/studio/export", toRequest(settings, format), { responseType: "blob" });
      const disposition = res.headers?.["content-disposition"] || "";
      const match = disposition.match(/filename="?([^";]+)"?/);
      const name = match ? match[1] : `report.${format}`;
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setNotice({ ok: true, text: `${name} downloaded.` });
    } catch {
      setNotice({ ok: false, text: `Couldn't export the ${format.toUpperCase()} report.` });
    } finally {
      setExporting(null);
    }
  };

  const uploadLogo = async (file) => {
    if (!file) return;
    if (!/\.(png|jpe?g)$/i.test(file.name)) {
      setNotice({ ok: false, text: "Use a PNG or JPG logo (SVG can't be embedded in PDF reports)." });
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setNotice({ ok: false, text: "Logo must be under 5 MB." });
      return;
    }
    const form = new FormData();
    form.append("file", file);
    if (orgName.trim()) form.append("company_name", orgName.trim());
    try {
      await api.post("/reports/logo", form);
      setBranding((b) => ({ ...b, logo_uploaded: true }));
      await loadLogo();
      setNotice({ ok: true, text: "Logo saved. It appears on every report." });
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't upload the logo.") });
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const removeLogo = async () => {
    try {
      await api.delete("/reports/branding/logo");
      setBranding((b) => ({ ...b, logo_uploaded: false }));
      await loadLogo();
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't remove the logo.") });
    }
  };

  const saveOrg = async () => {
    try {
      const res = await api.put("/reports/branding", { company_name: orgName.trim() });
      setBranding((b) => ({ ...b, ...res.data }));
      setSettings((s) => ({ ...s })); // refresh preview with the new name
      setNotice({ ok: true, text: "Organization name saved." });
    } catch (err) {
      setNotice({ ok: false, text: errorText(err, "Couldn't save the organization name.") });
    }
  };

  const visibleTargets = useMemo(() => {
    const q = targetQuery.trim().toLowerCase();
    return allTargets.filter((t) => !q || t.toLowerCase().includes(q)).slice(0, 80);
  }, [allTargets, targetQuery]);

  const toggleTarget = (t) => setSettings((s) => ({
    ...s,
    targets: s.targets.includes(t) ? s.targets.filter((x) => x !== t) : [...s.targets, t],
  }));

  const preview = model ? <ReportDocument model={model} logoUrl={logoUrl} /> : null;

  return (
    <div className="cc rs">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Report Studio</h1>
        </div>
        <div className="cc-top__tools">
          <button type="button" className="so-launch-btn rs-export" disabled={!!exporting || !model} onClick={() => exportReport("pdf")}>
            {exporting === "pdf" ? "Generating…" : "Export PDF"}
          </button>
          {["docx", "csv", "json"].map((f) => (
            <button key={f} type="button" className="cc-btn" disabled={!!exporting || !model} onClick={() => exportReport(f)}>
              {exporting === f ? "…" : f.toUpperCase()}
            </button>
          ))}
        </div>
      </header>

      {notice && (
        <div className={`so-notice${notice.ok ? "" : " so-notice--error"}`} role="status">
          <span>{notice.text}</span>
          <button type="button" className="cc-icon" aria-label="Dismiss" onClick={() => setNotice(null)}>×</button>
        </div>
      )}

      <div className="rs-layout">
        {/* ---------- Settings ---------- */}
        <div className="rs-settings">
          <section className="cc-panel" aria-label="Report type">
            <header className="cc-panel__head"><h2>Report type</h2></header>
            <div className="rs-modes" role="radiogroup" aria-label="Report type">
              {MODES.map((m) => (
                <button
                  key={m.key}
                  type="button"
                  role="radio"
                  aria-checked={settings.mode === m.key}
                  className="rs-mode"
                  onClick={() => set("mode")(m.key)}
                >
                  <strong>{m.label}</strong>
                  <span className="rs-mode__aud">{m.audience}</span>
                  <span className="rs-mode__text">{m.text}</span>
                </button>
              ))}
            </div>
          </section>

          <section className="cc-panel" aria-label="Scope">
            <header className="cc-panel__head"><h2>Scope</h2></header>
            <label className="so-field">
              Findings from
              <select className="so-input" value={settings.scanId} onChange={(e) => setSettings((s) => ({ ...s, scanId: e.target.value, targets: [] }))}>
                <option value="all">All scans</option>
                {scans.slice(0, 60).map((sc) => (
                  <option key={sc.id} value={sc.id}>{sc.scan_name} — {sc.target}</option>
                ))}
              </select>
            </label>
            <div className="rs-two">
              <label className="so-field">From<input type="date" className="so-input" value={settings.startDate} onChange={(e) => set("startDate")(e.target.value)} /></label>
              <label className="so-field">To<input type="date" className="so-input" value={settings.endDate} onChange={(e) => set("endDate")(e.target.value)} /></label>
            </div>
            <fieldset className="rs-targets">
              <legend>Targets {settings.targets.length ? `(${settings.targets.length} selected)` : "(all)"}</legend>
              <input type="search" className="so-input" placeholder="Filter targets" aria-label="Filter targets" value={targetQuery} onChange={(e) => setTargetQuery(e.target.value)} />
              <div className="rs-targets__list">
                {visibleTargets.map((t) => (
                  <label key={t} className="cc-check rs-target">
                    <input type="checkbox" checked={settings.targets.includes(t)} onChange={() => toggleTarget(t)} />
                    <span className="cc-mono">{t}</span>
                  </label>
                ))}
                {!visibleTargets.length && <p className="cc-muted">No targets.</p>}
              </div>
              {settings.targets.length > 0 && <button type="button" className="cc-btn" onClick={() => set("targets")([])}>Clear selection</button>}
            </fieldset>
            <label className="cc-check"><input type="checkbox" checked={settings.includeResolved} onChange={(e) => set("includeResolved")(e.target.checked)} />Include resolved issues</label>
            <label className="cc-check"><input type="checkbox" checked={settings.includeInfo} onChange={(e) => set("includeInfo")(e.target.checked)} />Include informational issues</label>
            <p className="cc-muted rs-note">Issues marked as false positives are always excluded.</p>
          </section>

          <section className="cc-panel" aria-label="Organization branding">
            <header className="cc-panel__head"><h2>Organization branding</h2></header>
            <div className="rs-logo">
              <div className="rs-logo__box">
                {logoUrl ? <img src={logoUrl} alt="Current report logo" /> : <span className="cc-muted">No logo</span>}
              </div>
              {canBrand && (
                <div className="rs-logo__actions">
                  <label className="cc-btn rs-upload">
                    {branding.logo_uploaded ? "Replace logo" : "Upload logo"}
                    <input ref={fileRef} type="file" accept=".png,.jpg,.jpeg" className="cc-sr" onChange={(e) => uploadLogo(e.target.files?.[0])} />
                  </label>
                  {branding.logo_uploaded && <button type="button" className="cc-btn so-danger" onClick={removeLogo}>Remove</button>}
                  <span className="cc-muted">PNG or JPG, under 5 MB</span>
                </div>
              )}
            </div>
            <label className="so-field">
              Your organization (report author)
              <span className="rs-inline">
                <input className="so-input" value={orgName} onChange={(e) => setOrgName(e.target.value)} disabled={!canBrand} />
                {canBrand && <button type="button" className="cc-btn" disabled={!orgName.trim() || orgName.trim() === branding.company_name} onClick={saveOrg}>Save</button>}
              </span>
            </label>
          </section>

          <section className="cc-panel" aria-label="Report details">
            <header className="cc-panel__head"><h2>Report details</h2></header>
            <label className="so-field">Title<input className="so-input" value={settings.reportTitle} placeholder="Vulnerability Assessment — Executive Report" onChange={(e) => set("reportTitle")(e.target.value)} /></label>
            <label className="so-field">Prepared for (client)<input className="so-input" value={settings.preparedFor} placeholder="e.g. Acme Corporation" onChange={(e) => set("preparedFor")(e.target.value)} /></label>
            <label className="so-field">Author<input className="so-input" value={settings.authorName} placeholder="Security Assessment Team" onChange={(e) => set("authorName")(e.target.value)} /></label>
            <div className="rs-two">
              <label className="so-field">Classification
                <select className="so-input" value={settings.classification} onChange={(e) => set("classification")(e.target.value)}>
                  {["Confidential", "Restricted", "Internal", "Public"].map((c) => <option key={c}>{c}</option>)}
                </select>
              </label>
              <label className="so-field">Version<input className="so-input" value={settings.version} onChange={(e) => set("version")(e.target.value)} /></label>
            </div>
          </section>

          <section className="cc-panel" aria-label="Sections">
            <header className="cc-panel__head"><h2>Sections</h2></header>
            <label className="cc-check"><input type="checkbox" checked={settings.mode === "technical" || settings.includeDetails} disabled={settings.mode === "technical"} onChange={(e) => set("includeDetails")(e.target.checked)} />Detailed findings{settings.mode === "technical" && " (always in Technical)"}</label>
            <label className="cc-check"><input type="checkbox" checked={settings.includeEvidence} onChange={(e) => set("includeEvidence")(e.target.checked)} />Evidence and proof</label>
            <label className="cc-check"><input type="checkbox" checked={settings.includeRemediation} onChange={(e) => set("includeRemediation")(e.target.checked)} />Remediation guidance</label>
            <label className="cc-check"><input type="checkbox" checked={settings.includeCves} onChange={(e) => set("includeCves")(e.target.checked)} />CVE references</label>
            <label className="cc-check"><input type="checkbox" checked={settings.mode === "compliance" || settings.includeCompliance} disabled={settings.mode === "compliance"} onChange={(e) => set("includeCompliance")(e.target.checked)} />Control mapping (NIST / ISO 27001){settings.mode === "compliance" && " (always in Compliance)"}</label>
            <button type="button" className="cc-btn rs-reset" onClick={() => setSettings(DEFAULTS)}>Reset all settings</button>
          </section>
        </div>

        {/* ---------- Preview ---------- */}
        <section className="cc-panel rs-preview" aria-label="Live document preview">
          <header className="cc-panel__head">
            <h2>Live preview</h2>
            <div className="rs-preview__tools">
              <span className={`rs-status${updating ? " is-busy" : ""}`} role="status">
                {updating ? "Updating…" : model ? `${model.summary.issues} issues · ${model.summary.targets} targets · ${model.summary.rating}` : ""}
              </span>
              <div className="cc-range" role="group" aria-label="Zoom">
                {[[0.6, "60%"], [0.8, "80%"], [1, "100%"]].map(([z, l]) => (
                  <button key={l} type="button" aria-pressed={zoom === z} onClick={() => setZoom(z)}>{l}</button>
                ))}
              </div>
              <button type="button" className="cc-btn" onClick={() => setFullscreen(true)} disabled={!model}>Full screen</button>
            </div>
          </header>
          {previewError && <p className="so-error">{previewError}</p>}
          <div className="rs-stage">
            <div className="rs-zoom" style={{ zoom }}>
              {preview || <p className="cc-empty">Building preview…</p>}
            </div>
          </div>
        </section>
      </div>

      {fullscreen && model && (
        <div className="rs-full" role="dialog" aria-modal="true" aria-label="Full screen report preview">
          <div className="rs-full__bar">
            <strong>{model.meta.title}</strong>
            <span className="rs-full__actions">
              <button type="button" className="so-launch-btn rs-export" disabled={!!exporting} onClick={() => exportReport("pdf")}>{exporting === "pdf" ? "Generating…" : "Export PDF"}</button>
              <button type="button" className="cc-btn" autoFocus onClick={() => setFullscreen(false)}>Close</button>
            </span>
          </div>
          <div className="rs-full__stage">{preview}</div>
        </div>
      )}
    </div>
  );
}

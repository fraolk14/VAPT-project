export default function Findings({ findings }) {
  return (
    <section id="findings" className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Drill-down analysis</p>
          <h2>Normalized findings</h2>
        </div>
      </div>
      <div className="finding-grid">
        {findings.map((finding) => (
          <article className="finding-card" key={finding.id}>
            <div className="finding-card__header">
              <span className={`pill pill--${finding.severity || "info"}`}>
                {finding.severity || "info"}
              </span>
              <small>{finding.source}</small>
            </div>
            <h3>{finding.title}</h3>
            <p>{finding.remediation || finding.evidence || "Awaiting enrichment."}</p>
            <dl>
              <div>
                <dt>Port</dt>
                <dd>{finding.port}/{finding.protocol}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{finding.status}</dd>
              </div>
              <div>
                <dt>CVSS</dt>
                <dd>{finding.cvss_score || "n/a"}</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

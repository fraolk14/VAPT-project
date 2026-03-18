function StatusDot({ healthy }) {
  return <span className={`status-dot ${healthy ? "is-healthy" : "is-unhealthy"}`} />;
}

function integrationLabel(name) {
  if (name === "openvas") return "Network Engine";
  if (name === "zap") return "Web Engine";
  if (name === "mobsf") return "Mobile Engine";
  return name;
}

export default function Integrations({ integrations }) {
  return (
    <section className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Control plane connectivity</p>
          <h2>Integrations</h2>
        </div>
      </div>
      <div className="integration-list">
        {Object.entries(integrations).map(([name, value]) => (
          <div key={name} className="integration-item">
            <div>
              <strong>{integrationLabel(name)}</strong>
              <p>{value.url}</p>
            </div>
            <div className="integration-item__status">
              <StatusDot healthy={value.healthy} />
              <span>{value.healthy ? "Healthy" : "Unavailable"}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

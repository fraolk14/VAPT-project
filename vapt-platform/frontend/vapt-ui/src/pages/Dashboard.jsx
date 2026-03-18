import Card from "../components/Card";

export default function Dashboard({ summary }) {
  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Risk overview</p>
            <h2>Executive dashboard</h2>
          </div>
        </div>
        <div className="metrics-grid">
          {summary.metrics.map((metric) => (
            <Card
              key={metric.label}
              title={metric.label}
              value={metric.value}
              trend={metric.trend}
            />
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Severity mix</p>
            <h2>Vulnerability distribution</h2>
          </div>
        </div>
        <div className="chip-grid">
          {Object.entries(summary.severity_breakdown).map(([severity, count]) => (
            <div className="severity-chip" key={severity}>
              <span>{severity}</span>
              <strong>{count}</strong>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Coverage</p>
            <h2>Tool utilization</h2>
          </div>
        </div>
        <div className="coverage-list">
          {Object.entries(summary.tool_coverage).map(([tool, count]) => (
            <div key={tool} className="coverage-row">
              <span>{tool}</span>
              <strong>{count} scans</strong>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

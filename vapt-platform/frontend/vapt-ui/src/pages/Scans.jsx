export default function Scans({ scans }) {
  return (
    <section id="scans" className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Campaign orchestration</p>
          <h2>Scan activity</h2>
        </div>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Tool</th>
              <th>Type</th>
              <th>Target</th>
              <th>Status</th>
              <th>Progress</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>{scan.scan_name}</td>
                <td>{scan.tool}</td>
                <td>{scan.scan_type}</td>
                <td>{scan.target}</td>
                <td>
                  <span className={`pill pill--${scan.status}`}>{scan.status}</span>
                </td>
                <td>{scan.progress}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

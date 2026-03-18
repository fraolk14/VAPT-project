export default function Assets({ assets }) {
  return (
    <section id="assets" className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Asset inventory</p>
          <h2>Critical surfaces</h2>
        </div>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Address</th>
              <th>Type</th>
              <th>Exposure</th>
              <th>Criticality</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => (
              <tr key={asset.id}>
                <td>
                  <strong>{asset.asset_name}</strong>
                  <p>{asset.hostname || "No hostname"}</p>
                </td>
                <td>{asset.ip_address}</td>
                <td>{asset.asset_type}</td>
                <td>{asset.exposure}</td>
                <td>{asset.criticality}</td>
                <td>{asset.risk_score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

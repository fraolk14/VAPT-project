import { useEffect, useMemo, useState } from "react";

import api from "../api/client";

const emptyAssetForm = {
  asset_name: "",
  ip_address: "",
  url: "",
  hostname: "",
  asset_type: "host",
  environment: "prod",
  criticality: "medium",
  owner: "",
  exposure: "internal",
  tags: [],
  cloud_provider: "",
  business_unit: "",
};

function assetDisplayName(asset) {
  return asset.asset_name || asset.name || asset.hostname || asset.ip_address || asset.url || "Unnamed asset";
}

function assetAddress(asset) {
  return asset.url || asset.ip_address || asset.hostname || "No address";
}

export default function Assets({ assets, attackSurface, attackPaths, onAssetCreated }) {
  const [localAssets, setLocalAssets] = useState(assets || []);
  const [assetForm, setAssetForm] = useState(emptyAssetForm);
  const [feedback, setFeedback] = useState("");
  const [feedbackType, setFeedbackType] = useState("idle");
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);
  const [search, setSearch] = useState("");
  const [exposureFilter, setExposureFilter] = useState("all");

  useEffect(() => {
    setLocalAssets(assets || []);
  }, [assets]);

  useEffect(() => {
    api.get("/assets").then((response) => setLocalAssets(response.data || [])).catch(() => {});
  }, []);

  const createAsset = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/assets/", {
        ...assetForm,
        tags: [],
        ip_address: assetForm.ip_address || null,
        url: assetForm.url || null,
        hostname: assetForm.hostname || null,
        owner: assetForm.owner || null,
        cloud_provider: assetForm.cloud_provider || null,
        business_unit: assetForm.business_unit || null,
      });
      setLocalAssets((current) => [response.data, ...current]);
      onAssetCreated?.(response.data);
      setAssetForm(emptyAssetForm);
      setFeedbackType("success");
      setFeedback("Asset created successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the asset right now.");
    }
  };

  const deleteAsset = async (asset) => {
    const label = assetDisplayName(asset);
    if (!window.confirm(`Delete asset "${label}"? Historical findings will remain, but this asset record will be removed.`)) return;
    try {
      await api.delete(`/assets/${asset.id}`);
      setLocalAssets((current) => current.filter((item) => item.id !== asset.id));
      setFeedbackType("success");
      setFeedback("Asset deleted.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to delete the asset right now.");
    }
  };

  const selectedPath = useMemo(() => attackPaths?.paths?.[selectedPathIndex] || [], [attackPaths, selectedPathIndex]);
  const filteredAssets = useMemo(
    () =>
      localAssets.filter((asset) => {
        const matchesExposure = exposureFilter === "all" || asset.exposure === exposureFilter;
        const blob = `${assetDisplayName(asset)} ${asset.hostname || ""} ${asset.ip_address || ""} ${asset.url || ""}`.toLowerCase();
        return matchesExposure && blob.includes(search.toLowerCase());
      }),
    [localAssets, search, exposureFilter]
  );
  const actionQueue = useMemo(
    () =>
      filteredAssets
        .filter((asset) => asset.exposure === "external" || String(asset.criticality).toLowerCase() === "critical")
        .slice(0, 6),
    [filteredAssets]
  );

  return (
    <section className="section-grid">
      <section className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Asset onboarding</p>
            <h2>Add host or URL</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={createAsset}>
          <input className="scan-input" placeholder="Asset name" value={assetForm.asset_name} onChange={(event) => setAssetForm((current) => ({ ...current, asset_name: event.target.value }))} />
          <input className="scan-input" placeholder="IP address or hostname" value={assetForm.ip_address} onChange={(event) => setAssetForm((current) => ({ ...current, ip_address: event.target.value }))} />
          <input className="scan-input" placeholder="URL (optional for web assets)" value={assetForm.url} onChange={(event) => setAssetForm((current) => ({ ...current, url: event.target.value }))} />
          <input className="scan-input" placeholder="Hostname (optional)" value={assetForm.hostname} onChange={(event) => setAssetForm((current) => ({ ...current, hostname: event.target.value }))} />
          <select className="scan-select" value={assetForm.asset_type} onChange={(event) => setAssetForm((current) => ({ ...current, asset_type: event.target.value }))}>
            <option value="host">Host</option>
            <option value="web">Web</option>
            <option value="domain">Domain</option>
            <option value="mobile">Mobile</option>
          </select>
          <select className="scan-select" value={assetForm.exposure} onChange={(event) => setAssetForm((current) => ({ ...current, exposure: event.target.value }))}>
            <option value="internal">Internal</option>
            <option value="external">External</option>
          </select>
          <select className="scan-select" value={assetForm.criticality} onChange={(event) => setAssetForm((current) => ({ ...current, criticality: event.target.value }))}>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <button type="submit" className="scan-action scan-action--resume">Create Asset</button>
        </form>
        {feedback ? <p className={`scan-feedback scan-feedback--${feedbackType}`}>{feedback}</p> : null}
      </section>

      <section id="assets" className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Asset inventory</p>
            <h2>Critical surfaces</h2>
          </div>
          <div className="table-controls">
            <input className="scan-input" placeholder="Search assets" value={search} onChange={(event) => setSearch(event.target.value)} />
            <select className="scan-select" value={exposureFilter} onChange={(event) => setExposureFilter(event.target.value)}>
              <option value="all">All exposure</option>
              <option value="external">External</option>
              <option value="internal">Internal</option>
            </select>
          </div>
        </div>
        <div className="table-wrap table-wrap--full">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Address</th>
                <th>Type</th>
                <th>Exposure</th>
                <th>Criticality</th>
                <th>Risk</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td data-label="Asset">
                    <strong>{assetDisplayName(asset)}</strong>
                    <p>{asset.hostname || asset.ip_address || "No hostname"}</p>
                  </td>
                  <td data-label="Address">{assetAddress(asset)}</td>
                  <td data-label="Type">{asset.asset_type}</td>
                  <td data-label="Exposure">{asset.exposure}</td>
                  <td data-label="Criticality">{asset.criticality}</td>
                  <td data-label="Risk">{asset.risk_score}</td>
                  <td data-label="Actions">
                    <button type="button" className="scan-action scan-action--cancel" onClick={() => deleteAsset(asset)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {!filteredAssets.length ? <tr><td colSpan="7"><p className="empty-copy">No assets matched the current filters.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Exposure analytics</p>
            <h2>Attack surface</h2>
          </div>
        </div>
        <div className="coverage-list">
          <div className="coverage-row"><span>External assets</span><strong>{attackSurface?.external_assets || 0}</strong></div>
          <div className="coverage-row"><span>Internal assets</span><strong>{attackSurface?.internal_assets || 0}</strong></div>
          <div className="coverage-row"><span>Cloud assets</span><strong>{attackSurface?.cloud_assets || 0}</strong></div>
          <div className="coverage-row"><span>Mobile assets</span><strong>{attackSurface?.mobile_assets || 0}</strong></div>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Operator queue</p>
            <h2>Asset tasks</h2>
          </div>
        </div>
        <div className="coverage-list">
          {actionQueue.map((asset) => (
            <div className="coverage-row" key={`task-${asset.id}`}>
              <span>{assetDisplayName(asset)}</span>
              <strong>{asset.exposure === "external" ? "Review exposure" : "Confirm ownership"}</strong>
            </div>
          ))}
          {!actionQueue.length ? <p className="empty-copy">No priority asset actions are pending.</p> : null}
        </div>
      </section>

      <section id="attack-paths" className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Path modeling</p>
            <h2>Attack paths</h2>
          </div>
        </div>
        <div className="attack-path-layout">
          <div className="coverage-list">
            {(attackPaths?.paths || []).map((path, index) => (
              <button
                key={`path-${index}`}
                type="button"
                className={selectedPathIndex === index ? "coverage-row coverage-row--button is-active" : "coverage-row coverage-row--button"}
                onClick={() => setSelectedPathIndex(index)}
              >
                <span>{path[0]?.asset_name || `Path ${index + 1}`}</span>
                <strong>{path.map((node) => node.technique).join(" -> ")}</strong>
              </button>
            ))}
            {!(attackPaths?.paths || []).length ? <p className="empty-copy">Attack path recommendations will appear here after scans complete.</p> : null}
          </div>

          <div className="panel panel--embedded attack-path-detail">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Referenced chain</p>
                <h2>{selectedPath.length ? selectedPath[0].asset_name : "Select a path"}</h2>
              </div>
            </div>
            {selectedPath.length ? (
              <div className="attack-path-nodes">
                {selectedPath.map((node, index) => (
                  <article key={`${node.target}-${index}`} className="attack-path-node">
                    <span className={`pill pill--${node.severity}`}>{node.severity}</span>
                    <strong>{node.finding_title}</strong>
                    <p>{node.technique}</p>
                    <div className="coverage-list">
                      <div className="coverage-row">
                        <span>Asset</span>
                        <strong>{node.asset_name}</strong>
                      </div>
                      <div className="coverage-row">
                        <span>Target</span>
                        <strong>{node.target}</strong>
                      </div>
                      <div className="coverage-row">
                        <span>Exposure</span>
                        <strong>{node.exposure}</strong>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <p className="empty-copy">Choose an attack path from the list to inspect what the path references.</p>
            )}
            <div className="coverage-list">
              {(attackPaths?.suggested_actions || []).map((action) => (
                <div className="coverage-row" key={action}>
                  <span>{action}</span>
                  <strong>Recommended</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </section>
  );
}

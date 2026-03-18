import { useState } from "react";

import api from "../api/client";

function engineLabel(tool) {
  return tool === "openvas" ? "Network Engine" : tool === "zap" ? "Web Engine" : "Mobile Engine";
}

function statusCopy(scan) {
  if (scan.status === "waiting") {
    return scan.error_message || "Queued in background";
  }
  if (scan.status === "running") {
    return "Collecting findings";
  }
  if (scan.status === "completed") {
    return `Findings captured: ${scan.result_summary?.finding_count || 0}`;
  }
  return scan.error_message || scan.status;
}

export default function Scans({ scans, onScanQueued }) {
  const [target, setTarget] = useState("");
  const [launchState, setLaunchState] = useState({ status: "idle", message: "" });

  const startNetworkScan = async (event) => {
    event.preventDefault();
    if (!target.trim()) return;

    setLaunchState({ status: "loading", message: "Queueing network assessment..." });

    try {
      const response = await api.post("/scans/network", {
        target: target.trim(),
        label: `Network Assessment ${target.trim()}`,
      });
      onScanQueued?.(response.data);
      setLaunchState({
        status: "success",
        message: "Network assessment queued. It will start in the background automatically.",
      });
      setTarget("");
    } catch (error) {
      const message =
        error?.response?.data?.detail ||
        "Unable to queue the assessment right now.";
      setLaunchState({ status: "error", message });
    }
  };

  return (
    <section id="scans" className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Campaign orchestration</p>
          <h2>Scan activity</h2>
        </div>
      </div>
      <form className="scan-launcher" onSubmit={startNetworkScan}>
        <div className="scan-launcher__copy">
          <strong>Launch a network assessment</strong>
          <p>Enter an IP address or hostname and the engine will handle the rest in the background.</p>
        </div>
        <div className="scan-launcher__controls">
          <input
            className="scan-input"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="10.0.0.15 or scanme.nmap.org"
          />
          <button type="submit" disabled={launchState.status === "loading"}>
            {launchState.status === "loading" ? "Queueing..." : "Start Scan"}
          </button>
        </div>
      </form>
      {launchState.message ? (
        <p className={`scan-feedback scan-feedback--${launchState.status}`}>
          {launchState.message}
        </p>
      ) : null}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Engine</th>
              <th>Type</th>
              <th>Target</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Background State</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>{scan.scan_name}</td>
                <td>{engineLabel(scan.tool)}</td>
                <td>{scan.scan_type}</td>
                <td>{scan.target}</td>
                <td>
                  <span className={`pill pill--${scan.status}`}>{scan.status}</span>
                </td>
                <td>{scan.progress}%</td>
                <td>{statusCopy(scan)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

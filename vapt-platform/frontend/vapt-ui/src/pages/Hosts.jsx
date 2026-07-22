import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import api from "../api/client";
import { resolveAssetForTarget, resolveOsLabel, targetOf } from "../utils/targetIntel";

function scanLabel(scan) {
  if (scan.scan_type === "network") return "Network";
  if (scan.scan_type === "web") return "Web";
  if (scan.scan_type === "mobile") return "Mobile";
  return scan.scan_type || "Scan";
}

function scanWhen(scan) {
  const raw = scan.finished_at || scan.created_at;
  const parsed = raw ? new Date(raw) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleString() : "n/a";
}

export default function Hosts({ scans = [], assets = [], findings = [] }) {
  const navigate = useNavigate();
  const [busyKey, setBusyKey] = useState("");
  const [activeTab, setActiveTab] = useState("scanned");

  const rows = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed" && (scan.scan_type === "network" || scan.scan_type === "web"));
    const byKey = new Map();
    completed.forEach((scan) => {
      const key = `${scan.scan_type}:${scan.target}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, scan);
        return;
      }
      const existingTime = new Date(existing.finished_at || existing.created_at || 0).getTime();
      const nextTime = new Date(scan.finished_at || scan.created_at || 0).getTime();
      if (nextTime >= existingTime) byKey.set(key, scan);
    });
    return Array.from(byKey.values()).sort((a, b) => {
      const at = new Date(a.finished_at || a.created_at || 0).getTime();
      const bt = new Date(b.finished_at || b.created_at || 0).getTime();
      return bt - at;
    });
  }, [scans]);

  const resolvedHosts = useMemo(() => {
    const resolved = (findings || []).filter((finding) => (finding.status || "").toLowerCase() === "resolved");
    const byTarget = new Map();
    resolved.forEach((finding) => {
      const key = targetOf(finding);
      const existing = byTarget.get(key);
      const currentTime = new Date(finding.resolved_at || finding.detected_at || 0).getTime();
      const existingTime = existing ? new Date(existing.resolved_at || existing.detected_at || 0).getTime() : 0;
      if (!existing || currentTime >= existingTime) {
        byTarget.set(key, finding);
      }
    });
    return Array.from(byTarget.values()).sort((a, b) => new Date(b.resolved_at || b.detected_at || 0).getTime() - new Date(a.resolved_at || a.detected_at || 0).getTime());
  }, [findings]);

  const rescan = async (scan) => {
    const key = `${scan.scan_type}:${scan.target}`;
    setBusyKey(key);
    try {
      if (scan.scan_type === "web") {
        await api.post("/scans/web", { target: scan.target, label: `Re-scan ${scan.target}` });
      } else {
        await api.post("/scans/network", { target: scan.target, label: `Re-scan ${scan.target}` });
      }
      navigate("/scans");
    } finally {
      setBusyKey("");
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Assessment inventory</p>
            <h2>Hosts</h2>
          </div>
        </div>

        <div className="subtabs">
          <button type="button" className={activeTab === "scanned" ? "subtab is-active" : "subtab"} onClick={() => setActiveTab("scanned")}>
            Scanned Hosts
            <span>{rows.length}</span>
          </button>
          <button type="button" className={activeTab === "resolved" ? "subtab is-active" : "subtab"} onClick={() => setActiveTab("resolved")}>
            Resolved Hosts
            <span>{resolvedHosts.length}</span>
          </button>
        </div>

        {activeTab === "scanned" ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Target</th>
                  <th>OS Type</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 50).map((scan) => {
                  const key = `${scan.scan_type}:${scan.target}`;
                  const asset = resolveAssetForTarget(scan.target, assets);
                  const matchingFinding = findings.find((finding) => targetOf(finding) === scan.target || targetOf(finding).includes(scan.target) || scan.target.includes(targetOf(finding)));
                  return (
                    <tr key={key}>
                      <td data-label="Date">{scanWhen(scan)}</td>
                      <td data-label="Target">
                        <button
                          type="button"
                          className="link-button"
                          onClick={() => navigate(`/findings?q=${encodeURIComponent(scan.target)}`)}
                          title="View findings for this target"
                        >
                          {scan.target}
                        </button>
                      </td>
                      <td data-label="OS Type">{resolveOsLabel({ asset, finding: matchingFinding, findings, assets, target: scan.target })}</td>
                      <td data-label="Type">{scanLabel(scan)}</td>
                      <td data-label="Status"><span className={`pill pill--${scan.status}`}>{scan.status}</span></td>
                      <td data-label="Action">
                        <button type="button" className="scan-action scan-action--resume" disabled={busyKey === key} onClick={() => rescan(scan)}>
                          {busyKey === key ? "Queueing..." : "Re-scan"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {!rows.length ? (
                  <tr>
                    <td colSpan="6"><p className="empty-copy">No completed network or web scans yet. Run a scan to populate this list.</p></td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Resolved At</th>
                  <th>Target</th>
                  <th>OS Type</th>
                  <th>Resolved By</th>
                  <th>Finding</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {resolvedHosts.slice(0, 50).map((finding) => {
                  const asset = resolveAssetForTarget(targetOf(finding), assets);
                  return (
                    <tr key={finding.id}>
                      <td data-label="Resolved At">{finding.resolved_at ? new Date(finding.resolved_at).toLocaleString() : "n/a"}</td>
                      <td data-label="Target">
                        <button type="button" className="link-button" onClick={() => navigate(`/findings/${finding.id}`)}>
                          {targetOf(finding)}
                        </button>
                      </td>
                      <td data-label="OS Type">{resolveOsLabel({ asset, finding, findings, assets, target: targetOf(finding) })}</td>
                      <td data-label="Resolved By">{finding.resolved_by || finding.assigned_to || "n/a"}</td>
                      <td data-label="Finding">{finding.title}</td>
                      <td data-label="Status"><span className="pill pill--completed">resolved</span></td>
                    </tr>
                  );
                })}
                {!resolvedHosts.length ? (
                  <tr>
                    <td colSpan="6"><p className="empty-copy">Resolved findings will appear here after analysts mark issues as resolved.</p></td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

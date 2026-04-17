import { useEffect, useMemo, useState } from "react";

import api from "../api/client";

const ENGINE_OPTIONS = {
  openvas: {
    label: "Network Engine",
    targetKind: "Network target",
    targetHelp: "Use a valid IP address, fully qualified domain name, or IPv4 CIDR block up to /24.",
    description: "Queue a host, FQDN, or network block for background discovery and network assessment.",
    buttonLabel: "Start Network Scan",
    loadingLabel: "Queueing network scan...",
    placeholder: "10.0.0.15, scanme.nmap.org, or 192.168.10.0/24",
    profile: "Full and fast",
    success: "Network assessment queued. It will start in the background automatically.",
    errorFallback: "Unable to queue the network assessment right now.",
  },
  zap: {
    label: "Web Engine",
    targetKind: "Website URL",
    targetHelp: "Use a full website URL starting with http:// or https://.",
    description: "Queue a full URL for spider discovery followed by active web scanning.",
    buttonLabel: "Start Web Scan",
    loadingLabel: "Queueing web scan...",
    placeholder: "https://example.com",
    profile: "spider-active",
    success: "Web assessment queued. The web engine will start automatically in the background.",
    errorFallback: "Unable to queue the web assessment right now.",
  },
  mobsf: {
    label: "Mobile Engine",
    targetKind: "Mobile binary",
    targetHelp: "Upload an APK, IPA, or AAB file for static analysis.",
    description: "Queue a mobile binary for background static security assessment.",
    buttonLabel: "Start Mobile Scan",
    loadingLabel: "Queueing mobile scan...",
    placeholder: "",
    profile: "static-analysis",
    success: "Mobile assessment queued. Static analysis will begin automatically in the background.",
    errorFallback: "Unable to queue the mobile assessment right now.",
  },
};

const FQDN_PATTERN = /^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$/;

function isValidIpAddress(value) {
  if (!value) return false;
  if (value.includes(":")) {
    return /^[0-9A-Fa-f:]+$/.test(value) && value.includes(":");
  }
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isValidFqdn(value) {
  return FQDN_PATTERN.test(value);
}

function isValidCidr(value) {
  const [ip, prefix] = value.split("/");
  if (!ip || prefix === undefined || !isValidIpAddress(ip)) return false;
  const prefixNumber = Number(prefix);
  return Number.isInteger(prefixNumber) && prefixNumber >= 24 && prefixNumber <= 32;
}

function validateTarget(engine, value) {
  const normalized = value.trim();
  if (!normalized) return "Target is required.";
  if (engine === "openvas") {
    return isValidIpAddress(normalized) || isValidFqdn(normalized) || isValidCidr(normalized) ? "" : "Enter a valid IP address, FQDN, or IPv4 CIDR block up to /24.";
  }
  if (engine === "zap") {
    try {
      const parsed = new URL(normalized);
      return parsed.protocol === "http:" || parsed.protocol === "https:" ? "" : "Enter a full http:// or https:// URL.";
    } catch {
      return "Enter a full http:// or https:// URL.";
    }
  }
  return "";
}

function engineLabel(tool) {
  return tool === "openvas" ? "Network Engine" : tool === "zap" ? "Web Engine" : "Mobile Engine";
}

function actionButtons(scan) {
  if (["completed", "failed", "cancelled"].includes(scan.status)) return [];
  if (scan.status === "paused") return ["resume", "cancel"];
  return ["pause", "cancel"];
}

function actionLabel(action) {
  if (action === "pause") return "Pause";
  if (action === "resume") return "Start";
  return "Cancel";
}

function assetTarget(asset, engine) {
  if (engine === "zap") return asset.url || "";
  return asset.ip_address || asset.hostname || "";
}

export default function Scans({ scans, assets, onScanQueued, onScanUpdated }) {
  const [engine, setEngine] = useState("openvas");
  const [target, setTarget] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [mobileFile, setMobileFile] = useState(null);
  const [launchState, setLaunchState] = useState({ status: "idle", message: "" });
  const [actionState, setActionState] = useState({});
  const [scheduleState, setScheduleState] = useState({ cadenceMinutes: "60", jobs: [] });
  const [assetInventory, setAssetInventory] = useState(assets || []);
  const selectedEngine = ENGINE_OPTIONS[engine];
  const targetError = validateTarget(engine, target);
  const inProgressScans = scans.filter((scan) => ["waiting", "queued", "running", "paused"].includes(scan.status));
  const filteredAssets = useMemo(
    () => (assetInventory || []).filter((asset) => (engine === "zap" ? Boolean(asset.url) : Boolean(asset.ip_address || asset.hostname))),
    [assetInventory, engine]
  );

  useEffect(() => {
    setAssetInventory(assets || []);
  }, [assets]);

  useEffect(() => {
    api.get("/assets").then((response) => setAssetInventory(response.data || [])).catch(() => {});
  }, []);

  const loadSchedules = async () => {
    try {
      const response = await api.get("/schedules/");
      setScheduleState((current) => ({ ...current, jobs: response.data }));
    } catch {
      setScheduleState((current) => ({ ...current, jobs: [] }));
    }
  };

  useEffect(() => {
    loadSchedules();
  }, []);

  const startScan = async (event) => {
    event.preventDefault();
    if (engine === "mobsf" && !mobileFile) {
      setLaunchState({ status: "error", message: "Select an APK, IPA, or AAB file to start a mobile assessment." });
      return;
    }
    if (engine !== "mobsf" && targetError) {
      setLaunchState({ status: "error", message: targetError });
      return;
    }
    setLaunchState({ status: "loading", message: selectedEngine.loadingLabel });
    try {
      let response;
      if (engine === "openvas") {
        response = await api.post("/scans/network", { target: target.trim(), label: `Network Assessment ${target.trim()}` });
      } else if (engine === "zap") {
        response = await api.post("/scans/web", { target: target.trim(), label: `Web Assessment ${target.trim()}` });
      } else {
        const form = new FormData();
        form.append("file", mobileFile);
        form.append("label", `Mobile Assessment ${mobileFile.name}`);
        response = await api.post("/scans/mobile", form, { headers: { "Content-Type": "multipart/form-data" } });
      }
      onScanQueued?.(response.data);
      setLaunchState({ status: "success", message: selectedEngine.success });
      setTarget("");
      setMobileFile(null);
      setSelectedAssetId("");
    } catch (error) {
      setLaunchState({ status: "error", message: error?.response?.data?.detail || selectedEngine.errorFallback });
    }
  };

  const handleScanAction = async (scan, action) => {
    setActionState((current) => ({ ...current, [scan.id]: action }));
    try {
      const response = await api.post(`/scans/${scan.id}/${action}`);
      onScanUpdated?.(response.data);
    } catch (error) {
      setLaunchState({ status: "error", message: error?.response?.data?.detail || `Unable to ${action} this assessment right now.` });
    } finally {
      setActionState((current) => {
        const next = { ...current };
        delete next[scan.id];
        return next;
      });
    }
  };

  const createSchedule = async () => {
    if (engine === "mobsf") {
      setLaunchState({ status: "error", message: "Recurring mobile schedules are not enabled yet." });
      return;
    }
    if (targetError) {
      setLaunchState({ status: "error", message: targetError });
      return;
    }
    try {
      await api.post("/schedules/", {
        job_name: `${selectedEngine.label} ${target.trim()}`,
        scan_type: engine === "openvas" ? "network" : "web",
        tool: engine,
        target: target.trim(),
        profile: selectedEngine.profile,
        cadence_minutes: Number(scheduleState.cadenceMinutes || 60),
        options: {},
      });
      setLaunchState({ status: "success", message: "Recurring assessment schedule created." });
      await loadSchedules();
    } catch (error) {
      setLaunchState({ status: "error", message: error?.response?.data?.detail || "Unable to create the schedule right now." });
    }
  };

  const toggleSchedule = async (jobId) => {
    try {
      await api.post(`/schedules/${jobId}/toggle`);
      await loadSchedules();
    } catch (error) {
      setLaunchState({ status: "error", message: error?.response?.data?.detail || "Unable to update the schedule right now." });
    }
  };

  return (
    <section className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Campaign orchestration</p>
          <h2>Launch and control scans</h2>
        </div>
      </div>
      <form className="scan-launcher" onSubmit={startScan}>
        <div className="scan-launcher__copy">
          <strong>Launch an assessment</strong>
          <p>{selectedEngine.description}</p>
        </div>
        <div className="scan-launcher__controls">
          <select className="scan-select" value={engine} onChange={(event) => { setEngine(event.target.value); setTarget(""); setSelectedAssetId(""); setLaunchState({ status: "idle", message: "" }); }}>
            {Object.entries(ENGINE_OPTIONS).map(([value, option]) => (
              <option key={value} value={value}>{option.label}</option>
            ))}
          </select>
          {engine !== "mobsf" ? (
            <>
              <select
                className="scan-select"
                value={selectedAssetId}
                onChange={(event) => {
                  const asset = filteredAssets.find((item) => item.id === event.target.value);
                  setSelectedAssetId(event.target.value);
                  setTarget(asset ? assetTarget(asset, engine) : "");
                }}
              >
                <option value="">Pick from assets</option>
                {filteredAssets.map((asset) => (
                  <option key={asset.id} value={asset.id}>
                    {asset.asset_name} - {assetTarget(asset, engine)}
                  </option>
                ))}
              </select>
              <input className="scan-input" value={target} onChange={(event) => { setTarget(event.target.value); setSelectedAssetId(""); }} placeholder={selectedEngine.placeholder} />
            </>
          ) : (
            <input
              className="scan-input"
              type="file"
              accept=".apk,.ipa,.aab"
              onChange={(event) => {
                setMobileFile(event.target.files?.[0] || null);
                if (launchState.status !== "idle") setLaunchState({ status: "idle", message: "" });
              }}
            />
          )}
          <button type="submit" disabled={launchState.status === "loading" || (engine !== "mobsf" && Boolean(targetError))}>
            {launchState.status === "loading" ? "Queueing..." : selectedEngine.buttonLabel}
          </button>
          <div className="scan-actions">
            <select className="scan-select" value={scheduleState.cadenceMinutes} onChange={(event) => setScheduleState((current) => ({ ...current, cadenceMinutes: event.target.value }))}>
              <option value="15">Every 15 min</option>
              <option value="30">Every 30 min</option>
              <option value="60">Hourly</option>
              <option value="360">Every 6 hours</option>
              <option value="1440">Daily</option>
            </select>
            <button type="button" className="scan-action scan-action--resume" onClick={createSchedule}>Schedule</button>
          </div>
          <p className="scan-target-hint"><strong>{selectedEngine.targetKind}:</strong> {selectedEngine.targetHelp}</p>
          {engine !== "mobsf" && targetError ? <p className="scan-feedback scan-feedback--error">{targetError}</p> : null}
          {engine === "mobsf" && mobileFile ? <p className="scan-feedback scan-feedback--success">Selected binary: {mobileFile.name}</p> : null}
        </div>
      </form>
      {launchState.message ? <p className={`scan-feedback scan-feedback--${launchState.status}`}>{launchState.message}</p> : null}

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
              <th>Controls</th>
            </tr>
          </thead>
          <tbody>
            {inProgressScans.map((scan) => (
              <tr key={scan.id}>
                <td data-label="Name">{scan.scan_name}</td>
                <td data-label="Engine">{engineLabel(scan.tool)}</td>
                <td data-label="Type">{scan.scan_type}</td>
                <td data-label="Target">{scan.target}</td>
                <td data-label="Status"><span className={`pill pill--${scan.status}`}>{scan.status}</span></td>
                <td data-label="Progress">{scan.progress}%</td>
                <td data-label="Controls">
                  <div className="scan-actions">
                    {actionButtons(scan).map((action) => (
                      <button key={action} type="button" className={`scan-action scan-action--${action}`} disabled={Boolean(actionState[scan.id])} onClick={() => handleScanAction(scan, action)}>
                        {actionState[scan.id] === action ? `${actionLabel(action)}...` : actionLabel(action)}
                      </button>
                    ))}
                    {!actionButtons(scan).length ? <span className="scan-actions__empty">No actions</span> : null}
                  </div>
                </td>
              </tr>
            ))}
            {!inProgressScans.length ? (
              <tr>
                <td colSpan="7"><p className="empty-copy">No scans are currently running.</p></td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div className="panel panel--embedded">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Automation</p>
            <h2>Scheduled assessments</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Job</th>
                <th>Engine</th>
                <th>Target</th>
                <th>Cadence</th>
                <th>Next Run</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {scheduleState.jobs.map((job) => (
                <tr key={job.id}>
                  <td data-label="Job"><strong>{job.job_name}</strong></td>
                  <td data-label="Engine">{engineLabel(job.tool)}</td>
                  <td data-label="Target">{job.target}</td>
                  <td data-label="Cadence">{job.cadence_minutes} min</td>
                  <td data-label="Next Run">{job.next_run_at ? new Date(job.next_run_at).toLocaleString() : "Pending"}</td>
                  <td data-label="Status">
                    <button type="button" className={`scan-action ${job.enabled ? "scan-action--pause" : "scan-action--resume"}`} onClick={() => toggleSchedule(job.id)}>
                      {job.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
              {!scheduleState.jobs.length ? (
                <tr>
                  <td colSpan="6"><p className="empty-copy">No recurring assessments configured yet.</p></td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

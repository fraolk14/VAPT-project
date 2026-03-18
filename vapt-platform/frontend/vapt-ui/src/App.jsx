import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import api from "./api/client";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
import Integrations from "./pages/Integrations";
import "./App.css";

const emptySummary = {
  metrics: [],
  tool_coverage: {},
  severity_breakdown: {},
  open_findings: 0,
  active_scans: 0,
  risk_score: 0,
};

function App() {
  const location = useLocation();
  const [summary, setSummary] = useState(emptySummary);
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [integrations, setIntegrations] = useState({});

  const handleScanQueued = (scan) => {
    setScans((current) => [scan, ...current.filter((item) => item.id !== scan.id)]);
  };

  useEffect(() => {
    let ignore = false;

    const load = () => {
      Promise.all([
        api.get("/dashboard/summary"),
        api.get("/assets"),
        api.get("/scans/"),
        api.get("/findings/"),
        api.get("/integrations/health"),
      ])
        .then(([summaryRes, assetsRes, scansRes, findingsRes, integrationsRes]) => {
          if (ignore) return;
          setSummary(summaryRes.data);
          setAssets(assetsRes.data);
          setScans(scansRes.data);
          setFindings(findingsRes.data);
          setIntegrations(integrationsRes.data);
        })
        .catch(() => {
          if (ignore) return;
          setSummary(emptySummary);
          setAssets([]);
          setScans([]);
          setFindings([]);
          setIntegrations({});
        });
    };

    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      ignore = true;
      window.clearInterval(interval);
    };
  }, []);

  return (
    <div className="shell">
      <div className="shell__background" />
      <Navbar />
      <main className="shell__main">
        <section className="hero">
          <div>
            <p className="eyebrow">Unified Offensive Security Operations</p>
            <h1>VAPT Command Center</h1>
            <p className="hero__lede">
              Correlate network, web, mobile, and shadow IT telemetry into one
              risk-driven workflow across web, desktop, and mobile surfaces.
            </p>
          </div>
          <div className="hero__panel">
            <div>
              <span>Platform Risk</span>
              <strong>{summary.risk_score || "0.0"}</strong>
            </div>
            <div>
              <span>Open Findings</span>
              <strong>{summary.open_findings}</strong>
            </div>
            <div>
              <span>Active Scans</span>
              <strong>{summary.active_scans}</strong>
            </div>
          </div>
        </section>

        <div className="page-intro">
          <p className="eyebrow">Workspace</p>
          <h2>{pageTitle(location.pathname)}</h2>
        </div>

        <Routes>
          <Route path="/" element={<Dashboard summary={summary} />} />
          <Route path="/scans" element={<Scans scans={scans} onScanQueued={handleScanQueued} />} />
          <Route path="/findings" element={<Findings findings={findings} />} />
          <Route path="/assets" element={<Assets assets={assets} />} />
          <Route path="/integrations" element={<Integrations integrations={integrations} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function pageTitle(pathname) {
  if (pathname === "/scans") return "Scans";
  if (pathname === "/findings") return "Findings";
  if (pathname === "/assets") return "Assets";
  if (pathname === "/integrations") return "Integrations";
  return "Dashboard";
}

export default App;

import { useEffect, useState } from "react";
import api from "./api/client";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
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
  const [summary, setSummary] = useState(emptySummary);
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [integrations, setIntegrations] = useState({});

  useEffect(() => {
    Promise.all([
      api.get("/dashboard/summary"),
      api.get("/assets"),
      api.get("/scans"),
      api.get("/findings"),
      api.get("/integrations/health"),
    ])
      .then(([summaryRes, assetsRes, scansRes, findingsRes, integrationsRes]) => {
        setSummary(summaryRes.data);
        setAssets(assetsRes.data);
        setScans(scansRes.data);
        setFindings(findingsRes.data);
        setIntegrations(integrationsRes.data);
      })
      .catch(() => {
        setSummary(emptySummary);
        setAssets([]);
        setScans([]);
        setFindings([]);
        setIntegrations({});
      });
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
              Correlate OpenVAS, ZAP, mobile, and shadow IT telemetry into one
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

        <Dashboard summary={summary} integrations={integrations} />
        <Scans scans={scans} />
        <Findings findings={findings} />
        <Assets assets={assets} />
      </main>
    </div>
  );
}

export default App;

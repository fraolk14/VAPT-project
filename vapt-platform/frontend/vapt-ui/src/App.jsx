import React, { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import api from "./api/client";
import Navbar from "./components/Navbar";
import "./App.css";
import Assets from "./pages/Assets";
import AIRemediation from "./pages/AIRemediation";
import AccessDenied from "./pages/AccessDenied";
import Admin from "./pages/Admin";
import Dashboard from "./pages/Dashboard";
import Developer from "./pages/Developer";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Hosts from "./pages/Hosts";
import GlobalAttackMap from "./pages/GlobalAttackMap";
import Integrations from "./pages/Integrations";
import Login from "./pages/Login";
import Misconfigurations from "./pages/Misconfigurations";
import Reports from "./pages/Reports";
import Scans from "./pages/Scans";
import ShadowIT from "./pages/ShadowIT";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import UnauthorizedSoftware from "./pages/UnauthorizedSoftware";
import AgentManagement from "./pages/AgentManagement";
import Users from "./pages/Users";

class SafeErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("React Error Boundary caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "40px", textAlign: "center", color: "#f8fafc", background: "#0f172a", minHeight: "100vh" }}>
          <h2 style={{ color: "#ef4444" }}>Workspace Render Error</h2>
          <p style={{ color: "#94a3b8" }}>{this.state.error?.toString() || "An unexpected error occurred."}</p>
          <button className="btn btn--primary" onClick={() => window.location.reload()} style={{ marginTop: "16px" }}>
            Reload Workspace
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const emptySummary = {
  metrics: [],
  scanned_targets: [],
  tool_coverage: {},
  severity_breakdown: {},
  target_severity_breakdown: {},
  target_severity_by_tool: {},
  owasp_top10: [],
  attack_activity: [],
  open_findings: 0,
  active_scans: 0,
  risk_score: 0,
};

function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const [authState, setAuthState] = useState({
    status: "loading",
    user: null,
    error: "",
    awaitingMfa: false,
  });
  const [publicAuthConfig, setPublicAuthConfig] = useState({
    policy: {
      policy_name: "default",
      captcha_enabled: false,
      mfa_required: false,
      sso_required: false,
      allow_local_login: true,
    },
    providers: [],
  });

  const [navCollapsed, setNavCollapsed] = useState(false);
  const [summary, setSummary] = useState(emptySummary);
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [integrations, setIntegrations] = useState({});
  const [threatIntel, setThreatIntel] = useState({});
  const [authStatus, setAuthStatus] = useState({});
  const [authSessions, setAuthSessions] = useState([]);
  const [posture, setPosture] = useState({ shadowIt: {}, unauthorizedSoftware: {}, misconfigurations: {} });
  const [platformData, setPlatformData] = useState({
    attackSurface: {},
    attackPaths: {},
    plugins: [],
    apiKeys: [],
    hooks: [],
    events: [],
    tenants: [],
    monitoringRules: [],
    monitoringEvents: [],
    incidents: [],
    compliance: {},
    auditLogs: [],
  });
  const [alerts, setAlerts] = useState({ rules: [], events: [] });

  useEffect(() => {
    Promise.allSettled([api.get("/auth/policy"), api.get("/auth/sso/providers")]).then(([policyRes, providersRes]) => {
      setPublicAuthConfig({
        policy: policyRes.status === "fulfilled" ? policyRes.value.data : {
          policy_name: "default",
          captcha_enabled: false,
          mfa_required: false,
          sso_required: false,
          allow_local_login: true,
        },
        providers: providersRes.status === "fulfilled" ? providersRes.value.data : [],
      });
    });

    const token = window.localStorage.getItem("vapt_token");
    if (!token) {
      setAuthState({ status: "anonymous", user: null, error: "", awaitingMfa: false });
      return;
    }

    api
      .get("/auth/me")
      .then((response) => {
        setAuthState({ status: "authenticated", user: response.data, error: "", awaitingMfa: false });
      })
      .catch(() => {
        window.localStorage.removeItem("vapt_token");
        setAuthState({ status: "anonymous", user: null, error: "", awaitingMfa: false });
      });
  }, []);

  useEffect(() => {
    if (authState.status !== "authenticated") return;
    let ignore = false;

    const loadData = () => {
      Promise.allSettled([
        api.get("/dashboard/summary"),
        api.get("/scans/"),
        api.get("/assets/"),
        api.get("/findings/"),
        api.get("/iam/users"),
        api.get("/iam/groups"),
        api.get("/integrations/status"),
        api.get("/threat-intelligence/summary"),
        api.get("/auth/status"),
        api.get("/auth/sessions"),
        api.get("/posture/summary"),
        api.get("/platform/attack-surface"),
        api.get("/platform/attack-paths"),
        api.get("/platform/plugins"),
        api.get("/platform/api-keys"),
        api.get("/platform/devsecops/hooks"),
        api.get("/platform/devsecops/events"),
        api.get("/platform/tenants"),
        api.get("/operations/monitoring/rules"),
        api.get("/operations/monitoring/events"),
        api.get("/operations/incidents"),
        api.get("/operations/compliance/dashboard"),
        api.get("/alerts/rules"),
        api.get("/alerts/events"),
      ]).then((results) => {
        if (ignore) return;
        const [
          summaryRes, scansRes, assetsRes, findingsRes, usersRes, groupsRes,
          integrationsRes, threatIntelRes, authStatusRes, authSessionsRes,
          postureRes, attackSurfaceRes, attackPathsRes, pluginsRes, apiKeysRes,
          hooksRes, eventsRes, tenantsRes, monitoringRulesRes, monitoringEventsRes,
          incidentsRes, complianceRes, alertRulesRes, alertEventsRes
        ] = results;

        if (summaryRes.status === "fulfilled") setSummary(summaryRes.value.data);
        if (scansRes.status === "fulfilled") setScans(scansRes.value.data);
        if (assetsRes.status === "fulfilled") setAssets(assetsRes.value.data);
        if (findingsRes.status === "fulfilled") setFindings(findingsRes.value.data);
        if (usersRes.status === "fulfilled") setUsers(usersRes.value.data);
        if (groupsRes.status === "fulfilled") setGroups(groupsRes.value.data);
        if (integrationsRes.status === "fulfilled") setIntegrations(integrationsRes.value.data);
        if (threatIntelRes.status === "fulfilled") setThreatIntel(threatIntelRes.value.data);
        if (authStatusRes.status === "fulfilled") setAuthStatus(authStatusRes.value.data);
        if (authSessionsRes.status === "fulfilled") setAuthSessions(authSessionsRes.value.data);
        if (postureRes.status === "fulfilled") setPosture(postureRes.value.data);

        setPlatformData({
          attackSurface: attackSurfaceRes.status === "fulfilled" ? attackSurfaceRes.value.data : {},
          attackPaths: attackPathsRes.status === "fulfilled" ? attackPathsRes.value.data : {},
          plugins: pluginsRes.status === "fulfilled" ? pluginsRes.value.data : [],
          apiKeys: apiKeysRes.status === "fulfilled" ? apiKeysRes.value.data : [],
          hooks: hooksRes.status === "fulfilled" ? hooksRes.value.data : [],
          events: eventsRes.status === "fulfilled" ? eventsRes.value.data : [],
          tenants: tenantsRes.status === "fulfilled" ? tenantsRes.value.data : [],
          monitoringRules: monitoringRulesRes.status === "fulfilled" ? monitoringRulesRes.value.data : [],
          monitoringEvents: monitoringEventsRes.status === "fulfilled" ? monitoringEventsRes.value.data : [],
          incidents: incidentsRes.status === "fulfilled" ? incidentsRes.value.data : [],
          compliance: complianceRes.status === "fulfilled" ? complianceRes.value.data : {},
        });

        setAlerts({
          rules: alertRulesRes.status === "fulfilled" ? alertRulesRes.value.data : [],
          events: alertEventsRes.status === "fulfilled" ? alertEventsRes.value.data : [],
        });
      });
    };

    loadData();
    const interval = window.setInterval(loadData, 4000);
    return () => {
      ignore = true;
      window.clearInterval(interval);
    };
  }, [authState.status]);

  const extractErrorMessage = (error) => {
    if (!error) return "Unable to sign in.";
    const detail = error?.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d) => (typeof d === "string" ? d : (d.msg || JSON.stringify(d)))).join(", ");
    }
    if (typeof detail === "object" && detail !== null) {
      return detail.message || detail.msg || JSON.stringify(detail);
    }
    if (error?.response?.data?.message) return error.response.data.message;
    if (error?.message) return error.message;
    return "Unable to sign in. Please check connectivity or server status.";
  };

  const handleLogin = async ({ username, password, otpCode, captchaToken, deviceName }) => {
    if (!username?.trim() || !password) {
      setAuthState((current) => ({
        ...current,
        status: "anonymous",
        error: "Username and password are required.",
      }));
      return;
    }

    setAuthState((current) => ({ ...current, status: "submitting", user: null, error: "" }));

    try {
      const form = new URLSearchParams();
      form.set("username", username.trim());
      form.set("password", password);
      if (otpCode?.trim()) form.set("otp_code", otpCode.trim());
      if (captchaToken?.trim()) form.set("captcha_token", captchaToken.trim());
      if (deviceName?.trim()) form.set("device_name", deviceName.trim());

      const tokenResponse = await api.post("/auth/login", form, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      if (tokenResponse.data.requires_mfa) {
        setAuthState({
          status: "anonymous",
          user: null,
          error: "",
          awaitingMfa: true,
        });
        return;
      }

      window.localStorage.setItem("vapt_token", tokenResponse.data.access_token);

      const profileResponse = await api.get("/auth/me");
      setAuthState({
        status: "authenticated",
        user: profileResponse.data,
        error: "",
        awaitingMfa: false,
      });
      navigate("/", { replace: true });
    } catch (error) {
      window.localStorage.removeItem("vapt_token");
      const errorMsg = extractErrorMessage(error);
      console.error("Sign in failed:", error, errorMsg);
      setAuthState({
        status: "anonymous",
        user: null,
        error: errorMsg,
        awaitingMfa: false,
      });
    }
  };

  const handleStartSso = async (providerId) => {
    try {
      const response = await api.get(`/auth/sso/${providerId}/start`);
      if (response.data?.redirect_url) {
        window.location.href = response.data.redirect_url;
      }
    } catch (error) {
      setAuthState((current) => ({
        ...current,
        error: error?.response?.data?.detail || "Failed to initiate SSO login redirect.",
      }));
    }
  };

  const handleLogout = () => {
    window.localStorage.removeItem("vapt_token");
    setAuthState({ status: "anonymous", user: null, error: "", awaitingMfa: false });
    navigate("/login", { replace: true });
  };

  const handleAssetCreated = (newAsset) => {
    setAssets((current) => [newAsset, ...current]);
  };

  const handleScanQueued = (newScan) => {
    setScans((current) => [newScan, ...current]);
  };

  const handleScanUpdated = (updatedScan) => {
    setScans((current) => current.map((item) => (item.id === updatedScan.id ? updatedScan : item)));
  };

  if (authState.status === "loading") {
    return (
      <div className="auth-loading">
        <div className="auth-loading__panel">
          <p className="eyebrow">Initializing secure session</p>
          <h1>Preparing VAP</h1>
        </div>
      </div>
    );
  }

  if (authState.status !== "authenticated" && location.pathname !== "/login") {
    return (
      <Login
        onLogin={handleLogin}
        onStartSso={handleStartSso}
        authConfig={publicAuthConfig}
        isSubmitting={authState.status === "submitting"}
        errorMessage={authState.error}
        awaitingMfa={authState.awaitingMfa}
      />
    );
  }

  return (
    <SafeErrorBoundary>
      <div className={navCollapsed ? "shell shell--nav-collapsed" : "shell"}>
        <div className="shell__background" />
        <Navbar
          user={authState.user}
          onLogout={handleLogout}
          collapsed={navCollapsed}
          onToggleCollapse={() => setNavCollapsed((current) => !current)}
        />
        <main className="shell__main">
          <div className="shell__content">
            <section className="hero">
              <div>
                <p className="eyebrow">Unified Offensive Security Operations</p>
                <h1>VAP</h1>
                <p className="hero__lede">
                  Correlate network, web, mobile, and shadow IT telemetry into one risk-driven
                  workflow across web, desktop, and mobile surfaces.
                </p>
              </div>
              <div className="hero__panel">
                <div>
                  <span>Platform Risk</span>
                  <strong>{summary.risk_score || "0.0"}</strong>
                </div>
                <div>
                  <span>Open Findings</span>
                  <strong>{summary.open_findings || 0}</strong>
                </div>
                <div>
                  <span>Active Scans</span>
                  <strong>{summary.active_scans || 0}</strong>
                </div>
              </div>
            </section>

            <div className="page-intro">
              <p className="eyebrow">Workspace</p>
              <h2>{pageTitle(location.pathname)}</h2>
            </div>

            <Routes>
              <Route
                path="/"
                element={<Dashboard summary={summary} assets={assets} findings={findings} threatIntel={threatIntel} posture={posture} attackSurface={platformData.attackSurface} attackPaths={platformData.attackPaths} incidents={platformData.incidents} monitoringEvents={platformData.monitoringEvents} />}
              />
              <Route path="/assets" element={<Assets assets={assets} findings={findings} attackSurface={platformData.attackSurface} attackPaths={platformData.attackPaths} onAssetCreated={handleAssetCreated} />} />
              <Route path="/ai-remediation" element={<AIRemediation findings={findings} scans={scans} compliance={platformData.compliance} />} />
              <Route
                path="/scans"
                element={
                  <Scans
                    scans={scans}
                    assets={assets}
                    onScanQueued={handleScanQueued}
                    onScanUpdated={handleScanUpdated}
                  />
                }
              />
              <Route path="/hosts" element={<Hosts scans={scans} assets={assets} findings={findings} />} />
              <Route path="/findings" element={<Findings findings={findings} users={users} groups={groups} />} />
              <Route path="/findings/:findingId" element={<FindingDetail findings={findings} assets={assets} />} />
              <Route path="/attack-map" element={<GlobalAttackMap />} />
              <Route path="/threat-intelligence" element={<ThreatIntelligence threatIntel={threatIntel} />} />
              <Route path="/shadow-it" element={<ShadowIT summary={posture.shadowIt} assets={assets} incidents={platformData.incidents} monitoringEvents={platformData.monitoringEvents} />} />
              <Route path="/misconfigurations" element={<Misconfigurations findings={findings} assets={assets} />} />
              <Route path="/unauthorized-software" element={<UnauthorizedSoftware summary={posture.unauthorizedSoftware} assets={assets} groups={groups} users={users} />} />
              <Route path="/agent-management" element={<AgentManagement />} />
              <Route path="/reports" element={<Reports findings={findings} scans={scans} compliance={platformData.compliance} incidents={platformData.incidents} alertRules={alerts.rules} alertEvents={alerts.events} />} />
              <Route path="/admin" element={<Users />} />
              <Route path="/users" element={<Users />} />
              <Route
                path="/developer"
                element={
                  <RoleGuard
                    user={authState.user}
                    allow={["admin"]}
                    fallbackTitle="Hidden developer area"
                    fallbackMessage="The developer console is only exposed to privileged internal operators."
                  >
                    <Developer scans={scans} findings={findings} users={users} groups={groups} auditLogs={platformData.auditLogs} />
                  </RoleGuard>
                }
              />
              <Route path="/integrations" element={<Integrations integrations={integrations} platformData={platformData} alertRules={alerts.rules} alertEvents={alerts.events} setAlerts={setAlerts} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </SafeErrorBoundary>
  );
}

function RoleGuard({ user, allow, children, fallbackTitle, fallbackMessage }) {
  if (allow.includes(user?.role)) {
    return children;
  }
  return <AccessDenied title={fallbackTitle} message={fallbackMessage} />;
}

function pageTitle(pathname) {
  if (pathname === "/assets") return "Assets";
  if (pathname === "/ai-remediation") return "AI Remediation";
  if (pathname === "/scans") return "Scans";
  if (pathname === "/hosts") return "Hosts";
  if (pathname === "/findings") return "Findings";
  if (pathname.startsWith("/findings/")) return "Finding Detail";
  if (pathname === "/attack-map") return "Global Attack Map";
  if (pathname === "/threat-intelligence") return "Threat Intelligence";
  if (pathname === "/shadow-it") return "Shadow IT";
  if (pathname === "/misconfigurations") return "Misconfigurations";
  if (pathname === "/unauthorized-software") return "Unauthorized Software";
  if (pathname === "/reports") return "Reports";
  if (pathname === "/admin" || pathname === "/users") return "Identity & Access Management (IAM)";
  if (pathname === "/developer") return "Developer";
  if (pathname === "/integrations") return "Integrations";
  return "Dashboard";
}

export default App;

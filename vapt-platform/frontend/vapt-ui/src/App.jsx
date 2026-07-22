import { useEffect, useState } from "react";
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
    const params = new URLSearchParams(window.location.search);
    const providerId = params.get("provider");
    const code = params.get("code");
    const state = params.get("state");
    const isCallback = params.get("sso_callback");
    if (!providerId || !code || !state || !isCallback || authState.status === "authenticated") return;

    setAuthState((current) => ({ ...current, status: "submitting", error: "" }));
    api.get(`/auth/sso/${providerId}/callback`, { params: { code, state, device_name: "SSO browser" } })
      .then(async (tokenResponse) => {
        window.localStorage.setItem("vapt_token", tokenResponse.data.access_token);
        const profileResponse = await api.get("/auth/me");
        window.history.replaceState({}, "", "/");
        setAuthState({ status: "authenticated", user: profileResponse.data, error: "", awaitingMfa: false });
        navigate("/", { replace: true });
      })
      .catch((error) => {
        window.history.replaceState({}, "", "/login");
        setAuthState({
          status: "anonymous",
          user: null,
          error: error?.response?.data?.detail || "Unable to complete SSO sign-in.",
          awaitingMfa: false,
        });
      });
  }, [authState.status, navigate]);

  const handleLogin = async ({ username, password, otpCode, captchaToken, deviceName }) => {
    if (!username.trim() || !password) {
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
      setAuthState({
        status: "anonymous",
        user: null,
        error: error?.response?.data?.detail || "Unable to sign in with those credentials.",
        awaitingMfa: false,
      });
    }
  };

  const handleLogout = () => {
    window.localStorage.removeItem("vapt_token");
    setAuthState({ status: "anonymous", user: null, error: "", awaitingMfa: false });
    navigate("/login", { replace: true });
  };

  const handleStartSso = async (providerId) => {
    try {
      const response = await api.get(`/auth/sso/${providerId}/start`);
      window.location.assign(response.data.redirect_url);
    } catch (error) {
      setAuthState((current) => ({
        ...current,
        status: "anonymous",
        error: error?.response?.data?.detail || "Unable to start SSO sign-in.",
      }));
    }
  };

  if (authState.status === "loading") {
    return (
      <div className="auth-loading">
        <div className="auth-loading__panel">
          <p className="eyebrow">Initializing secure session</p>
          <h1>Preparing VAPTICOM</h1>
        </div>
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={
          authState.status === "authenticated" ? (
            <Navigate to="/" replace />
          ) : (
            <Login
              onLogin={handleLogin}
              onStartSso={handleStartSso}
              isSubmitting={authState.status === "submitting"}
              errorMessage={authState.error}
              awaitingMfa={authState.awaitingMfa}
              authConfig={publicAuthConfig}
            />
          )
        }
      />
      <Route
        path="/*"
        element={
          authState.status === "authenticated" ? (
            <Workspace user={authState.user} onLogout={handleLogout} publicAuthConfig={publicAuthConfig} />
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
    </Routes>
  );
}

function Workspace({ user, onLogout, publicAuthConfig }) {
  const location = useLocation();
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [summary, setSummary] = useState(emptySummary);
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [integrations, setIntegrations] = useState({});
  const [authStatus, setAuthStatus] = useState({
    brute_force_protection: true,
    captcha_enabled: false,
    mfa_required: false,
    active_sessions: 0,
    locked_until: null,
  });
  const [authSessions, setAuthSessions] = useState([]);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [platformData, setPlatformData] = useState({
    plugins: [],
    apiKeys: [],
    hooks: [],
    events: [],
    attackSurface: {
      internal_assets: 0,
      external_assets: 0,
      web_assets: 0,
      cloud_assets: 0,
      mobile_assets: 0,
      exposed_findings: 0,
      internet_facing_targets: [],
      subdomain_candidates: [],
    },
    attackPaths: {
      total_paths: 0,
      high_risk_paths: 0,
      suggested_actions: [],
      paths: [],
    },
    tenants: [],
    monitoringRules: [],
    monitoringEvents: [],
    incidents: [],
    compliance: {
      templates: [],
      assessments: [],
      mapped_findings: 0,
      frameworks: {},
    },
    auditLogs: [],
  });
  const [alerts, setAlerts] = useState({
    rules: [],
    events: [],
  });
  const [posture, setPosture] = useState({
    shadowIt: { external_assets: 0, cloud_assets: 0, unknown_services: 0, reviewed_services: 0, suspicious_services: [], connector_status: {} },
    misconfigurations: { weak_tls: 0, exposed_services: 0, auth_issues: 0, cloud_findings: 0, categories: {}, top_items: [] },
    unauthorizedSoftware: { managed_endpoints: 0, unauthorized_apps: 0, high_risk_apps: 0, baseline_coverage: 0, detected_apps: [] },
  });
  const [threatIntel, setThreatIntel] = useState({
    total_enriched: 0,
    actively_exploited: 0,
    exploit_available: 0,
    by_severity: {},
    by_source: {},
    mitre_coverage: {},
    reference_coverage: {},
    misp_status: "not_configured",
    top_feed: [],
    misp_events: [],
  });

  const handleScanQueued = (scan) => {
    setScans((current) => [scan, ...current.filter((item) => item.id !== scan.id)]);
  };

  const handleScanUpdated = (scan) => {
    setScans((current) => current.map((item) => (item.id === scan.id ? scan : item)));
  };

  const handleAssetCreated = (asset) => {
    setAssets((current) => [asset, ...current.filter((item) => item.id !== asset.id)]);
  };

  useEffect(() => {
    let ignore = false;

    const load = () => {
      Promise.allSettled([
        api.get("/dashboard/summary"),
        api.get("/assets/"),
        api.get("/scans/"),
        api.get("/findings/"),
        api.get("/integrations/health"),
        api.get("/threat-intelligence/summary"),
        api.get("/auth/status"),
        api.get("/auth/sessions"),
        user?.role === "admin" ? api.get("/auth/admin/users") : Promise.reject(new Error("skipped")),
        user?.role === "admin" ? api.get("/auth/admin/groups") : Promise.reject(new Error("skipped")),
        api.get("/posture/shadow-it"),
        api.get("/posture/misconfigurations"),
        api.get("/posture/unauthorized-software"),
        api.get("/platform/attack-surface/summary"),
        api.get("/platform/attack-surface/paths"),
        api.get("/platform/plugins"),
        user?.role === "admin" ? api.get("/platform/api-keys") : Promise.reject(new Error("skipped")),
        api.get("/platform/devsecops/hooks"),
        api.get("/platform/devsecops/events"),
        user?.role === "admin" ? api.get("/operations/tenants") : Promise.reject(new Error("skipped")),
        api.get("/operations/monitoring/rules"),
        api.get("/operations/monitoring/events"),
        api.get("/operations/incidents"),
        api.get("/operations/compliance/summary"),
        user?.role === "admin" ? api.get("/operations/audit-logs") : Promise.reject(new Error("skipped")),
        api.get("/alerts/rules"),
        api.get("/alerts/events"),
      ]).then(([summaryRes, assetsRes, scansRes, findingsRes, integrationsRes, threatIntelRes, authStatusRes, authSessionsRes, usersRes, groupsRes, shadowRes, misconfigRes, softwareRes, attackSurfaceRes, attackPathsRes, pluginsRes, apiKeysRes, hooksRes, eventsRes, tenantsRes, monitoringRulesRes, monitoringEventsRes, incidentsRes, complianceRes, auditLogsRes, alertRulesRes, alertEventsRes]) => {
        if (ignore) return;
        setSummary(summaryRes.status === "fulfilled" ? summaryRes.value.data : emptySummary);
        setAssets(assetsRes.status === "fulfilled" ? assetsRes.value.data : []);
        setScans(scansRes.status === "fulfilled" ? scansRes.value.data : []);
        setFindings(findingsRes.status === "fulfilled" ? findingsRes.value.data : []);
        setIntegrations(integrationsRes.status === "fulfilled" ? integrationsRes.value.data : {});
        setAuthStatus(authStatusRes.status === "fulfilled" ? authStatusRes.value.data : {
          brute_force_protection: true,
          captcha_enabled: false,
          mfa_required: false,
          active_sessions: 0,
          locked_until: null,
        });
        setAuthSessions(authSessionsRes.status === "fulfilled" ? authSessionsRes.value.data : []);
        setUsers(usersRes.status === "fulfilled" ? usersRes.value.data : []);
        setGroups(groupsRes.status === "fulfilled" ? groupsRes.value.data : []);
        setPosture({
          shadowIt: shadowRes.status === "fulfilled" ? shadowRes.value.data : { external_assets: 0, cloud_assets: 0, unknown_services: 0, reviewed_services: 0, suspicious_services: [], connector_status: {} },
          misconfigurations: misconfigRes.status === "fulfilled" ? misconfigRes.value.data : { weak_tls: 0, exposed_services: 0, auth_issues: 0, cloud_findings: 0, categories: {}, top_items: [] },
          unauthorizedSoftware: softwareRes.status === "fulfilled" ? softwareRes.value.data : { managed_endpoints: 0, unauthorized_apps: 0, high_risk_apps: 0, baseline_coverage: 0, detected_apps: [] },
        });
        setThreatIntel(
          threatIntelRes.status === "fulfilled"
            ? threatIntelRes.value.data
            : {
                total_enriched: 0,
                actively_exploited: 0,
                exploit_available: 0,
                by_severity: {},
                by_source: {},
                mitre_coverage: {},
                reference_coverage: {},
                misp_status: "not_configured",
                top_feed: [],
                misp_events: [],
              }
        );
        setPlatformData({
          attackSurface: attackSurfaceRes.status === "fulfilled" ? attackSurfaceRes.value.data : {
            internal_assets: 0,
            external_assets: 0,
            web_assets: 0,
            cloud_assets: 0,
            mobile_assets: 0,
            exposed_findings: 0,
            internet_facing_targets: [],
            subdomain_candidates: [],
          },
          attackPaths: attackPathsRes.status === "fulfilled" ? attackPathsRes.value.data : {
            total_paths: 0,
            high_risk_paths: 0,
            suggested_actions: [],
            paths: [],
          },
          plugins: pluginsRes.status === "fulfilled" ? pluginsRes.value.data : [],
          apiKeys: apiKeysRes.status === "fulfilled" ? apiKeysRes.value.data : [],
          hooks: hooksRes.status === "fulfilled" ? hooksRes.value.data : [],
          events: eventsRes.status === "fulfilled" ? eventsRes.value.data : [],
          tenants: tenantsRes.status === "fulfilled" ? tenantsRes.value.data : [],
          monitoringRules: monitoringRulesRes.status === "fulfilled" ? monitoringRulesRes.value.data : [],
          monitoringEvents: monitoringEventsRes.status === "fulfilled" ? monitoringEventsRes.value.data : [],
          incidents: incidentsRes.status === "fulfilled" ? incidentsRes.value.data : [],
          compliance: complianceRes.status === "fulfilled" ? complianceRes.value.data : {
            templates: [],
            assessments: [],
            mapped_findings: 0,
            frameworks: {},
          },
          auditLogs: auditLogsRes.status === "fulfilled" ? auditLogsRes.value.data : [],
        });
        setAlerts({
          rules: alertRulesRes.status === "fulfilled" ? alertRulesRes.value.data : [],
          events: alertEventsRes.status === "fulfilled" ? alertEventsRes.value.data : [],
        });
      });
    };

    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      ignore = true;
      window.clearInterval(interval);
    };
  }, [user?.role]);

  return (
    <div className={navCollapsed ? "shell shell--nav-collapsed" : "shell"}>
      <div className="shell__background" />
      <Navbar
        user={user}
        onLogout={onLogout}
        collapsed={navCollapsed}
        onToggleCollapse={() => setNavCollapsed((current) => !current)}
      />
      <main className="shell__main">
        <div className="shell__content">
          <section className="hero">
            <div>
              <p className="eyebrow">Unified Offensive Security Operations</p>
              <h1>VAPTICOM</h1>
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
          <Route path="/reports" element={<Reports findings={findings} scans={scans} compliance={platformData.compliance} incidents={platformData.incidents} alertRules={alerts.rules} alertEvents={alerts.events} />} />
          <Route
            path="/admin"
            element={
              <RoleGuard
                user={user}
                allow={["admin"]}
                fallbackTitle="Admin access required"
                fallbackMessage="This area is reserved for administrative operators."
              >
                <Admin user={user} integrations={integrations} threatIntel={threatIntel} authStatus={authStatus} authSessions={authSessions} users={users} groups={groups} platformData={platformData} publicAuthConfig={publicAuthConfig} />
              </RoleGuard>
            }
          />
          <Route
            path="/developer"
            element={
              <RoleGuard
                user={user}
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
  if (pathname === "/admin") return "Users";
  if (pathname === "/developer") return "Developer";
  if (pathname === "/integrations") return "Integrations";
  return "Dashboard";
}

export default App;

import React, { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import api from "./api/client";
import Navbar from "./components/Navbar";
import "./App.css";
import "./theme.css";
import Assets from "./pages/Assets";
import AIRemediation from "./pages/AIRemediation";
import AccessDenied from "./pages/AccessDenied";
import Admin from "./pages/Admin";
import Analytics from "./pages/Analytics";
import CommandCenter from "./pages/CommandCenter";
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

  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [integrations, setIntegrations] = useState({});

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
    let inFlight = false;
    let hasLoaded = false;

    // Shared data refresh for all pages. Kept deliberately light: it used to fire 24 requests
    // (about 1 MB) every 4 seconds per open tab, which starved the API while scans ran.
    const loadData = () => {
      // Skip background refreshes in hidden tabs, but always do the first load.
      if (inFlight || (hasLoaded && document.hidden)) return;
      inFlight = true;

      // Each piece of state is applied as soon as its own request returns, so one slow
      // endpoint (e.g. threat-intel enrichment) never holds back findings or scans.
      const take = (path, apply) =>
        api.get(path).then((res) => { if (!ignore) apply(res.data); }).catch(() => {});

      Promise.allSettled([
        take("/findings/", setFindings),
        take("/scans/", setScans),
        take("/assets/", setAssets),
        take("/iam/users", setUsers),
        take("/iam/groups", setGroups),
      ]).then(() => {
        inFlight = false;
        hasLoaded = true;
      });
    };

    // Integration health probes external feeds, so fetch it once per sign-in, not on every poll.
    api.get("/integrations/health")
      .then((res) => { if (!ignore) setIntegrations(res.data); })
      .catch(() => {});

    loadData();
    const interval = window.setInterval(loadData, 30000);
    const onVisible = () => { if (!document.hidden) loadData(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      ignore = true;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
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

  const handleLogout = async () => {
    // End the session on the server too, so the token can't be reused.
    try {
      await api.post("/auth/logout");
    } catch {
      // Already expired or offline: clearing the token locally is all that's left to do.
    }
    window.localStorage.removeItem("vapt_token");
    setAuthState({ status: "anonymous", user: null, error: "", awaitingMfa: false });
    navigate("/", { replace: true });
  };

  useEffect(() => {
    const onSessionEnded = () => {
      setAuthState((current) => (current.status === "authenticated"
        ? { status: "anonymous", user: null, error: "Your session ended. Sign in again.", awaitingMfa: false }
        : current));
    };
    window.addEventListener("vapt:session-ended", onSessionEnded);
    return () => window.removeEventListener("vapt:session-ended", onSessionEnded);
  }, []);




  if (authState.status === "loading") {
    return (
      <div className="lg-loading" role="status"><span>Restoring your session…</span></div>
    );
  }

  if (authState.status !== "authenticated") {
    return (
      <Login
        onLogin={handleLogin}
        onStartSso={handleStartSso}
        authConfig={publicAuthConfig}
        isSubmitting={authState.status === "submitting"}
        errorMessage={authState.error}
        awaitingMfa={authState.awaitingMfa}
        onCancelMfa={() => setAuthState((current) => ({ ...current, awaitingMfa: false, error: "" }))}
      />
    );
  }

  return (
    <SafeErrorBoundary>
      <div className="shell">
        <Navbar user={authState.user} onLogout={handleLogout} integrations={integrations} />
        <main className="shell__main" id="main-content">
          <div className="shell__content">
            {!FULL_BLEED_ROUTES.has(location.pathname) && !location.pathname.startsWith("/findings/") && (
              <div className="nw-page-head">
                <h1>{pageTitle(location.pathname)}</h1>
              </div>
            )}

            <Routes>
              <Route path="/" element={<CommandCenter findings={findings} scans={scans} integrations={integrations} loading={!findings.length && !scans.length} />} />
              <Route
                path="/insights"
                element={<Analytics />}
              />
              <Route path="/assets" element={<Assets assets={assets} canOperate={canEditFindings(authState.user)} />} />
              <Route path="/ai-remediation" element={<AIRemediation findings={findings} />} />
              <Route
                path="/scans"
                element={
                  <Scans integrations={integrations} canOperate={canEditFindings(authState.user)} />
                }
              />
              <Route path="/hosts" element={<Hosts canOperate={canEditFindings(authState.user)} />} />
              <Route path="/findings" element={<Findings findings={findings} users={users} groups={groups} canEdit={canEditFindings(authState.user)} />} />
              <Route path="/findings/:findingId" element={<FindingDetail />} />
              <Route path="/attack-map" element={<GlobalAttackMap />} />
              <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
              <Route path="/shadow-it" element={<ShadowIT canOperate={canEditFindings(authState.user)} />} />
              <Route path="/misconfigurations" element={<Misconfigurations canOperate={canEditFindings(authState.user)} />} />
              <Route path="/unauthorized-software" element={<UnauthorizedSoftware canOperate={canEditFindings(authState.user)} />} />
              <Route path="/agent-management" element={<AgentManagement canAdmin={String(authState.user?.role || "").toLowerCase() === "admin"} />} />
              <Route path="/reports" element={<Reports canBrand={canEditFindings(authState.user)} />} />
              <Route path="/admin" element={<Users currentUser={authState.user} />} />
              <Route path="/users" element={<Users currentUser={authState.user} />} />
              <Route
                path="/developer"
                element={
                  <RoleGuard
                    user={authState.user}
                    allow={["admin"]}
                    fallbackTitle="Hidden developer area"
                    fallbackMessage="The developer console is only exposed to privileged internal operators."
                  >
                    <Developer scans={scans} findings={findings} users={users} groups={groups} auditLogs={[]} />
                  </RoleGuard>
                }
              />
              <Route path="/integrations" element={<Integrations canOperate={canEditFindings(authState.user)} canAdmin={String(authState.user?.role || "").toLowerCase() === "admin"} />} />
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

// Mirrors the backend's role mapping: admins and analysts (incl. "SecurityEngineer") may triage.
// Pages that draw their own command-center title band.
const FULL_BLEED_ROUTES = new Set(["/", "/findings", "/scans", "/assets", "/agent-management", "/reports", "/attack-map", "/threat-intelligence", "/insights", "/misconfigurations", "/shadow-it", "/unauthorized-software", "/integrations", "/admin", "/users", "/ai-remediation", "/hosts"]);

function canEditFindings(user) {
  const role = String(user?.role || "").toLowerCase().replace(/[\s_-]/g, "");
  return ["admin", "administrator", "analyst", "securityengineer", "engineer"].includes(role);
}

function pageTitle(pathname) {
  if (pathname === "/assets") return "Targets";
  if (pathname === "/insights") return "Analytics";
  if (pathname === "/agent-management") return "Endpoint agents";
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
  return "Overview";
}

export default App;

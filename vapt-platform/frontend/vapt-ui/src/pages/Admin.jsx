import { useEffect, useState } from "react";

import api from "../api/client";
import Card from "../components/Card";

const emptyUserForm = {
  username: "",
  email: "",
  password: "",
  role: "viewer",
  group_name: "",
  mfa_delivery_method: "totp",
};

const emptyGroupForm = {
  name: "",
  description: "",
};

const emptyTenantForm = {
  name: "",
  slug: "",
};

const emptyProviderForm = {
  name: "",
  provider_type: "oidc",
  login_url: "",
  metadata_url: "",
  client_id: "",
  client_secret: "",
  token_url: "",
  userinfo_url: "",
  scope: "openid profile email",
};

export default function Admin({ user, integrations, threatIntel, authStatus, authSessions, users, groups, platformData, publicAuthConfig }) {
  const healthyIntegrations = Object.values(integrations).filter((item) => item?.healthy).length;
  const totalIntegrations = Object.keys(integrations).length;
  const [localUsers, setLocalUsers] = useState(users || []);
  const [localGroups, setLocalGroups] = useState(groups || []);
  const [localTenants, setLocalTenants] = useState(platformData?.tenants || []);
  const [localProviders, setLocalProviders] = useState(publicAuthConfig?.providers || []);
  const [policy, setPolicy] = useState(publicAuthConfig?.policy || {
    captcha_enabled: false,
    mfa_required: false,
    sso_required: false,
    allow_local_login: true,
  });
  const [userForm, setUserForm] = useState(emptyUserForm);
  const [groupForm, setGroupForm] = useState(emptyGroupForm);
  const [tenantForm, setTenantForm] = useState(emptyTenantForm);
  const [providerForm, setProviderForm] = useState(emptyProviderForm);
  const [editingUserId, setEditingUserId] = useState("");
  const [userEditForm, setUserEditForm] = useState({
    username: "",
    email: "",
    password: "",
    role: "viewer",
    group_name: "",
    mfa_delivery_method: "totp",
    mfa_enabled: false,
    is_active: true,
  });
  const [emailGateway, setEmailGateway] = useState({
    configured: false,
    host: "mailpit",
    port: 1025,
    from_address: "noreply@vapticom.local",
    tls: false,
  });
  const [feedback, setFeedback] = useState("");
  const [feedbackType, setFeedbackType] = useState("idle");

  useEffect(() => setLocalUsers(users || []), [users]);
  useEffect(() => setLocalGroups(groups || []), [groups]);
  useEffect(() => setLocalTenants(platformData?.tenants || []), [platformData?.tenants]);
  useEffect(() => setLocalProviders(publicAuthConfig?.providers || []), [publicAuthConfig?.providers]);
  useEffect(() => setPolicy(publicAuthConfig?.policy || policy), [publicAuthConfig?.policy]);
  useEffect(() => {
    api.get("/auth/admin/email/status").then((response) => setEmailGateway(response.data)).catch(() => {});
  }, []);

  const createGroup = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/auth/admin/groups", groupForm);
      setLocalGroups((current) => [...current, response.data].sort((left, right) => left.name.localeCompare(right.name)));
      setGroupForm(emptyGroupForm);
      setFeedbackType("success");
      setFeedback("User group created.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the user group right now.");
    }
  };

  const createUser = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/auth/admin/users", { ...userForm, group_name: userForm.group_name || null });
      setLocalUsers((current) => [response.data, ...current]);
      setUserForm(emptyUserForm);
      setFeedbackType("success");
      setFeedback("User created successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the user right now.");
    }
  };

  const createTenant = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/operations/tenants", { ...tenantForm, settings: {} });
      setLocalTenants((current) => [response.data, ...current]);
      setTenantForm(emptyTenantForm);
      setFeedbackType("success");
      setFeedback("Tenant created.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the tenant right now.");
    }
  };

  const createProvider = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/auth/admin/sso/providers", {
        ...providerForm,
        metadata_url: providerForm.metadata_url || null,
      });
      setLocalProviders((current) => [response.data, ...current]);
      setProviderForm(emptyProviderForm);
      setFeedbackType("success");
      setFeedback("SSO provider registered.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the SSO provider right now.");
    }
  };

  const toggleProvider = async (providerId) => {
    try {
      const response = await api.post(`/auth/admin/sso/providers/${providerId}/toggle`);
      setLocalProviders((current) => current.map((item) => (item.id === providerId ? response.data : item)));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update provider state.");
    }
  };

  const savePolicy = async () => {
    try {
      const response = await api.post("/auth/admin/policy", policy);
      setPolicy(response.data);
      setFeedbackType("success");
      setFeedback("Authentication policy updated.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to update the policy right now.");
    }
  };

  const startEditUser = (entry) => {
    setEditingUserId(entry.id);
    setUserEditForm({
      username: entry.username,
      email: entry.email,
      password: "",
      role: entry.role,
      group_name: entry.group_name || "",
      mfa_delivery_method: entry.mfa_delivery_method || "totp",
      mfa_enabled: entry.mfa_enabled,
      is_active: entry.is_active,
    });
  };

  const cancelEditUser = () => {
    setEditingUserId("");
    setUserEditForm({
      username: "",
      email: "",
      password: "",
      role: "viewer",
      group_name: "",
      mfa_delivery_method: "totp",
      mfa_enabled: false,
      is_active: true,
    });
  };

  const saveUserEdit = async (userId) => {
    try {
      const response = await api.patch(`/auth/admin/users/${userId}`, {
        ...userEditForm,
        group_name: userEditForm.group_name || null,
        password: userEditForm.password || null,
      });
      setLocalUsers((current) => current.map((entry) => (entry.id === userId ? response.data : entry)));
      cancelEditUser();
      setFeedbackType("success");
      setFeedback("User updated successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to update the user right now.");
    }
  };

  const deleteUser = async (entry) => {
    if (!window.confirm(`Delete user "${entry.username}"? This removes their sessions and platform account.`)) return;
    try {
      await api.delete(`/auth/admin/users/${entry.id}`);
      setLocalUsers((current) => current.filter((item) => item.id !== entry.id));
      setFeedbackType("success");
      setFeedback("User deleted successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to delete the user right now.");
    }
  };

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Identity and access management</p>
            <h2>Users</h2>
          </div>
        </div>
        <div className="metrics-grid">
          <Card title="Current Role" value={user?.role || "unknown"} trend="Role-based administration active" />
          <Card title="Healthy Integrations" value={`${healthyIntegrations}/${totalIntegrations || 0}`} trend="Platform dependency health" />
          <Card title="Active Sessions" value={`${authStatus?.active_sessions || 0}`} trend="Tracked devices and tokens" />
          <Card title="Threat Enrichment" value={`${threatIntel?.total_enriched || 0}`} trend="Mapped findings under active triage" />
        </div>
      </div>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Provision access</p>
            <h2>Create platform user</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={createUser}>
          <input className="scan-input" placeholder="Username" value={userForm.username} onChange={(event) => setUserForm((current) => ({ ...current, username: event.target.value }))} />
          <input className="scan-input" placeholder="Email address" value={userForm.email} onChange={(event) => setUserForm((current) => ({ ...current, email: event.target.value }))} />
          <input className="scan-input" type="password" placeholder="Temporary password" value={userForm.password} onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))} />
          <select className="scan-select" value={userForm.role} onChange={(event) => setUserForm((current) => ({ ...current, role: event.target.value }))}>
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
          <select className="scan-select" value={userForm.group_name} onChange={(event) => setUserForm((current) => ({ ...current, group_name: event.target.value }))}>
            <option value="">No group</option>
            {localGroups.map((group) => <option key={group.id} value={group.name}>{group.name}</option>)}
          </select>
          <select className="scan-select" value={userForm.mfa_delivery_method} onChange={(event) => setUserForm((current) => ({ ...current, mfa_delivery_method: event.target.value }))}>
            <option value="totp">TOTP MFA</option>
            <option value="email">Email MFA</option>
          </select>
          <button type="submit" className="scan-action scan-action--resume">Create User</button>
        </form>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Ownership groups</p>
            <h2>Create assignment group</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={createGroup}>
          <input className="scan-input" placeholder="Group name" value={groupForm.name} onChange={(event) => setGroupForm((current) => ({ ...current, name: event.target.value }))} />
          <input className="scan-input" placeholder="Description" value={groupForm.description} onChange={(event) => setGroupForm((current) => ({ ...current, description: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Create Group</button>
        </form>
        <div className="coverage-list">
          {localGroups.length ? localGroups.map((group) => (
            <div className="coverage-row" key={group.id}>
              <span>{group.name}</span>
              <strong>{group.description || "Finding ownership group"}</strong>
            </div>
          )) : <p className="empty-copy">Create groups to organize who findings are assigned to.</p>}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Organizations</p>
            <h2>Create tenant</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={createTenant}>
          <input className="scan-input" placeholder="Tenant name" value={tenantForm.name} onChange={(event) => setTenantForm((current) => ({ ...current, name: event.target.value }))} />
          <input className="scan-input" placeholder="Slug" value={tenantForm.slug} onChange={(event) => setTenantForm((current) => ({ ...current, slug: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Create Tenant</button>
        </form>
        <div className="coverage-list">
          {localTenants.length ? localTenants.map((tenant) => (
            <div className="coverage-row" key={tenant.id}>
              <span>{tenant.name} ({tenant.slug})</span>
              <strong>{tenant.status}</strong>
            </div>
          )) : <p className="empty-copy">No tenant records are available yet.</p>}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Email gateway</p>
            <h2>Mail delivery</h2>
          </div>
        </div>
        <div className="coverage-list">
          <div className="coverage-row"><span>Status</span><strong>{emailGateway.configured ? "Configured" : "Not configured"}</strong></div>
          <div className="coverage-row"><span>SMTP host</span><strong>{emailGateway.host}:{emailGateway.port}</strong></div>
          <div className="coverage-row"><span>Sender</span><strong>{emailGateway.from_address}</strong></div>
          <div className="coverage-row"><span>MFA + assignment mail</span><strong>{emailGateway.tls ? "TLS enabled" : "Internal gateway"}</strong></div>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Enterprise authentication</p>
            <h2>Policy</h2>
          </div>
        </div>
        <div className="chip-grid">
          <label className="widget-selector__item"><input type="checkbox" checked={policy.allow_local_login} onChange={(event) => setPolicy((current) => ({ ...current, allow_local_login: event.target.checked }))} /><span>Allow local login</span></label>
          <label className="widget-selector__item"><input type="checkbox" checked={policy.captcha_enabled} onChange={(event) => setPolicy((current) => ({ ...current, captcha_enabled: event.target.checked }))} /><span>Enable CAPTCHA</span></label>
          <label className="widget-selector__item"><input type="checkbox" checked={policy.mfa_required} onChange={(event) => setPolicy((current) => ({ ...current, mfa_required: event.target.checked }))} /><span>Require MFA</span></label>
          <label className="widget-selector__item"><input type="checkbox" checked={policy.sso_required} onChange={(event) => setPolicy((current) => ({ ...current, sso_required: event.target.checked }))} /><span>Require SSO</span></label>
        </div>
        <div className="scan-actions">
          <button type="button" className="scan-action scan-action--resume" onClick={savePolicy}>Save Policy</button>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">SSO</p>
            <h2>Provider setup</h2>
          </div>
        </div>
        <p className="empty-copy">Callback URL for OIDC/OAuth2 providers: <strong>{window.location.origin}/login?sso_callback=1</strong></p>
        <form className="form-grid" onSubmit={createProvider}>
          <input className="scan-input" placeholder="Provider name" value={providerForm.name} onChange={(event) => setProviderForm((current) => ({ ...current, name: event.target.value }))} />
          <select className="scan-select" value={providerForm.provider_type} onChange={(event) => setProviderForm((current) => ({ ...current, provider_type: event.target.value }))}>
            <option value="oidc">OIDC</option>
            <option value="oauth2">OAuth2</option>
            <option value="saml">SAML</option>
          </select>
          <input className="scan-input" placeholder="Login URL" value={providerForm.login_url} onChange={(event) => setProviderForm((current) => ({ ...current, login_url: event.target.value }))} />
          <input className="scan-input" placeholder="Metadata URL (optional)" value={providerForm.metadata_url} onChange={(event) => setProviderForm((current) => ({ ...current, metadata_url: event.target.value }))} />
          <input className="scan-input" placeholder="Client ID" value={providerForm.client_id} onChange={(event) => setProviderForm((current) => ({ ...current, client_id: event.target.value }))} />
          <input className="scan-input" placeholder="Client secret" value={providerForm.client_secret} onChange={(event) => setProviderForm((current) => ({ ...current, client_secret: event.target.value }))} />
          <input className="scan-input" placeholder="Token URL (optional if discovery metadata is used)" value={providerForm.token_url} onChange={(event) => setProviderForm((current) => ({ ...current, token_url: event.target.value }))} />
          <input className="scan-input" placeholder="Userinfo URL (optional if discovery metadata is used)" value={providerForm.userinfo_url} onChange={(event) => setProviderForm((current) => ({ ...current, userinfo_url: event.target.value }))} />
          <input className="scan-input" placeholder="Scope" value={providerForm.scope} onChange={(event) => setProviderForm((current) => ({ ...current, scope: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Add Provider</button>
        </form>
        <div className="coverage-list">
          {localProviders.length ? localProviders.map((provider) => (
            <div className="coverage-row" key={provider.id}>
              <span>{provider.name} ({provider.provider_type})</span>
              <strong>
                {provider.enabled ? "enabled" : "disabled"}
                {" "}
                <button type="button" className="scan-action" onClick={() => toggleProvider(provider.id)}>{provider.enabled ? "Disable" : "Enable"}</button>
              </strong>
            </div>
          )) : <p className="empty-copy">No SSO providers configured yet.</p>}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Platform directory</p>
            <h2>Users and assigned groups</h2>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Group</th>
                <th>Source</th>
                <th>MFA</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {localUsers.map((entry) => (
                <tr key={entry.id}>
                  <td data-label="User">
                    {editingUserId === entry.id ? (
                      <div className="table-edit-stack">
                        <input className="scan-input" value={userEditForm.username} onChange={(event) => setUserEditForm((current) => ({ ...current, username: event.target.value }))} />
                        <input className="scan-input" value={userEditForm.email} onChange={(event) => setUserEditForm((current) => ({ ...current, email: event.target.value }))} />
                        <input className="scan-input" type="password" placeholder="Leave blank to keep password" value={userEditForm.password} onChange={(event) => setUserEditForm((current) => ({ ...current, password: event.target.value }))} />
                      </div>
                    ) : (
                      <>
                        <strong>{entry.username}</strong>
                        <p>{entry.email}</p>
                      </>
                    )}
                  </td>
                  <td data-label="Role">
                    {editingUserId === entry.id ? (
                      <select className="scan-select" value={userEditForm.role} onChange={(event) => setUserEditForm((current) => ({ ...current, role: event.target.value }))}>
                        <option value="viewer">Viewer</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    ) : entry.role}
                  </td>
                  <td data-label="Group">
                    {editingUserId === entry.id ? (
                      <select className="scan-select" value={userEditForm.group_name} onChange={(event) => setUserEditForm((current) => ({ ...current, group_name: event.target.value }))}>
                        <option value="">Unassigned</option>
                        {localGroups.map((group) => <option key={group.id} value={group.name}>{group.name}</option>)}
                      </select>
                    ) : (entry.group_name || "Unassigned")}
                  </td>
                  <td data-label="Source">{entry.auth_source}</td>
                  <td data-label="MFA">
                    {editingUserId === entry.id ? (
                      <div className="table-edit-stack">
                        <select className="scan-select" value={userEditForm.mfa_delivery_method} onChange={(event) => setUserEditForm((current) => ({ ...current, mfa_delivery_method: event.target.value }))}>
                          <option value="totp">TOTP</option>
                          <option value="email">Email</option>
                        </select>
                        <label className="widget-selector__item">
                          <input type="checkbox" checked={userEditForm.mfa_enabled} onChange={(event) => setUserEditForm((current) => ({ ...current, mfa_enabled: event.target.checked }))} />
                          <span>MFA enabled</span>
                        </label>
                      </div>
                    ) : (
                      entry.mfa_enabled ? `Enabled (${entry.mfa_delivery_method})` : `Configured (${entry.mfa_delivery_method})`
                    )}
                  </td>
                  <td data-label="Status">
                    {editingUserId === entry.id ? (
                      <label className="widget-selector__item">
                        <input type="checkbox" checked={userEditForm.is_active} onChange={(event) => setUserEditForm((current) => ({ ...current, is_active: event.target.checked }))} />
                        <span>{userEditForm.is_active ? "Active" : "Disabled"}</span>
                      </label>
                    ) : (entry.is_active ? "Active" : "Disabled")}
                  </td>
                  <td data-label="Actions">
                    <div className="scan-actions">
                      {editingUserId === entry.id ? (
                        <>
                          <button type="button" className="scan-action scan-action--resume" onClick={() => saveUserEdit(entry.id)}>Save</button>
                          <button type="button" className="scan-action" onClick={cancelEditUser}>Cancel</button>
                        </>
                      ) : (
                        <>
                          <button type="button" className="scan-action scan-action--resume" onClick={() => startEditUser(entry)}>Edit</button>
                          <button type="button" className="scan-action scan-action--cancel" onClick={() => deleteUser(entry)}>Delete</button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {!localUsers.length ? <tr><td colSpan="7"><p className="empty-copy">No users are visible yet.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Session telemetry</p>
            <h2>Tracked devices</h2>
          </div>
        </div>
        <div className="coverage-list">
          {authSessions?.length ? authSessions.map((session) => (
            <div className="coverage-row" key={session.id}>
              <span>{session.device_name || "Unnamed device"} {session.ip_address ? `(${session.ip_address})` : ""}</span>
              <strong>{session.is_active ? "Active" : "Revoked"}</strong>
            </div>
          )) : <p className="empty-copy">No session telemetry is available yet.</p>}
        </div>
        {feedback ? <p className={`scan-feedback scan-feedback--${feedbackType}`}>{feedback}</p> : null}
      </section>
    </section>
  );
}

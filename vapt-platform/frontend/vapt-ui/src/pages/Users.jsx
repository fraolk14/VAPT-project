import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { motion, AnimatePresence } from "framer-motion";
import api from "../api/client";
import {
  FiUsers,
  FiUserPlus,
  FiUserCheck,
  FiUserX,
  FiShield,
  FiLock,
  FiKey,
  FiSettings,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiCheckCircle,
  FiXCircle,
  FiFilter,
  FiRefreshCw,
  FiSliders,
  FiGlobe,
  FiServer,
  FiCpu,
  FiX,
  FiCheck,
} from "react-icons/fi";

// API Fetchers using authenticated client
const fetchUsersApi = async () => (await api.get("/iam/users")).data;
const fetchGroupsApi = async () => (await api.get("/iam/groups")).data;
const fetchRolesApi = async () => (await api.get("/iam/roles")).data;
const fetchPoliciesApi = async () => (await api.get("/iam/policies")).data;
const fetchSsoApi = async () => (await api.get("/iam/sso")).data;

export default function Users() {
  const [activeTab, setActiveTab] = useState("users"); // users | groups | rbac | policies | sso
  const [searchFilter, setSearchFilter] = useState("");
  const [modalState, setModalState] = useState(null); // null | "create_user" | "edit_user" | "create_group" | "create_policy"
  const [selectedUser, setSelectedUser] = useState(null);

  const queryClient = useQueryClient();

  // Queries
  const { data: users = [], isLoading: loadingUsers, refetch: refetchUsers } = useQuery({ queryKey: ["iam-users"], queryFn: fetchUsersApi });
  const { data: groups = [], isLoading: loadingGroups, refetch: refetchGroups } = useQuery({ queryKey: ["iam-groups"], queryFn: fetchGroupsApi });
  const { data: roles = [], isLoading: loadingRoles, refetch: refetchRoles } = useQuery({ queryKey: ["iam-roles"], queryFn: fetchRolesApi });
  const { data: policies = [], isLoading: loadingPolicies, refetch: refetchPolicies } = useQuery({ queryKey: ["iam-policies"], queryFn: fetchPoliciesApi });
  const { data: ssoConfigs = [], isLoading: loadingSso, refetch: refetchSso } = useQuery({ queryKey: ["iam-sso"], queryFn: fetchSsoApi });

  // Forms
  const userForm = useForm();
  const groupForm = useForm();
  const policyForm = useForm();

  // Mutations
  const createUserMutation = useMutation({
    mutationFn: async (data) => (await api.post("/iam/users", data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries(["iam-users"]);
      setModalState(null);
      userForm.reset();
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: async ({ id, data }) => (await api.put(`/iam/users/${id}`, data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries(["iam-users"]);
      setModalState(null);
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (id) => (await api.delete(`/iam/users/${id}`)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-users"]),
    onError: (err) => alert(err?.response?.data?.detail || "Failed to delete user."),
  });

  const toggleUserActiveMutation = useMutation({
    mutationFn: async (id) => (await api.post(`/iam/users/${id}/toggle-active`)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-users"]),
  });

  const toggleUserMfaMutation = useMutation({
    mutationFn: async (id) => (await api.post(`/iam/users/${id}/toggle-mfa`)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-users"]),
  });

  const createGroupMutation = useMutation({
    mutationFn: async (data) => (await api.post("/iam/groups", data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries(["iam-groups"]);
      setModalState(null);
      groupForm.reset();
    },
  });

  const deleteGroupMutation = useMutation({
    mutationFn: async (id) => (await api.delete(`/iam/groups/${id}`)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-groups"]),
    onError: (err) => alert(err?.response?.data?.detail || "Failed to delete group."),
  });

  const createPolicyMutation = useMutation({
    mutationFn: async (data) => (await api.post("/iam/policies", data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries(["iam-policies"]);
      setModalState(null);
      policyForm.reset();
    },
  });

  const deletePolicyMutation = useMutation({
    mutationFn: async (id) => (await api.delete(`/iam/policies/${id}`)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-policies"]),
    onError: (err) => alert(err?.response?.data?.detail || "Failed to delete policy."),
  });

  const saveSsoMutation = useMutation({
    mutationFn: async (data) => (await api.post("/iam/sso", data)).data,
    onSuccess: () => queryClient.invalidateQueries(["iam-sso"]),
  });

  // Filtered Users
  const filteredUsers = users.filter(
    (u) =>
      !searchFilter ||
      u.email?.toLowerCase().includes(searchFilter.toLowerCase()) ||
      u.full_name?.toLowerCase().includes(searchFilter.toLowerCase()) ||
      u.role_name?.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", padding: "8px 0" }}>
      {/* Top Banner Header */}
      <div
        className="panel"
        style={{
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.85))",
          border: "1px solid rgba(148, 163, 184, 0.15)",
          borderRadius: "16px",
          padding: "20px 24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{ background: "rgba(56, 189, 248, 0.1)", padding: "12px", borderRadius: "12px", border: "1px solid rgba(56, 189, 248, 0.2)" }}>
            <FiShield style={{ color: "#38bdf8", fontSize: "24px" }} />
          </div>
          <div>
            <h1 style={{ fontSize: "1.5rem", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
              Identity & Access Management (IAM)
            </h1>
            <p style={{ color: "#94a3b8", fontSize: "0.88rem", margin: 0 }}>
              Production user administration, role-based access control, TOTP MFA enforcement, policy engine, and SSO integration.
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            refetchUsers();
            refetchGroups();
            refetchRoles();
            refetchPolicies();
            refetchSso();
          }}
          className="btn btn--secondary"
          style={{ height: "38px", padding: "0 14px", display: "flex", alignItems: "center", gap: "6px" }}
        >
          <FiRefreshCw className={loadingUsers ? "spin" : ""} /> Refresh Telemetry
        </button>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: "flex", gap: "10px", borderBottom: "1px solid rgba(148, 163, 184, 0.15)", paddingBottom: "12px", flexWrap: "wrap" }}>
        {[
          { id: "users", label: `Users (${users.length})`, icon: FiUsers },
          { id: "groups", label: `Groups (${groups.length})`, icon: FiUserCheck },
          { id: "rbac", label: `RBAC Roles (${roles.length})`, icon: FiShield },
          { id: "policies", label: `Policy Engine (${policies.length})`, icon: FiSliders },
          { id: "sso", label: "SSO Configuration", icon: FiKey },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: "8px 16px",
                borderRadius: "8px",
                border: activeTab === tab.id ? "1px solid #38bdf8" : "1px solid transparent",
                background: activeTab === tab.id ? "rgba(56, 189, 248, 0.15)" : "transparent",
                color: activeTab === tab.id ? "#38bdf8" : "#94a3b8",
                fontWeight: "600",
                fontSize: "0.88rem",
                display: "flex",
                alignItems: "center",
                gap: "8px",
                cursor: "pointer",
                transition: "all 0.2s ease",
              }}
            >
              <Icon /> {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: USER MANAGEMENT */}
      {activeTab === "users" && (
        <div className="panel">
          <div className="panel__header" style={{ flexWrap: "wrap", gap: "16px" }}>
            <div>
              <p className="eyebrow">Directory Accounts</p>
              <h2>User Management</h2>
            </div>

            <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
              <input
                className="scan-input"
                placeholder="Filter by name, email, role..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{ width: "220px", height: "38px" }}
              />
              <button
                onClick={() => {
                  userForm.reset();
                  setModalState("create_user");
                }}
                className="btn btn--primary"
                style={{ height: "38px", padding: "0 16px", display: "flex", alignItems: "center", gap: "6px" }}
              >
                <FiUserPlus /> Create User
              </button>
            </div>
          </div>

          <div className="table-wrap">
            <table className="table table--dense">
              <thead>
                <tr>
                  <th>User Profile</th>
                  <th>Role</th>
                  <th>Assigned Groups</th>
                  <th>Status</th>
                  <th>MFA (TOTP)</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.id}>
                    <td data-label="User Profile">
                      <strong style={{ color: "#f8fafc" }}>{u.full_name}</strong>
                      <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>{u.email}</p>
                    </td>
                    <td data-label="Role">
                      <span className="pill pill--info" style={{ background: "rgba(56, 189, 248, 0.12)", color: "#38bdf8" }}>
                        {u.role_name}
                      </span>
                    </td>
                    <td data-label="Assigned Groups">
                      {u.groups.length > 0 ? (
                        u.groups.map((g) => (
                          <span key={g} style={{ padding: "2px 6px", borderRadius: "4px", background: "rgba(148, 163, 184, 0.12)", color: "#cbd5e1", fontSize: "0.75rem", marginRight: "4px" }}>
                            {g}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: "#64748b", fontSize: "0.78rem" }}>No groups</span>
                      )}
                    </td>
                    <td data-label="Status">
                      <button
                        onClick={() => toggleUserActiveMutation.mutate(u.id)}
                        style={{
                          background: "none",
                          border: "none",
                          cursor: "pointer",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "4px",
                          color: u.is_active ? "#10b981" : "#ef4444",
                          fontWeight: "600",
                        }}
                      >
                        {u.is_active ? <FiCheckCircle /> : <FiXCircle />}
                        {u.is_active ? "Active" : "Inactive"}
                      </button>
                    </td>
                    <td data-label="MFA (TOTP)">
                      <button
                        onClick={() => toggleUserMfaMutation.mutate(u.id)}
                        className={`pill pill--${u.mfa_enabled ? "critical" : "low"}`}
                        style={{ cursor: "pointer" }}
                      >
                        {u.mfa_enabled ? "MFA Enforced" : "MFA Disabled"}
                      </button>
                    </td>
                    <td data-label="Actions">
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          onClick={() => {
                            setSelectedUser(u);
                            userForm.setValue("full_name", u.full_name);
                            userForm.setValue("email", u.email);
                            userForm.setValue("role_id", u.role_id);
                            setModalState("edit_user");
                          }}
                          style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer" }}
                        >
                          <FiEdit />
                        </button>
                        <button
                          onClick={() => {
                            if (window.confirm(`Delete user ${u.email}?`)) {
                              deleteUserMutation.mutate(u.id);
                            }
                          }}
                          style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer" }}
                        >
                          <FiTrash2 />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}

                {filteredUsers.length === 0 && (
                  <tr>
                    <td colSpan="6" style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                      <FiUsers style={{ fontSize: "32px", color: "#38bdf8", marginBottom: "8px" }} />
                      <p style={{ margin: 0, fontWeight: "500" }}>No users found</p>
                      <small>No directory accounts configured in PostgreSQL database.</small>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: GROUP MANAGEMENT */}
      {activeTab === "groups" && (
        <div className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Organizational Teams</p>
              <h2>Group Management</h2>
            </div>
            <button
              onClick={() => {
                groupForm.reset();
                setModalState("create_group");
              }}
              className="btn btn--primary"
              style={{ height: "38px", padding: "0 16px", display: "flex", alignItems: "center", gap: "6px" }}
            >
              <FiPlus /> Create Group
            </button>
          </div>

          <div className="table-wrap">
            <table className="table table--dense">
              <thead>
                <tr>
                  <th>Group Name</th>
                  <th>Description</th>
                  <th>Assigned Members</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.id}>
                    <td data-label="Group Name"><strong style={{ color: "#38bdf8" }}>{g.name}</strong></td>
                    <td data-label="Description">{g.description || "n/a"}</td>
                    <td data-label="Assigned Members">
                      <span className="pill pill--info">{g.user_count} Users</span>
                    </td>
                    <td data-label="Actions">
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete group ${g.name}?`)) {
                            deleteGroupMutation.mutate(g.id);
                          }
                        }}
                        style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer" }}
                      >
                        <FiTrash2 />
                      </button>
                    </td>
                  </tr>
                ))}

                {groups.length === 0 && (
                  <tr>
                    <td colSpan="4" style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                      <FiUserCheck style={{ fontSize: "32px", color: "#38bdf8", marginBottom: "8px" }} />
                      <p style={{ margin: 0, fontWeight: "500" }}>No groups created</p>
                      <small>Create organizational groups to assign bulk security policies.</small>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: RBAC ROLES */}
      {activeTab === "rbac" && (
        <div className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Role Matrix</p>
              <h2>Role-Based Access Control (RBAC)</h2>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            {roles.map((r) => (
              <div key={r.id} style={{ background: "rgba(30, 41, 59, 0.6)", padding: "20px", borderRadius: "12px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                  <h3 style={{ color: "#38bdf8", margin: 0, fontSize: "1.1rem" }}>{r.name}</h3>
                  <span className="pill pill--info">System Role</span>
                </div>
                <p style={{ color: "#94a3b8", fontSize: "0.85rem", marginBottom: "14px" }}>{r.description}</p>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "0.82rem" }}>
                  {Object.entries(r.permissions || {}).map(([perm, val]) => (
                    <div key={perm} style={{ display: "flex", alignItems: "center", gap: "6px", color: val ? "#cbd5e1" : "#64748b" }}>
                      {val ? <FiCheck style={{ color: "#10b981" }} /> : <FiX style={{ color: "#ef4444" }} />}
                      <span>{perm.replace("_", " ")}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: SYSTEM POLICY ENGINE */}
      {activeTab === "policies" && (
        <div className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Granular Access Rules</p>
              <h2>System Policy Engine</h2>
            </div>
            <button
              onClick={() => {
                policyForm.reset();
                setModalState("create_policy");
              }}
              className="btn btn--primary"
              style={{ height: "38px", padding: "0 16px", display: "flex", alignItems: "center", gap: "6px" }}
            >
              <FiPlus /> Assign Findings Policy
            </button>
          </div>

          <div className="table-wrap">
            <table className="table table--dense">
              <thead>
                <tr>
                  <th>Policy Name</th>
                  <th>Assigned User / Group</th>
                  <th>Asset Types</th>
                  <th>Severities</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td data-label="Policy Name">
                      <strong style={{ color: "#f8fafc" }}>{p.name}</strong>
                      <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>{p.description || "n/a"}</p>
                    </td>
                    <td data-label="Assigned User / Group">
                      {p.user_name ? (
                        <span className="pill pill--info">User: {p.user_name}</span>
                      ) : p.group_name ? (
                        <span className="pill pill--medium">Group: {p.group_name}</span>
                      ) : (
                        <span style={{ color: "#64748b" }}>Global</span>
                      )}
                    </td>
                    <td data-label="Asset Types">
                      {(p.finding_scope?.asset_types || []).join(", ") || "All"}
                    </td>
                    <td data-label="Severities">
                      {(p.finding_scope?.severities || []).join(", ") || "All"}
                    </td>
                    <td data-label="Actions">
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete policy ${p.name}?`)) {
                            deletePolicyMutation.mutate(p.id);
                          }
                        }}
                        style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer" }}
                      >
                        <FiTrash2 />
                      </button>
                    </td>
                  </tr>
                ))}

                {policies.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: "center", padding: "40px", color: "#64748b" }}>
                      <FiSliders style={{ fontSize: "32px", color: "#38bdf8", marginBottom: "8px" }} />
                      <p style={{ margin: 0, fontWeight: "500" }}>No policies configured</p>
                      <small>Assign findings scope rules by asset type, severity, or CVE to specific users/groups.</small>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 5: SSO CONFIGURATION */}
      {activeTab === "sso" && (
        <div className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Single Sign-On Settings</p>
              <h2>SSO (SAML / OIDC) Configuration</h2>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            {ssoConfigs.map((cfg) => (
              <div key={cfg.provider} style={{ background: "rgba(30, 41, 59, 0.6)", padding: "20px", borderRadius: "12px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                  <h3 style={{ color: "#38bdf8", margin: 0, textTransform: "capitalize" }}>{cfg.provider} SSO</h3>
                  <button
                    onClick={() => {
                      saveSsoMutation.mutate({
                        provider: cfg.provider,
                        client_id: cfg.client_id,
                        client_secret: cfg.client_secret,
                        issuer_url: cfg.issuer_url,
                        is_enabled: !cfg.is_enabled,
                      });
                    }}
                    className={`pill pill--${cfg.is_enabled ? "critical" : "low"}`}
                    style={{ cursor: "pointer" }}
                  >
                    {cfg.is_enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div>
                    <label style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Client ID</label>
                    <input
                      className="scan-input"
                      defaultValue={cfg.client_id}
                      onBlur={(e) => saveSsoMutation.mutate({ provider: cfg.provider, client_id: e.target.value, is_enabled: cfg.is_enabled })}
                      placeholder="Enter Client ID"
                      style={{ width: "100%", fontSize: "0.82rem" }}
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Client Secret</label>
                    <input
                      type="password"
                      className="scan-input"
                      defaultValue={cfg.client_secret}
                      onBlur={(e) => saveSsoMutation.mutate({ provider: cfg.provider, client_secret: e.target.value, is_enabled: cfg.is_enabled })}
                      placeholder="Enter Client Secret"
                      style={{ width: "100%", fontSize: "0.82rem" }}
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: "0.75rem", color: "#94a3b8", display: "block" }}>Issuer URL</label>
                    <input
                      className="scan-input"
                      defaultValue={cfg.issuer_url}
                      onBlur={(e) => saveSsoMutation.mutate({ provider: cfg.provider, issuer_url: e.target.value, is_enabled: cfg.is_enabled })}
                      placeholder="https://identity-provider.com"
                      style={{ width: "100%", fontSize: "0.82rem" }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CREATE / EDIT MODALS */}
      <AnimatePresence>
        {modalState === "create_user" && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.7)", zIndex: 9999, display: "flex", justifyContent: "center", alignItems: "center" }} onClick={() => setModalState(null)}>
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }} onClick={(e) => e.stopPropagation()} style={{ width: "440px", background: "#0f172a", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "14px", padding: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
                <h3 style={{ color: "#f8fafc", margin: 0 }}>Create User Account</h3>
                <button onClick={() => setModalState(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><FiX /></button>
              </div>

              <form
                onSubmit={userForm.handleSubmit((data) =>
                  createUserMutation.mutate({
                    ...data,
                    role_id: data.role_id ? parseInt(data.role_id) : null,
                    group_ids: (data.group_ids || []).map((gid) => parseInt(gid)),
                  })
                )}
                style={{ display: "flex", flexDirection: "column", gap: "12px" }}
              >
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Email Address</label>
                  <input {...userForm.register("email", { required: true })} className="scan-input" placeholder="user@domain.com" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Full Name</label>
                  <input {...userForm.register("full_name", { required: true })} className="scan-input" placeholder="John Doe" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Account Password</label>
                  <input
                    type="password"
                    {...userForm.register("password")}
                    className="scan-input"
                    placeholder="Enter password (e.g. ChangeMe123!)"
                    style={{ width: "100%" }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Role</label>
                  <select {...userForm.register("role_id")} className="scan-select" style={{ width: "100%" }}>
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>{r.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>
                    Assign to Groups
                  </label>
                  {groups.length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", background: "rgba(30, 41, 59, 0.5)", padding: "10px", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)", maxHeight: "120px", overflowY: "auto" }}>
                      {groups.map((g) => (
                        <label key={g.id} style={{ fontSize: "0.82rem", color: "#cbd5e1", display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                          <input type="checkbox" value={g.id} {...userForm.register("group_ids")} />
                          {g.name}
                        </label>
                      ))}
                    </div>
                  ) : (
                    <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>No groups created yet. Create a group in the Groups tab first.</p>
                  )}
                </div>
                <label style={{ fontSize: "0.85rem", color: "#cbd5e1", display: "flex", alignItems: "center", gap: "8px" }}>
                  <input type="checkbox" {...userForm.register("mfa_enabled")} /> Enforce TOTP MFA
                </label>

                <button type="submit" disabled={createUserMutation.isPending} className="btn btn--primary" style={{ marginTop: "12px" }}>
                  {createUserMutation.isPending ? "Creating..." : "Save User"}
                </button>
              </form>
            </motion.div>
          </div>
        )}

        {modalState === "edit_user" && selectedUser && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.7)", zIndex: 9999, display: "flex", justifyContent: "center", alignItems: "center" }} onClick={() => setModalState(null)}>
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }} onClick={(e) => e.stopPropagation()} style={{ width: "440px", background: "#0f172a", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "14px", padding: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
                <h3 style={{ color: "#f8fafc", margin: 0 }}>Edit User Account</h3>
                <button onClick={() => setModalState(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><FiX /></button>
              </div>

              <form
                onSubmit={userForm.handleSubmit((data) =>
                  updateUserMutation.mutate({
                    id: selectedUser.id,
                    data: {
                      ...data,
                      role_id: data.role_id ? parseInt(data.role_id) : null,
                      group_ids: (data.group_ids || []).map((gid) => parseInt(gid)),
                    },
                  })
                )}
                style={{ display: "flex", flexDirection: "column", gap: "12px" }}
              >
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Email Address</label>
                  <input {...userForm.register("email", { required: true })} className="scan-input" placeholder="user@domain.com" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Full Name</label>
                  <input {...userForm.register("full_name", { required: true })} className="scan-input" placeholder="John Doe" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>New Password (Optional)</label>
                  <input
                    type="password"
                    {...userForm.register("password")}
                    className="scan-input"
                    placeholder="Leave blank to keep existing password"
                    style={{ width: "100%" }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Role</label>
                  <select {...userForm.register("role_id")} className="scan-select" style={{ width: "100%" }}>
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>{r.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8", display: "block", marginBottom: "4px" }}>
                    Assigned Groups
                  </label>
                  {groups.length > 0 ? (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", background: "rgba(30, 41, 59, 0.5)", padding: "10px", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)", maxHeight: "120px", overflowY: "auto" }}>
                      {groups.map((g) => (
                        <label key={g.id} style={{ fontSize: "0.82rem", color: "#cbd5e1", display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                          <input type="checkbox" value={g.id} {...userForm.register("group_ids")} />
                          {g.name}
                        </label>
                      ))}
                    </div>
                  ) : (
                    <p style={{ margin: 0, fontSize: "0.78rem", color: "#64748b" }}>No groups created yet. Create a group in the Groups tab first.</p>
                  )}
                </div>
                <label style={{ fontSize: "0.85rem", color: "#cbd5e1", display: "flex", alignItems: "center", gap: "8px" }}>
                  <input type="checkbox" {...userForm.register("mfa_enabled")} /> Enforce TOTP MFA
                </label>

                <button type="submit" disabled={updateUserMutation.isPending} className="btn btn--primary" style={{ marginTop: "12px" }}>
                  {updateUserMutation.isPending ? "Updating..." : "Update User"}
                </button>
              </form>
            </motion.div>
          </div>
        )}

        {modalState === "create_group" && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.7)", zIndex: 9999, display: "flex", justifyContent: "center", alignItems: "center" }} onClick={() => setModalState(null)}>
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }} onClick={(e) => e.stopPropagation()} style={{ width: "400px", background: "#0f172a", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "14px", padding: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
                <h3 style={{ color: "#f8fafc", margin: 0 }}>Create User Group</h3>
                <button onClick={() => setModalState(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><FiX /></button>
              </div>

              <form onSubmit={groupForm.handleSubmit((data) => createGroupMutation.mutate(data))} style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Group Name</label>
                  <input {...groupForm.register("name", { required: true })} className="scan-input" placeholder="e.g. SOC Team" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Description</label>
                  <input {...groupForm.register("description")} className="scan-input" placeholder="Security Operations Analysts" style={{ width: "100%" }} />
                </div>

                <button type="submit" disabled={createGroupMutation.isPending} className="btn btn--primary" style={{ marginTop: "12px" }}>
                  {createGroupMutation.isPending ? "Creating..." : "Save Group"}
                </button>
              </form>
            </motion.div>
          </div>
        )}

        {modalState === "create_policy" && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.7)", zIndex: 9999, display: "flex", justifyContent: "center", alignItems: "center" }} onClick={() => setModalState(null)}>
            <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }} exit={{ scale: 0.9 }} onClick={(e) => e.stopPropagation()} style={{ width: "450px", background: "#0f172a", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "14px", padding: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "16px" }}>
                <h3 style={{ color: "#f8fafc", margin: 0 }}>Assign Findings Policy</h3>
                <button onClick={() => setModalState(null)} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}><FiX /></button>
              </div>

              <form
                onSubmit={policyForm.handleSubmit((data) => {
                  createPolicyMutation.mutate({
                    name: data.name,
                    description: data.description,
                    user_id: data.user_id || null,
                    group_id: data.group_id ? parseInt(data.group_id) : null,
                    finding_scope: {
                      asset_types: data.asset_types ? data.asset_types.split(",").map((s) => s.trim()) : ["OS"],
                      severities: data.severities ? data.severities.split(",").map((s) => s.trim()) : ["CRITICAL", "HIGH"],
                    },
                  });
                })}
                style={{ display: "flex", flexDirection: "column", gap: "12px" }}
              >
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Policy Name</label>
                  <input {...policyForm.register("name", { required: true })} className="scan-input" placeholder="Critical Network Policy" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Assign to User (Optional)</label>
                  <select {...policyForm.register("user_id")} className="scan-select" style={{ width: "100%" }}>
                    <option value="">None</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>{u.full_name} ({u.email})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Assign to Group (Optional)</label>
                  <select {...policyForm.register("group_id")} className="scan-select" style={{ width: "100%" }}>
                    <option value="">None</option>
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>{g.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Asset Types (comma separated)</label>
                  <input {...policyForm.register("asset_types")} className="scan-input" placeholder="OS, Network, Website, Endpoint" style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Severities (comma separated)</label>
                  <input {...policyForm.register("severities")} className="scan-input" placeholder="CRITICAL, HIGH, MEDIUM" style={{ width: "100%" }} />
                </div>

                <button type="submit" disabled={createPolicyMutation.isPending} className="btn btn--primary" style={{ marginTop: "12px" }}>
                  {createPolicyMutation.isPending ? "Creating..." : "Save Policy"}
                </button>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}

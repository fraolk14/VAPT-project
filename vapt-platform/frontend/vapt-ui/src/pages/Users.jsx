import { Fragment, useCallback, useEffect, useMemo, useState } from "react";

import api from "../api/client";
import { useAnimatedNumber } from "../components/cc/ccHooks";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../ops.css";
import "../users.css";

const PERMS = [
  ["view_findings", "View findings"],
  ["edit_findings", "Triage findings"],
  ["run_scans", "Run scans"],
  ["view_reports", "Reports"],
  ["manage_users", "Manage users"],
];

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString([], { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "Never");
const errText = (err, fallback) => (err?.response?.data?.detail ? String(err.response.data.detail) : fallback);
const ACTION_LABEL = {
  "auth.login": "Signed in", "user.create": "User created", "user.update": "User changed", "user.delete": "User deleted",
  "user.activate": "User activated", "user.deactivate": "User deactivated", "user.mfa_reset": "MFA reset", "user.unlock": "Account unlocked",
  "user.sessions_revoked": "Sessions revoked", "auth.policy_update": "Sign-in policy changed", "auth.sso_toggle": "SSO provider changed",
};

function Kpi({ label, value, suffix = "", tone, hint }) {
  const shown = useAnimatedNumber(value ?? 0);
  return (
    <div className={`cc-kpi${tone ? ` cc-kpi--${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value == null ? "—" : `${shown}${suffix}`}</strong>
      {hint ? <small className="an-kpi-hint">{hint}</small> : null}
    </div>
  );
}

function UserDetail({ user, roles, groups, me, onAction }) {
  const [form, setForm] = useState({ full_name: user.full_name || "", email: user.email, role_id: user.role_id || "", group_ids: user.group_ids || [] });
  const [password, setPassword] = useState("");
  const [sessions, setSessions] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const isMe = user.id === me;

  useEffect(() => {
    api.get(`/iam/users/${user.id}/sessions`).then((r) => setSessions(r.data)).catch(() => setSessions([]));
  }, [user.id]);

  const save = (e) => {
    e.preventDefault();
    const body = {};
    if (form.full_name !== (user.full_name || "")) body.full_name = form.full_name;
    if (form.email !== user.email) body.email = form.email;
    if (String(form.role_id) !== String(user.role_id || "") && form.role_id) body.role_id = Number(form.role_id);
    if (JSON.stringify([...form.group_ids].sort()) !== JSON.stringify([...(user.group_ids || [])].sort())) body.group_ids = form.group_ids;
    if (password) body.password = password;
    if (!Object.keys(body).length) return onAction(null, "Nothing changed.");
    onAction(() => api.put(`/iam/users/${user.id}`, body), password ? "Saved. The new password is active and their other sessions were signed out." : "Saved.").then(() => setPassword(""));
  };

  return (
    <div className="mc-detail us-detail">
      <section>
        <h3>Profile & role</h3>
        <form className="us-form" onSubmit={save}>
          <label><span>Name</span><input className="so-input" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
          <label><span>Email</span><input className="so-input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label><span>Role</span>
            <select className="so-input" value={form.role_id} onChange={(e) => setForm({ ...form, role_id: e.target.value })}>
              {!user.role_id ? <option value="">{user.role_name}</option> : null}
              {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          </label>
          <label><span>New password</span><input className="so-input" type="password" autoComplete="new-password" minLength={12} placeholder="leave blank to keep" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          {groups.length ? (
            <fieldset className="us-groups">
              <legend>Groups</legend>
              {groups.map((g) => (
                <label key={g.id} className="cc-check">
                  <input type="checkbox" checked={form.group_ids.includes(g.id)} onChange={(e) => setForm({ ...form, group_ids: e.target.checked ? [...form.group_ids, g.id] : form.group_ids.filter((x) => x !== g.id) })} />
                  {g.name}
                </label>
              ))}
            </fieldset>
          ) : null}
          <button type="submit" className="cc-btn cc-btn--primary">Save changes</button>
        </form>
      </section>
      <section>
        <h3>Access</h3>
        <div className="us-actions">
          {user.locked || user.failed_login_attempts ? <button type="button" className="cc-btn" onClick={() => onAction(() => api.post(`/iam/users/${user.id}/unlock`), `${user.username} unlocked.`)}>Unlock{user.failed_login_attempts ? ` (${user.failed_login_attempts} failed)` : ""}</button> : null}
          {user.mfa_enabled ? <button type="button" className="cc-btn" onClick={() => onAction(() => api.post(`/iam/users/${user.id}/toggle-mfa`), `MFA reset for ${user.username}. They'll set it up again.`)}>Reset MFA</button> : null}
          <button type="button" className="cc-btn" disabled={!user.active_sessions} onClick={() => onAction(() => api.post(`/iam/users/${user.id}/revoke-sessions`), (r) => r.data.message)}>Sign out everywhere</button>
          {!isMe ? <button type="button" className={`cc-btn ${user.is_active ? "sh-btn-bad" : "sh-btn-ok"}`} onClick={() => onAction(() => api.post(`/iam/users/${user.id}/toggle-active`), (r) => r.data.message)}>{user.is_active ? "Deactivate" : "Activate"}</button> : null}
        </div>
        {!isMe ? (
          confirmDelete ? (
            <div className="us-confirm" role="alert">
              <p>Delete <strong>{user.username}</strong> permanently? Their sessions end now and this can't be undone. Deactivating keeps the account and its history.</p>
              <div className="op-row">
                <button type="button" className="cc-btn sh-btn-bad" onClick={() => onAction(() => api.delete(`/iam/users/${user.id}`), `${user.username} deleted.`)}>Delete permanently</button>
                <button type="button" className="cc-btn" onClick={() => setConfirmDelete(false)}>Cancel</button>
              </div>
            </div>
          ) : <button type="button" className="cc-btn us-delete" onClick={() => setConfirmDelete(true)}>Delete user…</button>
        ) : <p className="so-sub">This is your account. Another administrator has to deactivate, delete or demote it.</p>}
        <h3 className="us-subhead">Sessions</h3>
        {sessions === null ? <p className="cc-muted">Loading…</p> : sessions.length ? (
          <ul className="cc-list us-sessions">
            {sessions.slice(0, 6).map((s) => (
              <li key={s.id}>
                <span className={`cc-dot cc-dot--${s.is_active ? "healthy" : "down"}`} aria-hidden="true" />
                <span className="an-overdue__main">
                  <span className="cc-mono">{s.ip_address || "unknown IP"}</span>
                  <span className="so-sub" title={s.user_agent || ""}>{(s.user_agent || "").slice(0, 60) || "unknown device"}</span>
                  <span className="so-sub">{s.is_active ? "Active" : "Ended"} · last seen {fmtTime(s.last_seen_at)}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : <p className="cc-muted">No sessions.</p>}
      </section>
    </div>
  );
}

export default function Users({ currentUser }) {
  const [users, setUsers] = useState(null);
  const [roles, setRoles] = useState([]);
  const [groups, setGroups] = useState([]);
  const [signIn, setSignIn] = useState(null);
  const [audit, setAudit] = useState([]);
  const [forbidden, setForbidden] = useState(false);
  const [notice, setNotice] = useState(null);
  const [open, setOpen] = useState(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [tempPassword, setTempPassword] = useState(null);
  const [createForm, setCreateForm] = useState({ email: "", full_name: "", username: "", role_id: "", group_ids: [] });
  const [groupForm, setGroupForm] = useState({ name: "", description: "" });

  const load = useCallback(async () => {
    try {
      const [u, r, g, s, a] = await Promise.all([
        api.get("/iam/users"), api.get("/iam/roles"), api.get("/iam/groups"), api.get("/iam/sign-in"), api.get("/iam/audit"),
      ]);
      setUsers(u.data); setRoles(r.data); setGroups(g.data); setSignIn(s.data); setAudit(a.data);
    } catch (err) {
      if (err?.response?.status === 403) setForbidden(true);
      else setNotice({ ok: false, text: "Couldn't load users. Check that the API is running." });
    }
  }, []);

  useEffect(() => {
    const id = window.setTimeout(load, 0);
    return () => window.clearTimeout(id);
  }, [load]);

  const onAction = async (fn, okText) => {
    if (!fn) {
      setNotice({ ok: true, text: okText });
      return null;
    }
    try {
      const res = await fn();
      setNotice({ ok: true, text: typeof okText === "function" ? okText(res) : okText });
      await load();
      return res;
    } catch (err) {
      setNotice({ ok: false, text: errText(err, "That didn't work.") });
      return null;
    }
  };

  const createUser = async (e) => {
    e.preventDefault();
    const res = await onAction(() => api.post("/iam/users", {
      email: createForm.email, full_name: createForm.full_name, username: createForm.username || undefined,
      role_id: createForm.role_id ? Number(createForm.role_id) : undefined, group_ids: createForm.group_ids,
    }), "User created.");
    if (res) {
      setTempPassword(res.data.temporary_password ? { user: createForm.email, password: res.data.temporary_password } : null);
      setCreateForm({ email: "", full_name: "", username: "", role_id: "", group_ids: [] });
    }
  };

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (users || []).filter((u) => {
      if (filter === "admins" && u.role !== "admin") return false;
      if (filter === "nomfa" && (u.mfa_enabled || !u.is_active)) return false;
      if (filter === "locked" && !u.locked) return false;
      if (filter === "inactive" && u.is_active) return false;
      return !q || `${u.username} ${u.email} ${u.full_name} ${u.role_name}`.toLowerCase().includes(q);
    });
  }, [users, query, filter]);

  if (forbidden) {
    return (
      <div className="cc us-page">
        <header className="cc-top"><div className="cc-top__title"><span className="cc-live-dot" aria-hidden="true" /><h1>Users & Access</h1></div></header>
        <p className="cc-empty">Only administrators can manage users.</p>
      </div>
    );
  }

  const active = (users || []).filter((u) => u.is_active);
  const mfaPct = active.length ? Math.round((active.filter((u) => u.mfa_enabled).length / active.length) * 100) : null;
  const me = currentUser?.id;

  return (
    <div className="cc us-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Users & Access</h1>
        </div>
        <div className="cc-top__tools">
          <button type="button" className="cc-btn" onClick={load}>Refresh</button>
        </div>
      </header>

      {notice ? <p className={notice.ok ? "mc-ok op-notice" : "so-error op-notice"} role={notice.ok ? "status" : "alert"}>{notice.text}</p> : null}
      {tempPassword ? (
        <div className="op-secret op-notice" role="status">
          <p><strong>Temporary password for {tempPassword.user}.</strong> Share it over a secure channel. It won't be shown again.</p>
          <code>{tempPassword.password}</code>
          <div className="op-row">
            <button type="button" className="cc-btn" onClick={() => navigator.clipboard?.writeText(tempPassword.password).catch(() => {})}>Copy</button>
            <button type="button" className="cc-btn" onClick={() => setTempPassword(null)}>Done</button>
          </div>
        </div>
      ) : null}

      <div className="cc-kpis">
        <Kpi label="Active users" value={active.length} hint={users ? `${users.length} accounts in total` : undefined} />
        <Kpi label="Administrators" value={(users || []).filter((u) => u.is_active && u.role === "admin").length} />
        <Kpi label="MFA coverage" value={mfaPct} suffix="%" tone={mfaPct != null && mfaPct < 100 ? "hot" : "live"} hint="of active users" />
        <Kpi label="Locked accounts" value={(users || []).filter((u) => u.locked).length} tone={(users || []).some((u) => u.locked) ? "hot" : ""} />
        <Kpi label="Signed-in sessions" value={(users || []).reduce((n, u) => n + (u.active_sessions || 0), 0)} tone="live" />
      </div>

      <section className="cc-panel sh-section" aria-label="Users">
        <header className="cc-panel__head"><h2>Users</h2></header>
        <div className="mc-filters">
          <div className="cc-range" role="group" aria-label="Filter users">
            {[["all", "All"], ["admins", "Admins"], ["nomfa", "No MFA"], ["locked", "Locked"], ["inactive", "Inactive"]].map(([k, l]) => (
              <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>
            ))}
          </div>
          <input className="so-input mc-search" type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, email or role" aria-label="Search users" />
        </div>
        <div className="so-table-wrap">
          <table className="so-table mc-table">
            <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">MFA</th><th scope="col">Last sign-in</th></tr></thead>
            <tbody>
              {list.map((u) => {
                const expanded = open === u.id;
                return (
                  <Fragment key={u.id}>
                    <tr className={expanded ? "is-open" : ""}>
                      <td>
                        <button type="button" className="mc-issue" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : u.id)}>
                          <span aria-hidden="true" className="mc-caret">{expanded ? "▾" : "▸"}</span>
                          <span>
                            {u.full_name || u.username}{u.id === me ? <span className="so-sub"> · you</span> : null}
                            <span className="so-sub cc-mono" style={{ display: "block" }}>{u.username} · {u.email}</span>
                          </span>
                        </button>
                      </td>
                      <td><span className={`us-role us-role--${u.role}`}>{u.role_name}</span></td>
                      <td>
                        {!u.is_active ? <span className="op-status op-status--bad">Inactive</span>
                          : u.locked ? <span className="op-status op-status--warn">Locked</span>
                            : <span className="op-status op-status--ok">Active</span>}
                        {u.active_sessions ? <span className="so-sub" style={{ display: "block" }}>{u.active_sessions} session{u.active_sessions === 1 ? "" : "s"}</span> : null}
                      </td>
                      <td>{u.mfa_enabled ? <span className="op-status op-status--ok">{u.mfa_method || "On"}</span> : <span className="op-status op-status--warn">Off</span>}</td>
                      <td className="cc-mono cc-muted">{fmtTime(u.last_login)}{u.last_login_ip ? <span className="so-sub" style={{ display: "block" }}>{u.last_login_ip}</span> : null}</td>
                    </tr>
                    {expanded ? (
                      <tr className="mc-detail-row"><td colSpan={5}><UserDetail user={u} roles={roles} groups={groups} me={me} onAction={onAction} /></td></tr>
                    ) : null}
                  </Fragment>
                );
              })}
              {!list.length ? <tr><td colSpan={5} className="cc-empty so-empty">{users ? "No users match." : "Loading…"}</td></tr> : null}
            </tbody>
          </table>
        </div>
        <details className="op-form">
          <summary>Add a user</summary>
          <form onSubmit={createUser}>
            <label><span>Email</span><input className="so-input" type="email" required value={createForm.email} onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })} /></label>
            <label><span>Full name</span><input className="so-input" required value={createForm.full_name} onChange={(e) => setCreateForm({ ...createForm, full_name: e.target.value })} /></label>
            <label><span>Username</span><input className="so-input" placeholder="defaults to the email name" value={createForm.username} onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })} /></label>
            <label><span>Role</span>
              <select className="so-input" required value={createForm.role_id} onChange={(e) => setCreateForm({ ...createForm, role_id: e.target.value })}>
                <option value="">Choose a role</option>
                {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <button type="submit" className="cc-btn cc-btn--primary">Create user</button>
          </form>
          <p className="an-note">A temporary password is generated and shown once. Users turn MFA on themselves from their profile.</p>
        </details>
      </section>

      <div className="an-grid op-grid">
        <section className="cc-panel an-w" aria-label="Roles">
          <header className="cc-panel__head"><h2>Roles</h2></header>
          <div className="so-table-wrap">
            <table className="so-table an-table us-perms">
              <thead><tr><th scope="col">Role</th>{PERMS.map(([, l]) => <th key={l} scope="col">{l}</th>)}</tr></thead>
              <tbody>
                {roles.map((r) => (
                  <tr key={r.id}>
                    <th scope="row" title={r.description}>{r.name}<span className="so-sub" style={{ display: "block" }}>{(users || []).filter((u) => u.role_id === r.id || (!u.role_id && u.role === r.platform_role)).length} users</span></th>
                    {PERMS.map(([k]) => <td key={k} className={r.permissions?.[k] ? "us-yes" : "us-no"} aria-label={r.permissions?.[k] ? "yes" : "no"}>{r.permissions?.[k] ? "✓" : "—"}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="cc-panel an-w" aria-label="Sign-in settings">
          <header className="cc-panel__head"><h2>Sign-in</h2></header>
          {signIn ? (
            <>
              <div className="us-toggles">
                <label className="cc-check">
                  <input type="checkbox" checked={signIn.allow_local_login} onChange={(e) => onAction(() => api.post("/iam/sign-in", { allow_local_login: e.target.checked }), "Sign-in policy saved.")} />
                  Allow password sign-in
                </label>
                <label className="cc-check">
                  <input type="checkbox" checked={signIn.captcha_enabled} onChange={(e) => onAction(() => api.post("/iam/sign-in", { captcha_enabled: e.target.checked }), "Sign-in policy saved.")} />
                  Require a shared access code at sign-in
                </label>
                {signIn.captcha_enabled && !signIn.access_code_enforced ? (
                  <p className="an-bad so-sub">Switched on, but not enforced: the server has no private access code. Set CAPTCHA_BYPASS_TOKEN in the API's environment and restart it.</p>
                ) : !signIn.access_code_configured ? (
                  <p className="so-sub">Needs CAPTCHA_BYPASS_TOKEN set to a private code on the API first. This is one shared code for everyone, not a puzzle CAPTCHA.</p>
                ) : null}
              </div>
              <h3 className="an-subhead">SSO providers</h3>
              <ul className="cc-list">
                {signIn.providers.map((p) => (
                  <li key={p.id} className="an-overdue">
                    <span className={`cc-dot cc-dot--${p.enabled ? "healthy" : "down"}`} aria-hidden="true" />
                    <span className="an-overdue__main">
                      <span>{p.name} <span className="so-sub">· {p.type}</span></span>
                      <span className="so-sub cc-mono op-break">{p.login_url}</span>
                      {p.placeholder ? <span className="an-bad so-sub">Placeholder address — this button can't work on the sign-in page.</span> : null}
                      {!p.client_id_set ? <span className="so-sub">No client ID configured.</span> : null}
                    </span>
                    <button type="button" className="cc-btn" onClick={() => onAction(() => api.post(`/iam/sso-providers/${p.id}/toggle`), `${p.name} ${p.enabled ? "hidden from" : "shown on"} the sign-in page.`)}>{p.enabled ? "Disable" : "Enable"}</button>
                  </li>
                ))}
                {!signIn.providers.length ? <li className="cc-empty">No SSO providers.</li> : null}
              </ul>
              <p className="an-note">MFA isn't enforced for everyone yet, so the "No MFA" filter above lists who still needs to set it up.</p>
            </>
          ) : <p className="cc-empty">Loading…</p>}
        </section>

        <section className="cc-panel an-w" aria-label="Groups">
          <header className="cc-panel__head"><h2>Teams & groups</h2></header>
          <ul className="cc-list">
            {groups.map((g) => (
              <li key={g.id} className="an-overdue">
                <span className="an-overdue__main">
                  <span>{g.name}</span>
                  <span className="so-sub">{g.user_count} member{g.user_count === 1 ? "" : "s"}{g.description ? ` · ${g.description}` : ""}</span>
                </span>
                <button type="button" className="cc-btn" onClick={() => onAction(() => api.delete(`/iam/groups/${g.id}`), `${g.name} deleted.`)}>Delete</button>
              </li>
            ))}
            {!groups.length ? <li className="cc-empty">No groups. Groups are used to assign findings to teams.</li> : null}
          </ul>
          <details className="op-form">
            <summary>Add a group</summary>
            <form onSubmit={(e) => { e.preventDefault(); onAction(() => api.post("/iam/groups", groupForm), "Group created.").then((r) => r && setGroupForm({ name: "", description: "" })); }}>
              <label><span>Name</span><input className="so-input" required value={groupForm.name} onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} /></label>
              <label><span>Description</span><input className="so-input" value={groupForm.description} onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} /></label>
              <button type="submit" className="cc-btn cc-btn--primary">Add group</button>
            </form>
          </details>
        </section>

        <section className="cc-panel an-w" aria-label="Access log">
          <header className="cc-panel__head"><h2>Access log</h2></header>
          <ul className="cc-list op-scroll">
            {audit.map((a) => (
              <li key={a.id}>
                <span className="an-overdue__main">
                  <span>{ACTION_LABEL[a.action] || a.action}{a.details?.username ? <> · <span className="cc-mono">{a.details.username}</span></> : null}</span>
                  <span className="so-sub">by {a.actor} · {fmtTime(a.created_at)}{a.outcome && a.outcome !== "success" ? ` · ${a.outcome}` : ""}</span>
                </span>
              </li>
            ))}
            {!audit.length ? <li className="cc-empty">No access events yet.</li> : null}
          </ul>
        </section>
      </div>
    </div>
  );
}

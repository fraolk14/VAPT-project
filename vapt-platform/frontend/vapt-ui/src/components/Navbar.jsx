import { NavLink } from "react-router-dom";

function navItemsForRole(role) {
  const items = [
    { to: "/", label: "Dashboard", end: true },
    { to: "/assets", label: "Assets" },
    { to: "/scans", label: "Scans" },
    { to: "/hosts", label: "Hosts" },
    { to: "/findings", label: "Findings" },
    { to: "/ai-remediation", label: "AI Remediation" },
    { to: "/attack-map", label: "Attack Map" },
    { to: "/threat-intelligence", label: "Threat Intelligence" },
    { to: "/shadow-it", label: "Shadow IT" },
    { to: "/misconfigurations", label: "Misconfigurations" },
    { to: "/unauthorized-software", label: "Unauthorized Software" },
    { to: "/reports", label: "Reports" },
  ];

  if (role === "admin") {
    items.push({ to: "/admin", label: "Users" });
  }

  return items;
}

export default function Navbar({ user, onLogout, collapsed, onToggleCollapse }) {
  const navItems = navItemsForRole(user?.role);

  return (
    <aside className={collapsed ? "sidebar is-collapsed" : "sidebar"}>
      <div className="sidebar__head">
        <div className="sidebar__brand">
          {!collapsed ? (
            <>
              <p className="topbar__kicker">VAPTICOM Security Platform</p>
              <strong>VAPTICOM</strong>
              <span className="sidebar__tag">Vulnerability Assessment & Penetration Testing</span>
            </>
          ) : (
            <strong className="sidebar__brand-mark">V</strong>
          )}
        </div>
        <button
          type="button"
          className="sidebar__toggle"
          onClick={onToggleCollapse}
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          {collapsed ? "›" : "‹"}
        </button>
      </div>
      <nav className="sidebar__nav">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => (isActive ? "sidebar__link is-active" : "sidebar__link")}
            title={collapsed ? item.label : undefined}
          >
            <span className="sidebar__link-text">{collapsed ? item.label.slice(0, 1) : item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__user">
        {!collapsed ? (
          <div className="sidebar__user-copy">
            <p className="topbar__user-label">Signed in as</p>
            <strong>{user?.username || "Operator"}</strong>
            <p className="topbar__user-label">Tenant {user?.tenant_id || "default"}</p>
            <p className="topbar__user-label">MFA {user?.mfa_enabled ? "enabled" : "disabled"}</p>
          </div>
        ) : null}
        <button type="button" className="topbar__logout" onClick={onLogout}>
          {collapsed ? "↩" : "Logout"}
        </button>
      </div>
    </aside>
  );
}

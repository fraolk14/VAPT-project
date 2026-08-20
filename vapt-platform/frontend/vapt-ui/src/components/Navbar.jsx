import { NavLink } from "react-router-dom";
import { TbTarget } from "react-icons/tb";
import {
  HiOutlineSquares2X2,
  HiOutlineComputerDesktop,
  HiOutlineServerStack,
  HiOutlineShieldExclamation,
  HiOutlineCpuChip,
  HiOutlineGlobeAlt,
  HiOutlineBolt,
  HiOutlineEyeSlash,
  HiOutlineWrenchScrewdriver,
  HiOutlineNoSymbol,
  HiOutlineSignal,
  HiOutlineDocumentText,
  HiOutlineUserGroup,
} from "react-icons/hi2";

function navItemsForRole(role) {
  const items = [
    { to: "/", label: "Dashboard", icon: <HiOutlineSquares2X2 />, end: true },
    { to: "/assets", label: "Assets", icon: <HiOutlineComputerDesktop /> },
    { to: "/scans", label: "Scans", icon: <TbTarget /> },
    { to: "/hosts", label: "Hosts", icon: <HiOutlineServerStack /> },
    { to: "/findings", label: "Findings", icon: <HiOutlineShieldExclamation /> },
    { to: "/ai-remediation", label: "AI Remediation", icon: <HiOutlineCpuChip /> },
    { to: "/attack-map", label: "Attack Map", icon: <HiOutlineGlobeAlt /> },
    { to: "/threat-intelligence", label: "Threat Intelligence", icon: <HiOutlineBolt /> },
    { to: "/shadow-it", label: "Shadow IT", icon: <HiOutlineEyeSlash /> },
    { to: "/misconfigurations", label: "Misconfigurations", icon: <HiOutlineWrenchScrewdriver /> },
    { to: "/unauthorized-software", label: "Unauthorized Software", icon: <HiOutlineNoSymbol /> },
    { to: "/agent-management", label: "Endpoint Agents", icon: <HiOutlineSignal /> },
    { to: "/reports", label: "Reports", icon: <HiOutlineDocumentText /> },
  ];

  if (role === "admin") {
    items.push({ to: "/admin", label: "Users & IAM", icon: <HiOutlineUserGroup /> });
  }

  return items;
}

export default function Navbar({ user, onLogout, collapsed, onToggleCollapse }) {
  const navItems = navItemsForRole(user?.role);

  return (
    <>
      {/* Floating Toggle Button - Visible when Sidebar is Collapsed */}
      {collapsed && (
        <button
          type="button"
          className="sidebar-floating-toggle"
          onClick={onToggleCollapse}
          aria-label="Expand navigation menu"
          title="Expand navigation menu"
        >
          <span className="sidebar-floating-toggle__icon">☰</span>
          <span className="sidebar-floating-toggle__label">Menu</span>
        </button>
      )}

      {/* Main Sidebar Panel */}
      <aside className={`sidebar ${collapsed ? "is-hidden" : "is-expanded"}`}>
        <div className="sidebar__head">
          <div className="sidebar__brand">
            <p className="topbar__kicker">VAP Platform</p>
            <strong className="sidebar__brand-title">VAP</strong>
            <span className="sidebar__tag">Security Assessment & VAPT</span>
          </div>
          <button
            type="button"
            className="sidebar__toggle"
            onClick={onToggleCollapse}
            aria-label="Hide navigation sidebar"
            title="Hide navigation sidebar"
          >
            ✕
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="sidebar__nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? "sidebar__link is-active" : "sidebar__link")}
            >
              <span className="sidebar__link-icon">{item.icon}</span>
              <span className="sidebar__link-text">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* User Session Footer */}
        <div className="sidebar__user">
          <div className="sidebar__user-copy">
            <p className="topbar__user-label">Signed in as</p>
            <strong className="sidebar__username">{user?.username || "Operator"}</strong>
            <div className="sidebar__user-pills">
              <span className="sidebar__user-pill">{user?.role || "user"}</span>
              <span className="sidebar__user-pill">{user?.mfa_enabled ? "MFA On" : "MFA Off"}</span>
            </div>
          </div>
          <button type="button" className="topbar__logout" onClick={onLogout}>
            Logout
          </button>
        </div>
      </aside>
    </>
  );
}

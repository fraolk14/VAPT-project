import { NavLink } from "react-router-dom";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/scans", label: "Scans" },
  { to: "/findings", label: "Findings" },
  { to: "/assets", label: "Assets" },
  { to: "/integrations", label: "Integrations" },
];

export default function Navbar() {
  return (
    <header className="topbar">
      <div>
        <p className="topbar__kicker">Production-ready VAPT platform</p>
        <strong>Blackridge Security Mesh</strong>
      </div>
      <nav className="topbar__nav">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => (isActive ? "topbar__link is-active" : "topbar__link")}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}

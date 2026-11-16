import { useEffect, useRef, useState } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";

const PRIMARY = [
  { to: "/", label: "Overview", end: true },
  { to: "/findings", label: "Findings" },
  { to: "/scans", label: "Scans" },
  { to: "/assets", label: "Targets" },
  { to: "/agent-management", label: "Agents" },
  { to: "/reports", label: "Reports" },
];

function secondaryItems(role) {
  const items = [
    { to: "/insights", label: "Analytics" },
    { to: "/hosts", label: "Hosts" },
    { to: "/ai-remediation", label: "AI remediation" },
    { to: "/attack-map", label: "Attack map" },
    { to: "/threat-intelligence", label: "Threat intelligence" },
    { to: "/shadow-it", label: "Shadow IT" },
    { to: "/misconfigurations", label: "Misconfigurations" },
    { to: "/unauthorized-software", label: "Unauthorized software" },
    { to: "/integrations", label: "Integrations" },
  ];
  if (role === "admin") {
    items.push({ to: "/admin", label: "Users & access" });
  }
  return items;
}

function engineSummary(integrations) {
  const entries = Object.values(integrations || {});
  if (!entries.length) return { label: "Checking engines", tone: "" };
  const up = entries.filter((entry) => entry && entry.healthy).length;
  return { label: `${up}/${entries.length} engines up`, tone: up === entries.length ? "nw-dot--ok" : "nw-dot--warn" };
}

const linkClass = ({ isActive }) => (isActive ? "nw-nav__link active" : "nw-nav__link");

export default function Navbar({ user, onLogout, integrations }) {
  const location = useLocation();
  const moreRef = useRef(null);
  const [moreOpen, setMoreOpen] = useState(false);
  const secondary = secondaryItems(user?.role);
  const moreActive = secondary.some((item) => location.pathname.startsWith(item.to));
  const engines = engineSummary(integrations);

  // Close the "More" menu after picking an item or when clicking elsewhere.
  useEffect(() => {
    if (!moreOpen) return undefined;
    const onPointer = (event) => {
      if (moreRef.current && !moreRef.current.contains(event.target)) setMoreOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [moreOpen]);

  return (
    <header className="nw-header">
      <a className="nw-skip" href="#main-content">Skip to content</a>
      <div className="nw-header__inner">
        <Link to="/" className="nw-brand" aria-label="Vapticom overview">
          <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
            <circle cx="11" cy="11" r="9" stroke="var(--nw-accent)" strokeWidth="2" fill="none" />
            <circle cx="11" cy="11" r="3" fill="var(--nw-accent)" />
          </svg>
          VAPTICOM
        </Link>

        <nav className="nw-nav" aria-label="Primary">
          {PRIMARY.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
              {item.label}
            </NavLink>
          ))}
          <details
            ref={moreRef}
            className={moreActive ? "nw-more is-active" : "nw-more"}
            open={moreOpen}
            onToggle={(event) => setMoreOpen(event.currentTarget.open)}
          >
            <summary>
              More
              <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                <path d="M3 4.5l3 3 3-3" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
              </svg>
            </summary>
            <div className="nw-more__menu">
              {secondary.map((item) => (
                <NavLink key={item.to} to={item.to} className={linkClass} onClick={() => setMoreOpen(false)}>
                  {item.label}
                </NavLink>
              ))}
            </div>
          </details>
        </nav>

        <div className="nw-header__tools">
          <span className="nw-engines" title="Scanner engine health">
            <span className={`nw-dot ${engines.tone}`} />
            {engines.label}
          </span>
          <Link to="/scans" className="nw-btn nw-btn--accent">+ Launch scan</Link>
          <span className="nw-user">
            {user?.username || "Operator"}
            <button type="button" className="nw-btn nw-btn--ghost" onClick={onLogout}>
              Sign out
            </button>
          </span>
        </div>
      </div>
    </header>
  );
}

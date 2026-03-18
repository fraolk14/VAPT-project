export default function Navbar() {
  return (
    <header className="topbar">
      <div>
        <p className="topbar__kicker">Production-ready VAPT platform</p>
        <strong>Blackridge Security Mesh</strong>
      </div>
      <nav className="topbar__nav">
        <a href="#dashboard">Dashboard</a>
        <a href="#scans">Scans</a>
        <a href="#findings">Findings</a>
        <a href="#assets">Assets</a>
      </nav>
    </header>
  );
}

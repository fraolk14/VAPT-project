import { useEffect, useMemo, useState } from "react";

import api from "../api/client";

export default function UnauthorizedSoftware({ summary, assets = [] }) {
  const [softwareList, setSoftwareList] = useState([]);
  const [whitelist, setWhitelist] = useState([]);
  const [riskFilter, setRiskFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  
  // Whitelist form state
  const [whitelistForm, setWhitelistForm] = useState({ name: "", vendor: "", reason: "Approved by Security Team" });
  
  // Discovery trigger state
  const [discoverTarget, setDiscoverTarget] = useState("");
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [feedback, setFeedback] = useState("");

  const fetchSoftwareData = () => {
    api.get("/software")
      .then((res) => setSoftwareList(res.data))
      .catch(() => setSoftwareList([]));

    api.get("/software/whitelist")
      .then((res) => setWhitelist(res.data))
      .catch(() => setWhitelist([]));
  };

  useEffect(() => {
    fetchSoftwareData();
  }, []);

  const rows = useMemo(() => {
    return softwareList
      .filter((item) => riskFilter === "all" || item.status.toLowerCase() === riskFilter.toLowerCase())
      .filter((item) => statusFilter === "all" || item.status === statusFilter)
      .filter((item) => {
        const itemIp = item.ip_address || item.metadata?.ip_address || "";
        return !ipFilter.trim() || itemIp.includes(ipFilter.trim());
      })
      .filter((item) => `${item.name} ${item.vendor || ""} ${item.category || ""} ${item.version || ""}`.toLowerCase().includes(query.trim().toLowerCase()))
      .sort((a, b) => b.risk_score - a.risk_score);
  }, [softwareList, riskFilter, statusFilter, ipFilter, query]);

  const selected = useMemo(() => softwareList.find((item) => item.id === selectedId) || rows[0] || null, [softwareList, selectedId, rows]);

  const handleAddWhitelist = async (event) => {
    event.preventDefault();
    if (!whitelistForm.name.trim()) return;
    try {
      await api.post("/software/whitelist", {
        name: whitelistForm.name.trim(),
        vendor: whitelistForm.vendor.trim() || null,
        reason: whitelistForm.reason.trim() || "Approved by Security Team",
      });
      setWhitelistForm({ name: "", vendor: "", reason: "Approved by Security Team" });
      setFeedback(`Added '${whitelistForm.name}' to approved whitelist.`);
      fetchSoftwareData();
    } catch (error) {
      setFeedback(error?.response?.data?.detail || "Failed to whitelist software.");
    }
  };

  const handleRemoveWhitelist = async (id, name) => {
    try {
      await api.delete(`/software/whitelist/${id}`);
      setFeedback(`Removed '${name}' from whitelist.`);
      fetchSoftwareData();
    } catch (error) {
      setFeedback("Failed to remove whitelist entry.");
    }
  };

  const handleRunDiscovery = async (event) => {
    event.preventDefault();
    if (!discoverTarget.trim()) return;
    setIsDiscovering(true);
    setFeedback(`Running WMI / Nmap -sV discovery on ${discoverTarget}...`);
    try {
      const res = await api.post("/software/discover", { target: discoverTarget.trim() });
      setFeedback(`Discovery complete for ${discoverTarget}. Found ${res.data.length} software entries.`);
      setIsDiscovering(false);
      setIpFilter(discoverTarget.trim());
      setDiscoverTarget("");
      fetchSoftwareData();
    } catch (error) {
      setIsDiscovering(false);
      setFeedback(error?.response?.data?.detail || "Discovery failed for target host.");
    }
  };

  const [subnetInput, setSubnetInput] = useState("192.168.10.0/24");
  const [isBulkWhitelisting, setIsBulkWhitelisting] = useState(false);

  const handleBulkWhitelist = async () => {
    if (!window.confirm("Are you sure you want to approve and whitelist ALL discovered software across all endpoints?")) return;
    setIsBulkWhitelisting(true);
    setFeedback("Processing bulk baseline whitelisting across all managed endpoints...");
    try {
      const res = await api.post("/software/bulk-whitelist");
      setFeedback(`✅ ${res.data.message}`);
      fetchSoftwareData();
    } catch (err) {
      setFeedback("Failed to bulk whitelist software.");
    } finally {
      setIsBulkWhitelisting(false);
    }
  };

  const handleRunSubnetDiscovery = async (e) => {
    e.preventDefault();
    setIsDiscovering(true);
    setFeedback(`Running endpoint software discovery across subnet ${subnetInput}...`);
    try {
      const res = await api.post("/software/discover-subnet", { subnet: subnetInput });
      setFeedback(`✅ ${res.data.message}`);
      fetchSoftwareData();
    } catch (err) {
      setFeedback("Failed to run subnet software discovery.");
    } finally {
      setIsDiscovering(false);
    }
  };

  const approvedCount = softwareList.filter((s) => s.status === "APPROVED").length;
  const vulnerableCount = softwareList.filter((s) => s.status === "VULNERABLE").length;
  const unauthorizedCount = softwareList.filter((s) => s.status === "UNAUTHORIZED").length;

  return (
    <section className="section-grid">
      <div className="panel panel--metrics">
        <div className="panel__header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <p className="eyebrow">Unauthorized software governance</p>
            <h2>Application and endpoint review</h2>
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={handleBulkWhitelist}
              disabled={isBulkWhitelisting}
              className="scan-action scan-action--resume"
              style={{ background: "linear-gradient(135deg, #10b981 0%, #059669 100%)", color: "#fff", fontWeight: "bold" }}
            >
              {isBulkWhitelisting ? "Whitelisting All..." : "🛡️ Whitelist All Discovered Software"}
            </button>
          </div>
        </div>
        <div className="metrics-grid">
          <article className="metric-card"><span>Total Discovered</span><strong>{softwareList.length}</strong><small>Discovered in PostgreSQL</small></article>
          <article className="metric-card"><span>Approved Software</span><strong>{approvedCount}</strong><small>Whitelisted by policy</small></article>
          <article className="metric-card"><span>Vulnerable Apps</span><strong>{vulnerableCount}</strong><small>Known CVE vulnerabilities</small></article>
          <article className="metric-card"><span>Unauthorized Drift</span><strong>{unauthorizedCount}</strong><small>Requires review / containment</small></article>
        </div>
      </div>

      {/* Discovery Subprocess & Subnet Section */}
      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Endpoint & Subnet Discovery</p>
            <h2>Run Endpoint Software Discovery (Subnet / WMI / Nmap -sV)</h2>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <form className="form-grid" onSubmit={handleRunDiscovery}>
            <input
              className="scan-input"
              placeholder="Target IP Address or Hostname (e.g. 192.168.10.130)"
              value={discoverTarget}
              onChange={(e) => setDiscoverTarget(e.target.value)}
              required
            />
            <button type="submit" className="scan-action scan-action--resume" disabled={isDiscovering}>
              {isDiscovering ? "Discovering..." : "Scan Target Host"}
            </button>
          </form>

          <form className="form-grid" onSubmit={handleRunSubnetDiscovery}>
            <input
              className="scan-input"
              placeholder="Subnet Range (e.g. 192.168.10.0/24)"
              value={subnetInput}
              onChange={(e) => setSubnetInput(e.target.value)}
              required
            />
            <button type="submit" className="scan-action scan-action--resume" disabled={isDiscovering} style={{ background: "#0284c7" }}>
              {isDiscovering ? "Scanning Subnet..." : "📡 Discover Subnet Endpoints"}
            </button>
          </form>
        </div>
        {feedback ? <p className="scan-feedback scan-feedback--success" style={{ marginTop: "12px" }}>{feedback}</p> : null}
      </div>

      {/* Software Inventory Table */}
      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Discovered software inventory</p>
            <h2>Discovered Software ({rows.length})</h2>
          </div>
          <div className="table-controls">
            <input className="scan-input" placeholder="Filter by target IP (e.g. 192.168.1.50)" value={ipFilter} onChange={(e) => setIpFilter(e.target.value)} />
            <input className="scan-input" placeholder="Filter by software name, vendor..." value={query} onChange={(e) => setQuery(e.target.value)} />
            <select className="scan-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">All statuses</option>
              <option value="UNAUTHORIZED">UNAUTHORIZED</option>
              <option value="VULNERABLE">VULNERABLE</option>
              <option value="APPROVED">APPROVED</option>
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Software Name</th>
                <th>Target IP</th>
                <th>Source</th>
                <th>Vendor</th>
                <th>Category</th>
                <th>Status</th>
                <th>Risk Score</th>
                <th>CVEs</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => {
                const targetIp = item.ip_address || item.metadata?.ip_address || "127.0.0.1";
                const sourceLabel = item.source || item.metadata?.source || "Nmap -sV";
                return (
                  <tr
                    key={item.id}
                    className={selected?.id === item.id ? "finding-row--selected" : ""}
                    onClick={() => setSelectedId(item.id)}
                    style={{ cursor: "pointer" }}
                  >
                    <td data-label="Software Name"><strong>{item.name}</strong></td>
                    <td data-label="Target IP"><code>{targetIp}</code></td>
                    <td data-label="Source"><span className="pill pill--info">{sourceLabel}</span></td>
                    <td data-label="Vendor">{item.vendor || "n/a"}</td>
                    <td data-label="Category">{item.category}</td>
                    <td data-label="Status">
                      <span className={`pill pill--${item.status === "APPROVED" ? "low" : item.status === "VULNERABLE" ? "critical" : "high"}`}>
                        {item.status}
                      </span>
                    </td>
                    <td data-label="Risk Score"><strong>{item.risk_score.toFixed(1)}</strong></td>
                    <td data-label="CVEs">{item.cves?.length ? item.cves.join(", ") : "None"}</td>
                  </tr>
                );
              })}
              {!rows.length ? (
                <tr>
                  <td colSpan="8">
                    <p className="empty-copy">No software discovered for specified IP address in PostgreSQL database.</p>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Software Details & Network Source Mapping */}
      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Network Source Mapping & Remediation</p>
            <h2>{selected ? selected.name : "No software selected"}</h2>
          </div>
        </div>
        {selected ? (
          <div className="finding-detail-grid finding-detail-grid--single">
            <article className="panel panel--embedded">
              <div className="coverage-list">
                <div className="coverage-row"><span>Discovered Target IP</span><code>{selected.ip_address || selected.metadata?.ip_address || "127.0.0.1"}</code></div>
                <div className="coverage-row"><span>Discovery Network Source</span><strong>{selected.source || selected.metadata?.source || "Nmap -sV Subprocess"}</strong></div>
                <div className="coverage-row"><span>Endpoint / Hostname</span><strong>{selected.metadata?.hostname || selected.value || "Unassigned / Target Host"}</strong></div>
                <div className="coverage-row"><span>Software Name</span><strong>{selected.name}</strong></div>
                <div className="coverage-row"><span>Vendor</span><strong>{selected.vendor || "n/a"}</strong></div>
                <div className="coverage-row"><span>Category</span><strong>{selected.category}</strong></div>
                <div className="coverage-row"><span>Governance Status</span><strong>{selected.status}</strong></div>
                <div className="coverage-row"><span>Calculated Risk Score</span><strong>{selected.risk_score}</strong></div>
                <div className="coverage-row"><span>Associated CVEs</span><strong>{selected.cves?.length ? selected.cves.join(", ") : "None"}</strong></div>
              </div>
            </article>
          </div>
        ) : (
          <p className="empty-copy">Select a software entry to view network source mapping.</p>
        )}
      </div>

      {/* Whitelist Governance Section */}
      <div className="panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Approved baseline policy</p>
            <h2>Manage Approved Whitelist ({whitelist.length})</h2>
          </div>
        </div>
        <form className="form-grid" onSubmit={handleAddWhitelist}>
          <input className="scan-input" placeholder="Software Name (e.g. Apache HTTP Server)" value={whitelistForm.name} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, name: e.target.value }))} required />
          <input className="scan-input" placeholder="Vendor (e.g. Apache)" value={whitelistForm.vendor} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, vendor: e.target.value }))} />
          <input className="scan-input" placeholder="Approval Reason" value={whitelistForm.reason} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, reason: e.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Add to Whitelist</button>
        </form>

        <div className="table-wrap" style={{ marginTop: "20px" }}>
          <table className="table table--dense">
            <thead>
              <tr>
                <th>Software Name</th>
                <th>Vendor</th>
                <th>Reason</th>
                <th>Added At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {whitelist.map((w) => (
                <tr key={w.id}>
                  <td data-label="Software Name"><strong>{w.name}</strong></td>
                  <td data-label="Vendor">{w.vendor || "n/a"}</td>
                  <td data-label="Reason">{w.reason}</td>
                  <td data-label="Added At">{new Date(w.created_at).toLocaleDateString()}</td>
                  <td data-label="Action">
                    <button type="button" className="scan-action scan-action--pause" onClick={() => handleRemoveWhitelist(w.id, w.name)}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
              {!whitelist.length ? (
                <tr>
                  <td colSpan="5">
                    <p className="empty-copy">No whitelisted software entries configured in database.</p>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

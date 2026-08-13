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

  // Pagination state (10 per page)
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;
  
  // Whitelist form state
  const [whitelistForm, setWhitelistForm] = useState({ name: "", vendor: "", reason: "Approved by Security Team" });
  
  // Discovery trigger state
  const [discoverTarget, setDiscoverTarget] = useState("");
  const [subnetInput, setSubnetInput] = useState("192.168.10.0/24");
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [isBulkWhitelisting, setIsBulkWhitelisting] = useState(false);
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

  // Filter rows
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

  // Reset to page 1 whenever filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [query, ipFilter, statusFilter, riskFilter]);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const pagedRows = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, currentPage]);

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

  const handleToggleWhitelist = async (swName, swVendor, currentStatus) => {
    try {
      if (currentStatus === "APPROVED") {
        // Find whitelist item ID to remove
        const entry = whitelist.find((w) => w.name.toLowerCase() === swName.toLowerCase());
        if (entry) {
          await api.delete(`/software/whitelist/${entry.id}`);
          setFeedback(`Blacklisted / Removed '${swName}' from approved whitelist.`);
        } else {
          // Manual approval removal fallback
          await api.post("/software/whitelist", { name: swName, vendor: swVendor, reason: "Unapproved by Analyst" });
        }
      } else {
        await api.post("/software/whitelist", {
          name: swName,
          vendor: swVendor || null,
          reason: "Approved via Discovered Inventory Action",
        });
        setFeedback(`Whitelisted / Approved '${swName}'.`);
      }
      fetchSoftwareData();
    } catch (err) {
      setFeedback("Failed to update software governance action.");
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

  const approvedCount = softwareList.filter((s) => s.status === "APPROVED").length;
  const vulnerableCount = softwareList.filter((s) => s.status === "VULNERABLE").length;
  const unauthorizedCount = softwareList.filter((s) => s.status === "UNAUTHORIZED").length;

  return (
    <section className="section-grid">
      {/* Top Metrics Panel */}
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

      {/* Main Two-Column Layout (Discovery & Policy on LEFT, Software Inventory on RIGHT) */}
      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "20px", alignItems: "start" }}>
        
        {/* LEFT COLUMN: Endpoint & Subnet Discovery + Whitelist Governance */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          {/* 1. Endpoint & Subnet Discovery Panel */}
          <div className="panel">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Endpoint & Subnet Discovery</p>
                <h3 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "1.05rem" }}>Run Software Discovery</h3>
              </div>
            </div>
            
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <form className="form-grid" onSubmit={handleRunDiscovery} style={{ gridTemplateColumns: "1fr" }}>
                <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Scan Single Target IP / Host</label>
                <input
                  className="scan-input"
                  placeholder="Target IP (e.g. 192.168.10.130)"
                  value={discoverTarget}
                  onChange={(e) => setDiscoverTarget(e.target.value)}
                  required
                />
                <button type="submit" className="scan-action scan-action--resume" disabled={isDiscovering}>
                  {isDiscovering ? "Discovering..." : "Scan Target Host"}
                </button>
              </form>

              <div style={{ borderTop: "1px solid rgba(148, 163, 184, 0.15)", paddingTop: "12px" }}>
                <form className="form-grid" onSubmit={handleRunSubnetDiscovery} style={{ gridTemplateColumns: "1fr" }}>
                  <label style={{ fontSize: "0.78rem", color: "#94a3b8" }}>Discover Subnet Managed Endpoints</label>
                  <input
                    className="scan-input"
                    placeholder="Subnet (e.g. 192.168.10.0/24)"
                    value={subnetInput}
                    onChange={(e) => setSubnetInput(e.target.value)}
                    required
                  />
                  <button type="submit" className="scan-action scan-action--resume" disabled={isDiscovering} style={{ background: "#0284c7" }}>
                    {isDiscovering ? "Scanning Subnet..." : "📡 Discover Subnet Endpoints"}
                  </button>
                </form>
              </div>
            </div>
            {feedback ? <p className="scan-feedback scan-feedback--success" style={{ marginTop: "12px", fontSize: "0.8rem" }}>{feedback}</p> : null}
          </div>

          {/* 2. Whitelist Baseline Form */}
          <div className="panel">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Approved baseline policy</p>
                <h3 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "1.05rem" }}>Add Whitelist Policy</h3>
              </div>
            </div>
            <form className="form-grid" onSubmit={handleAddWhitelist} style={{ gridTemplateColumns: "1fr" }}>
              <input className="scan-input" placeholder="Software Name (e.g. Apache)" value={whitelistForm.name} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, name: e.target.value }))} required />
              <input className="scan-input" placeholder="Vendor (e.g. Apache Foundation)" value={whitelistForm.vendor} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, vendor: e.target.value }))} />
              <input className="scan-input" placeholder="Approval Reason" value={whitelistForm.reason} onChange={(e) => setWhitelistForm((prev) => ({ ...prev, reason: e.target.value }))} />
              <button type="submit" className="scan-action scan-action--resume">Add to Whitelist</button>
            </form>
          </div>

          {/* 3. Managed Whitelist Entries */}
          <div className="panel">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Whitelist Policy</p>
                <h3 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "1.05rem" }}>Approved Policy ({whitelist.length})</h3>
              </div>
            </div>
            <div style={{ maxHeight: "280px", overflowY: "auto" }}>
              <table className="table table--dense" style={{ fontSize: "0.8rem" }}>
                <thead>
                  <tr>
                    <th>Software Name</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {whitelist.map((w) => (
                    <tr key={w.id}>
                      <td><strong>{w.name}</strong><br/><small style={{ color: "#94a3b8" }}>{w.vendor || "Any Vendor"}</small></td>
                      <td>
                        <button type="button" className="scan-action scan-action--pause" style={{ padding: "2px 6px", fontSize: "0.7rem" }} onClick={() => handleRemoveWhitelist(w.id, w.name)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                  {!whitelist.length ? (
                    <tr>
                      <td colSpan="2"><p className="empty-copy" style={{ padding: "10px 0" }}>No whitelist policy entries configured.</p></td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Discovered Software Inventory Table & Details */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          {/* Software Inventory Panel */}
          <div className="panel" style={{ margin: 0 }}>
            <div className="panel__header" style={{ flexDirection: "column", alignItems: "flex-start", gap: "12px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                <div>
                  <p className="eyebrow">Discovered software inventory</p>
                  <h2>Discovered Software ({rows.length})</h2>
                </div>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
                  Showing {(currentPage - 1) * pageSize + (pagedRows.length ? 1 : 0)} - {(currentPage - 1) * pageSize + pagedRows.length} of {rows.length}
                </span>
              </div>
              <div className="table-controls" style={{ width: "100%", display: "flex", gap: "8px" }}>
                <input className="scan-input" placeholder="Filter by IP..." value={ipFilter} onChange={(e) => setIpFilter(e.target.value)} style={{ flex: 1 }} />
                <input className="scan-input" placeholder="Filter by software name..." value={query} onChange={(e) => setQuery(e.target.value)} style={{ flex: 1 }} />
                <select className="scan-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                  <option value="all">All Statuses</option>
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
                    <th>Status</th>
                    <th>Risk Score</th>
                    <th>Governance Action</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedRows.map((item) => {
                    const targetIp = item.ip_address || item.metadata?.ip_address || "127.0.0.1";
                    const sourceLabel = item.source || item.metadata?.source || "Nmap -sV";
                    const isApproved = item.status === "APPROVED";
                    return (
                      <tr
                        key={item.id}
                        className={selected?.id === item.id ? "finding-row--selected" : ""}
                        onClick={() => setSelectedId(item.id)}
                        style={{ cursor: "pointer" }}
                      >
                        <td data-label="Software Name"><strong>{item.name}</strong><br/><small style={{ color: "#94a3b8" }}>v{item.version || "n/a"}</small></td>
                        <td data-label="Target IP"><code>{targetIp}</code></td>
                        <td data-label="Source"><span className="pill pill--info" style={{ fontSize: "0.72rem" }}>{sourceLabel}</span></td>
                        <td data-label="Vendor">{item.vendor || "n/a"}</td>
                        <td data-label="Status">
                          <span className={`pill pill--${isApproved ? "low" : item.status === "VULNERABLE" ? "critical" : "high"}`}>
                            {item.status}
                          </span>
                        </td>
                        <td data-label="Risk Score"><strong>{item.risk_score.toFixed(1)}</strong></td>
                        <td data-label="Governance Action" onClick={(e) => e.stopPropagation()}>
                          {isApproved ? (
                            <button
                              type="button"
                              className="scan-action scan-action--pause"
                              style={{ padding: "4px 8px", fontSize: "0.75rem", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", color: "#f87171" }}
                              onClick={() => handleToggleWhitelist(item.name, item.vendor, "APPROVED")}
                            >
                              🚫 Blacklist / Unallow
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="scan-action scan-action--resume"
                              style={{ padding: "4px 8px", fontSize: "0.75rem", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#34d399" }}
                              onClick={() => handleToggleWhitelist(item.name, item.vendor, "UNAUTHORIZED")}
                            >
                              🛡️ Allow / Whitelist
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {!pagedRows.length ? (
                    <tr>
                      <td colSpan="7">
                        <p className="empty-copy">No software items found matching filter criteria.</p>
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls (Show 10 per page) */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px", borderTop: "1px solid rgba(148, 163, 184, 0.15)" }}>
              <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>
                Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong> ({rows.length} total applications)
              </span>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  type="button"
                  className="scan-action"
                  disabled={currentPage <= 1}
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  style={{ opacity: currentPage <= 1 ? 0.5 : 1, cursor: currentPage <= 1 ? "not-allowed" : "pointer" }}
                >
                  ◀ Previous
                </button>
                <button
                  type="button"
                  className="scan-action"
                  disabled={currentPage >= totalPages}
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  style={{ opacity: currentPage >= totalPages ? 0.5 : 1, cursor: currentPage >= totalPages ? "not-allowed" : "pointer" }}
                >
                  Next ▶
                </button>
              </div>
            </div>
          </div>

          {/* Selected Software Network Mapping Panel */}
          <div className="panel">
            <div className="panel__header">
              <div>
                <p className="eyebrow">Network Source Mapping & Details</p>
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
        </div>
      </div>
    </section>
  );
}

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
        const entry = whitelist.find((w) => w.name.toLowerCase() === swName.toLowerCase());
        if (entry) {
          await api.delete(`/software/whitelist/${entry.id}`);
          setFeedback(`Blacklisted / Removed '${swName}' from approved whitelist.`);
        } else {
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
    <section className="section-grid" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      
      {/* 1. Top Metrics Banner */}
      <div className="panel panel--metrics" style={{ margin: 0 }}>
        <div className="panel__header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <p className="eyebrow">Unauthorized software governance</p>
            <h2 style={{ fontSize: "1.35rem", margin: 0 }}>Application & Endpoint Software Governance</h2>
          </div>
          <div style={{ display: "flex", gap: "12px" }}>
            <button
              onClick={handleBulkWhitelist}
              disabled={isBulkWhitelisting}
              className="scan-action scan-action--resume"
              style={{ background: "linear-gradient(135deg, #10b981 0%, #059669 100%)", color: "#fff", fontWeight: "bold", padding: "8px 16px", borderRadius: "8px", border: "none" }}
            >
              {isBulkWhitelisting ? "Whitelisting All..." : "🛡️ Whitelist All Discovered Software"}
            </button>
          </div>
        </div>
        <div className="metrics-grid" style={{ marginTop: "16px" }}>
          <article className="metric-card"><span>Total Discovered</span><strong>{softwareList.length}</strong><small>Discovered in PostgreSQL</small></article>
          <article className="metric-card"><span>Approved Software</span><strong>{approvedCount}</strong><small>Whitelisted by policy</small></article>
          <article className="metric-card"><span>Vulnerable Apps</span><strong>{vulnerableCount}</strong><small>Known CVE vulnerabilities</small></article>
          <article className="metric-card"><span>Unauthorized Drift</span><strong>{unauthorizedCount}</strong><small>Requires review / containment</small></article>
        </div>
      </div>

      {/* 2. Discovered Software Inventory Panel (FULL 100% HORIZONTAL WIDTH) */}
      <div className="panel" style={{ margin: 0, width: "100%", boxSizing: "border-box" }}>
        <div className="panel__header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px", marginBottom: "16px" }}>
          <div>
            <p className="eyebrow">Discovered software inventory</p>
            <h2 style={{ fontSize: "1.25rem", margin: 0 }}>Discovered Software ({rows.length})</h2>
          </div>
          <span style={{ fontSize: "0.85rem", color: "#94a3b8", background: "rgba(30, 41, 59, 0.6)", padding: "6px 12px", borderRadius: "6px", border: "1px solid rgba(148, 163, 184, 0.12)" }}>
            Showing <strong>{(currentPage - 1) * pageSize + (pagedRows.length ? 1 : 0)}</strong> - <strong>{(currentPage - 1) * pageSize + pagedRows.length}</strong> of <strong>{rows.length}</strong>
          </span>
        </div>

        {/* Full-width Responsive Search and Filter Bar */}
        <div className="table-controls" style={{ width: "100%", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px", marginBottom: "16px" }}>
          <input className="scan-input" placeholder="🔍 Search by software name, vendor..." value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: "100%" }} />
          <input className="scan-input" placeholder="🌐 Filter by Target IP (e.g. 192.168.30.129)..." value={ipFilter} onChange={(e) => setIpFilter(e.target.value)} style={{ width: "100%" }} />
          <select className="scan-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={{ width: "100%" }}>
            <option value="all">All Statuses (Approved, Unauthorized, Vulnerable)</option>
            <option value="UNAUTHORIZED">UNAUTHORIZED</option>
            <option value="VULNERABLE">VULNERABLE</option>
            <option value="APPROVED">APPROVED</option>
          </select>
        </div>

        {/* Full-width Scrollable Table Container */}
        <div className="table-wrap" style={{ overflowX: "auto", width: "100%", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.12)" }}>
          <table className="table table--dense" style={{ width: "100%", minWidth: "950px", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "rgba(15, 23, 42, 0.8)", textAlign: "left" }}>
                <th style={{ padding: "12px 14px", width: "24%" }}>Software Name & Version</th>
                <th style={{ padding: "12px 14px", width: "16%" }}>Target IP Address</th>
                <th style={{ padding: "12px 14px", width: "15%" }}>Discovery Source</th>
                <th style={{ padding: "12px 14px", width: "15%" }}>Vendor / Publisher</th>
                <th style={{ padding: "12px 14px", width: "10%" }}>Status</th>
                <th style={{ padding: "12px 14px", width: "8%" }}>Risk Score</th>
                <th style={{ padding: "12px 14px", width: "12%", textAlign: "right" }}>Governance Action</th>
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
                    style={{ cursor: "pointer", transition: "background 0.15s ease" }}
                  >
                    <td data-label="Software Name" style={{ padding: "12px 14px" }}>
                      <strong style={{ color: "#f8fafc", fontSize: "0.9rem", display: "block" }}>{item.name}</strong>
                      <small style={{ color: "#94a3b8", fontSize: "0.78rem" }}>{item.version ? `v${item.version}` : "Version unspecified"}</small>
                    </td>
                    <td data-label="Target IP" style={{ padding: "12px 14px" }}>
                      <code style={{ background: "rgba(30, 41, 59, 0.8)", padding: "4px 8px", borderRadius: "4px", fontSize: "0.82rem", color: "#38bdf8" }}>{targetIp}</code>
                    </td>
                    <td data-label="Source" style={{ padding: "12px 14px" }}>
                      <span className="pill pill--info" style={{ fontSize: "0.75rem", padding: "4px 8px" }}>{sourceLabel}</span>
                    </td>
                    <td data-label="Vendor" style={{ padding: "12px 14px", color: "#cbd5e1", fontSize: "0.85rem" }}>{item.vendor || "Unknown Vendor"}</td>
                    <td data-label="Status" style={{ padding: "12px 14px" }}>
                      <span className={`pill pill--${isApproved ? "low" : item.status === "VULNERABLE" ? "critical" : "high"}`} style={{ fontSize: "0.75rem", fontWeight: "600" }}>
                        {item.status}
                      </span>
                    </td>
                    <td data-label="Risk Score" style={{ padding: "12px 14px" }}>
                      <strong style={{ color: item.risk_score >= 7 ? "#f87171" : item.risk_score >= 4 ? "#fbbf24" : "#34d399", fontSize: "0.9rem" }}>
                        {item.risk_score.toFixed(1)}
                      </strong>
                    </td>
                    <td data-label="Governance Action" style={{ padding: "12px 14px", textAlign: "right" }} onClick={(e) => e.stopPropagation()}>
                      {isApproved ? (
                        <button
                          type="button"
                          className="scan-action scan-action--pause"
                          style={{ padding: "6px 12px", fontSize: "0.78rem", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", color: "#f87171", borderRadius: "6px", fontWeight: "600" }}
                          onClick={() => handleToggleWhitelist(item.name, item.vendor, "APPROVED")}
                        >
                          🚫 Blacklist App
                        </button>
                      ) : (
                        <button
                          type="button"
                          className="scan-action scan-action--resume"
                          style={{ padding: "6px 12px", fontSize: "0.78rem", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#34d399", borderRadius: "6px", fontWeight: "600" }}
                          onClick={() => handleToggleWhitelist(item.name, item.vendor, "UNAUTHORIZED")}
                        >
                          🛡️ Whitelist App
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!pagedRows.length ? (
                <tr>
                  <td colSpan="7" style={{ padding: "24px", textAlign: "center" }}>
                    <p className="empty-copy" style={{ color: "#94a3b8", margin: 0 }}>No software items found matching filter criteria.</p>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        {/* Full-width Responsive Pagination Controls */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px", marginTop: "16px", paddingTop: "14px", borderTop: "1px solid rgba(148, 163, 184, 0.15)" }}>
          <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>
            Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong> ({rows.length} total applications)
          </span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              type="button"
              className="scan-action"
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
              style={{ opacity: currentPage <= 1 ? 0.4 : 1, cursor: currentPage <= 1 ? "not-allowed" : "pointer", padding: "6px 14px", fontSize: "0.8rem" }}
            >
              ◀ Previous
            </button>
            <button
              type="button"
              className="scan-action"
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
              style={{ opacity: currentPage >= totalPages ? 0.4 : 1, cursor: currentPage >= totalPages ? "not-allowed" : "pointer", padding: "6px 14px", fontSize: "0.8rem" }}
            >
              Next ▶
            </button>
          </div>
        </div>
      </div>

      {/* 3. Dual Sub-Panels (Bottom Layout): Details on LEFT (1fr), Discovery & Policy on RIGHT (380px) */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "24px", alignItems: "start" }}>
        
        {/* LEFT SUB-PANEL: Selected Software Network Mapping & Details */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel__header" style={{ marginBottom: "14px" }}>
            <div>
              <p className="eyebrow">Network Source Mapping & Details</p>
              <h3 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "1.1rem" }}>{selected ? selected.name : "No software selected"}</h3>
            </div>
          </div>
          {selected ? (
            <div className="finding-detail-grid finding-detail-grid--single">
              <article className="panel panel--embedded">
                <div className="coverage-list" style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Discovered Target IP</span><code>{selected.ip_address || selected.metadata?.ip_address || "127.0.0.1"}</code></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Discovery Network Source</span><strong>{selected.source || selected.metadata?.source || "Nmap -sV Subprocess"}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Endpoint / Hostname</span><strong>{selected.metadata?.hostname || selected.value || "Unassigned / Target Host"}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Software Name</span><strong>{selected.name}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Vendor</span><strong>{selected.vendor || "n/a"}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Category</span><strong>{selected.category}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Governance Status</span><strong>{selected.status}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}><span>Calculated Risk Score</span><strong>{selected.risk_score}</strong></div>
                  <div className="coverage-row" style={{ display: "flex", justifyContent: "space-between", padding: "8px 0" }}><span>Associated CVEs</span><strong>{selected.cves?.length ? selected.cves.join(", ") : "None"}</strong></div>
                </div>
              </article>
            </div>
          ) : (
            <p className="empty-copy">Select a software entry from the inventory table above to view details.</p>
          )}
        </div>

        {/* RIGHT SUB-PANEL: Discovery & Approved Baseline Policy Tools */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          
          {/* 1. Endpoint & Subnet Discovery Panel */}
          <div className="panel" style={{ margin: 0 }}>
            <div className="panel__header" style={{ marginBottom: "12px" }}>
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

          {/* 2. Whitelist Baseline Policy Form */}
          <div className="panel" style={{ margin: 0 }}>
            <div className="panel__header" style={{ marginBottom: "12px" }}>
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

          {/* 3. Approved Whitelist Policy List */}
          <div className="panel" style={{ margin: 0 }}>
            <div className="panel__header" style={{ marginBottom: "12px" }}>
              <div>
                <p className="eyebrow">Whitelist Policy</p>
                <h3 style={{ color: "#f8fafc", margin: "4px 0", fontSize: "1.05rem" }}>Approved Policy ({whitelist.length})</h3>
              </div>
            </div>
            <div style={{ maxHeight: "240px", overflowY: "auto" }}>
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
      </div>
    </section>
  );
}

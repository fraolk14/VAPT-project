import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import api from "../api/client";

const POLL_MS = 60 * 1000;
const KIND_LABEL = { finding_assigned: "Assigned to you", new_cve: "New CVE", cve_digest: "CVE digest" };

function ago(iso) {
  if (!iso) return "";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Navbar bell: findings assigned to you and new CVEs from the threat-intel feeds. */
export default function NotificationBell() {
  const navigate = useNavigate();
  const rootRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState([]);
  const [unread, setUnread] = useState(0);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.get("/notifications", { params: { limit: 30 } });
      setItems(res.data.items || []);
      setUnread(res.data.unread || 0);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(load, 0);
    const timer = window.setInterval(() => { if (!document.hidden) load(); }, POLL_MS);
    const onVisible = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [load]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (e) => { if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const openItem = async (n) => {
    if (!n.read) {
      setItems((list) => list.map((x) => (x.id === n.id ? { ...x, read: true } : x)));
      setUnread((u) => Math.max(0, u - 1));
      api.post(`/notifications/${n.id}/read`).catch(() => load());
    }
    setOpen(false);
    if (n.link) navigate(n.link);
  };

  const readAll = async () => {
    setItems((list) => list.map((x) => ({ ...x, read: true })));
    setUnread(0);
    try {
      await api.post("/notifications/read-all");
    } catch {
      load();
    }
  };

  return (
    <div className="nw-bell" ref={rootRef}>
      <button
        type="button"
        className={`nw-bell__btn${unread ? " has-unread" : ""}`}
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
        aria-haspopup="true"
        onClick={() => { setOpen((o) => !o); if (!open) load(); }}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M6 9a6 6 0 1 1 12 0c0 5 2 6.5 2 6.5H4S6 14 6 9Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
          <path d="M10 19a2 2 0 0 0 4 0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
        {unread > 0 && <span className="nw-bell__badge">{unread > 99 ? "99+" : unread}</span>}
      </button>

      {open && (
        <div className="nw-bell__panel" role="dialog" aria-label="Notifications">
          <header className="nw-bell__head">
            <strong>Notifications</strong>
            <button type="button" className="nw-bell__link" onClick={readAll} disabled={!unread}>Mark all read</button>
          </header>
          {failed && !items.length ? (
            <p className="nw-bell__empty">Couldn't load notifications.</p>
          ) : !items.length ? (
            <p className="nw-bell__empty">
              Nothing yet. You'll be notified when a finding is assigned to you and when new exploited or critical CVEs appear in threat intelligence.
            </p>
          ) : (
            <ul className="nw-bell__list">
              {items.map((n) => (
                <li key={n.id}>
                  <button type="button" className={`nw-bell__item${n.read ? "" : " is-unread"}`} onClick={() => openItem(n)}>
                    <span className={`nw-bell__sev nw-bell__sev--${n.severity || "info"}`} aria-hidden="true" />
                    <span className="nw-bell__text">
                      <span className="nw-bell__meta">
                        {KIND_LABEL[n.kind] || n.kind}
                        {n.data?.source ? ` · ${n.data.source}` : ""}
                        {n.data?.in_environment ? " · in your environment" : ""}
                        {" · "}{ago(n.created_at)}
                      </span>
                      <span className="nw-bell__title">{n.title}</span>
                      {n.body ? <span className="nw-bell__body">{n.body}</span> : null}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

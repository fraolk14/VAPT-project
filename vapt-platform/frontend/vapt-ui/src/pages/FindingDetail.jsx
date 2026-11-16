import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import api from "../api/client";
import { Workspace } from "./AIRemediation";
import "../commandcenter.css";
import "../scans.css";
import "../analytics.css";
import "../misconfig.css";
import "../ops.css";
import "../airem.css";

/** One finding: facts, evidence, guidance and analysis (the same workspace AI Remediation uses). */
export default function FindingDetail() {
  const { findingId } = useParams();
  const [aiReady, setAiReady] = useState(false);

  useEffect(() => {
    api.get("/ai/status").then((r) => setAiReady(Boolean(r.data?.available))).catch(() => setAiReady(false));
  }, []);

  return (
    <div className="cc ai-page">
      <header className="cc-top">
        <div className="cc-top__title">
          <span className="cc-live-dot" aria-hidden="true" />
          <h1>Finding</h1>
        </div>
        <div className="cc-top__tools">
          <Link className="cc-btn" to="/findings">Back to Findings</Link>
        </div>
      </header>
      <section className="cc-panel ai-detail" aria-label="Finding detail">
        <Workspace key={findingId} findingId={findingId} aiReady={aiReady} />
      </section>
    </div>
  );
}

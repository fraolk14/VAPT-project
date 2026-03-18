from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.dashboard import DashboardMetric, DashboardSummary
from app.services.risk_engine import summarize_risk

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    risk = summarize_risk(findings)
    coverage = Counter(scan.tool for scan in scans)

    metrics = [
        DashboardMetric(label="Assets Monitored", value="2", trend="+12%"),
        DashboardMetric(
            label="Active Campaigns",
            value=str(sum(1 for scan in scans if scan.status == "running")),
            trend="+2",
        ),
        DashboardMetric(label="Open Findings", value=str(risk["open_findings"]), trend="-8%"),
        DashboardMetric(label="Risk Score", value=str(risk["risk_score"]), trend="-4.3%"),
    ]

    return DashboardSummary(
        metrics=metrics,
        tool_coverage=dict(coverage),
        severity_breakdown=risk["severity_breakdown"],
        open_findings=risk["open_findings"],
        active_scans=sum(1 for scan in scans if scan.status == "running"),
        risk_score=risk["risk_score"],
    )

from pydantic import BaseModel, Field


class DashboardMetric(BaseModel):
    label: str
    value: str
    trend: str


class DashboardSummary(BaseModel):
    metrics: list[DashboardMetric] = Field(default_factory=list)
    tool_coverage: dict[str, int] = Field(default_factory=dict)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    open_findings: int
    active_scans: int
    risk_score: float

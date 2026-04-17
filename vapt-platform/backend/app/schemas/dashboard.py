from pydantic import BaseModel, Field


class DashboardMetric(BaseModel):
    label: str
    value: str
    trend: str


class DashboardTargetSummary(BaseModel):
    target: str
    tool: str
    severity: str
    finding_count: int


class DashboardOwaspSummary(BaseModel):
    category: str
    count: int


class DashboardAttackActivity(BaseModel):
    attack: str
    count: int
    severity: str
    source: str


class DashboardSummary(BaseModel):
    metrics: list[DashboardMetric] = Field(default_factory=list)
    scanned_targets: list[DashboardTargetSummary] = Field(default_factory=list)
    tool_coverage: dict[str, int] = Field(default_factory=dict)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    target_severity_breakdown: dict[str, int] = Field(default_factory=dict)
    target_severity_by_tool: dict[str, dict[str, int]] = Field(default_factory=dict)
    owasp_top10: list[DashboardOwaspSummary] = Field(default_factory=list)
    attack_activity: list[DashboardAttackActivity] = Field(default_factory=list)
    open_findings: int
    active_scans: int
    risk_score: float

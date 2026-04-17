from typing import Literal

from pydantic import BaseModel, Field, field_validator


PriorityLiteral = Literal["Critical", "High", "Medium", "Low"]
ConfidenceLiteral = Literal["Low", "Medium", "High"]
ThreatLevelLiteral = Literal["Low", "Medium", "High", "Critical"]


class AIAssetContext(BaseModel):
    criticality: str = "Medium"
    type: str = "Unknown"
    exposure: str = "Internal"


class AIVulnerabilityInput(BaseModel):
    cve: str | None = None
    cvss: float | None = None
    asset: AIAssetContext
    vulnerability: str
    scan_details: str = ""
    exploit_available: bool | None = None
    source: str | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("cvss")
    @classmethod
    def validate_cvss(cls, value: float | None) -> float | None:
        if value is not None and not 0 <= value <= 10:
            raise ValueError("cvss must be between 0 and 10")
        return value


class AIRiskScoreResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    priority: PriorityLiteral
    reason: str


class AIExplanationResponse(BaseModel):
    summary: str
    impact: str
    exploitation: str
    technical_details: str


class AIRemediationResponse(BaseModel):
    remediation_steps: list[str] = Field(default_factory=list)
    patches: list[str] = Field(default_factory=list)
    configuration_fix: str


class AIFalsePositiveResponse(BaseModel):
    false_positive_probability: int = Field(ge=0, le=100)
    confidence: ConfidenceLiteral
    reason: str


class AIThreatIntelResponse(BaseModel):
    actively_exploited: bool
    known_attacks: list[str] = Field(default_factory=list)
    threat_level: ThreatLevelLiteral


class AIAnalysisEnvelope(BaseModel):
    provider: str
    model: str
    cached: bool = False
    analysis_type: str
    data: dict


class AIAssistRequest(BaseModel):
    mode: str = "assistant"
    prompt: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    context: dict = Field(default_factory=dict)


class AIAssistResponse(BaseModel):
    mode: str
    content: str
    model: str
    provider: str = "local"
    status: str = "ready"


class AIFindingRecommendationRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)


class AIFindingRecommendation(BaseModel):
    finding_id: str
    recommendation: str


class AIFindingRecommendationResponse(BaseModel):
    model: str
    provider: str = "local"
    items: list[AIFindingRecommendation] = Field(default_factory=list)


class AIStatusResponse(BaseModel):
    available: bool
    provider: str
    model: str
    status: str
    capabilities: list[str] = Field(default_factory=list)
    setup_hint: str | None = None

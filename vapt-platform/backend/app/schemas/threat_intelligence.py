from pydantic import BaseModel, Field


class ThreatFeedItem(BaseModel):
    finding_id: str
    title: str
    cve_id: str | None = None
    severity: str
    source: str
    target: str
    cvss_score: float | None = None
    exploit_available: bool = False
    actively_exploited: bool = False
    exploit_indicator: str
    mitre_attack: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    feed_sources: list[str] = Field(default_factory=list)


class MISPFeedEvent(BaseModel):
    id: str
    name: str
    description: str | None = None
    modified: str | None = None
    created: str | None = None
    author_name: str | None = None
    indicator_count: int = 0
    tags: list[str] = Field(default_factory=list)
    adversary: str | None = None
    tlp: str | None = None
    threat_level: str | None = None
    references: list[str] = Field(default_factory=list)
    url: str | None = None


class ExternalThreatEvent(BaseModel):
    id: str
    source: str
    name: str
    description: str | None = None
    created: str | None = None
    indicator_count: int = 0
    severity: str | None = None
    matched_findings: int = 0
    matched_targets: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    url: str | None = None


class ThreatIntelSummary(BaseModel):
    total_enriched: int
    actively_exploited: int
    exploit_available: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    mitre_coverage: dict[str, int] = Field(default_factory=dict)
    reference_coverage: dict[str, int] = Field(default_factory=dict)
    misp_status: str = "not_configured"
    top_feed: list[ThreatFeedItem] = Field(default_factory=list)
    misp_events: list[MISPFeedEvent] = Field(default_factory=list)
    external_feed_status: str = "not_configured"
    external_events: list[ExternalThreatEvent] = Field(default_factory=list)


class ThreatIntelFeedResponse(BaseModel):
    total: int
    items: list[ThreatFeedItem] = Field(default_factory=list)


class AttackMapFlow(BaseModel):
    id: str
    source_country: str
    target_country: str
    source_region: str | None = None
    target_region: str | None = None
    attack_type: str
    severity: str
    timestamp: str
    title: str
    industry: str | None = None
    malware_type: str | None = None
    ti_source: str | None = None
    references: list[str] = Field(default_factory=list)
    target_label: str | None = None
    company_name: str | None = None


class AttackMapCountryStat(BaseModel):
    country: str
    attacks: int


class AttackMapIndustryStat(BaseModel):
    industry: str
    attacks: int


class AttackMapMalwareStat(BaseModel):
    malware_type: str
    attacks: int


class AttackMapCountryDetail(BaseModel):
    country: str
    attack_count: int
    source_count: int
    target_count: int
    top_attack_types: list[dict[str, int]] = Field(default_factory=list)
    top_sources: list[dict[str, int]] = Field(default_factory=list)
    top_industries: list[dict[str, int]] = Field(default_factory=list)
    top_malware: list[dict[str, int]] = Field(default_factory=list)
    latest_flows: list[AttackMapFlow] = Field(default_factory=list)


class AttackMapResponse(BaseModel):
    generated_at: str
    daily_attack_count: int
    active_flow_count: int
    flows: list[AttackMapFlow] = Field(default_factory=list)
    most_attacked_1h: list[AttackMapCountryStat] = Field(default_factory=list)
    most_attacked_12h: list[AttackMapCountryStat] = Field(default_factory=list)
    most_attacked_24h: list[AttackMapCountryStat] = Field(default_factory=list)
    most_targeted_industries: list[AttackMapIndustryStat] = Field(default_factory=list)
    top_malware_types: list[AttackMapMalwareStat] = Field(default_factory=list)
    countries: dict[str, AttackMapCountryDetail] = Field(default_factory=dict)

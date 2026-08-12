from sqlalchemy.orm import Session

from app.models.auth import AuthPolicy, SSOProvider
from app.models.operations import ComplianceTemplate, MonitoringRule
from app.models.tenant import Tenant
from app.models.asset import Asset
from app.models.user import User
from app.models.finding import Finding
from app.services.security import hash_password


def seed_demo_data(db: Session) -> None:
    default_tenant = db.query(Tenant).filter(Tenant.slug == "default").first()
    if not default_tenant:
        default_tenant = Tenant(
            id="default",
            name="Default Organization",
            slug="default",
            status="active",
            settings={"branding": "Blackridge Security Mesh"},
            is_default=True,
        )
        db.add(default_tenant)
        db.commit()

    if db.query(User).count() == 0:
        db.add(
            User(
                username="admin",
                email="admin@vapt.local",
                tenant_id="default",
                password_hash=hash_password("ChangeMe123!"),
                role="admin",
                auth_source="local",
                mfa_enabled=False,
            )
        )
    else:
        admin = db.query(User).filter(User.username == "admin").first()
        if admin and admin.mfa_enabled and not admin.mfa_secret:
            admin.mfa_enabled = False
        if admin and not admin.tenant_id:
            admin.tenant_id = "default"

    if db.query(Asset).count() == 0:
        db.add_all(
            [
                Asset(
                    asset_name="Edge Gateway",
                    tenant_id="default",
                    ip_address="10.0.0.10",
                    hostname="edge-gw",
                    os="Ubuntu 24.04",
                    asset_type="network",
                    environment="prod",
                    criticality="critical",
                    owner="Network Team",
                    exposure="external",
                    tags=["dmz", "internet-facing"],
                    business_unit="Infrastructure",
                    risk_score=86.5,
                ),
                Asset(
                    asset_name="Customer Portal",
                    tenant_id="default",
                    ip_address="10.0.1.22",
                    hostname="portal-web-01",
                    os="Debian 12",
                    asset_type="web",
                    environment="prod",
                    criticality="high",
                    owner="AppSec",
                    exposure="external",
                    tags=["pci", "customer-facing"],
                    business_unit="Digital",
                    risk_score=74.1,
                ),
                Asset(
                    asset_name="Finance Workstation 07",
                    tenant_id="default",
                    ip_address="10.0.5.77",
                    hostname="fin-ws-07",
                    os="Windows 11",
                    asset_type="endpoint",
                    environment="prod",
                    criticality="high",
                    owner="Finance IT",
                    exposure="internal",
                    tags=["AnyDesk", "UnsignedTool", "Browser"],
                    business_unit="Finance",
                    risk_score=63.5,
                ),
                Asset(
                    asset_name="Unsanctioned SaaS Workspace",
                    tenant_id="default",
                    ip_address="198.51.100.20",
                    hostname="collab-shadow.example",
                    os="SaaS",
                    asset_type="saas",
                    environment="prod",
                    criticality="medium",
                    owner=None,
                    exposure="external",
                    tags=["ShadowSaaS", "Notion", "Dropbox"],
                    cloud_provider="Multi-cloud",
                    business_unit="Unknown",
                    risk_score=58.0,
                ),
            ]
        )
    else:
        asset_names = {asset.asset_name for asset in db.query(Asset).all()}
        additions = []
        if "Finance Workstation 07" not in asset_names:
            additions.append(
                Asset(
                    asset_name="Finance Workstation 07",
                    tenant_id="default",
                    ip_address="10.0.5.77",
                    hostname="fin-ws-07",
                    os="Windows 11",
                    asset_type="endpoint",
                    environment="prod",
                    criticality="high",
                    owner="Finance IT",
                    exposure="internal",
                    tags=["AnyDesk", "UnsignedTool", "Browser"],
                    business_unit="Finance",
                    risk_score=63.5,
                )
            )
        if "Unsanctioned SaaS Workspace" not in asset_names:
            additions.append(
                Asset(
                    asset_name="Unsanctioned SaaS Workspace",
                    tenant_id="default",
                    ip_address="198.51.100.20",
                    hostname="collab-shadow.example",
                    os="SaaS",
                    asset_type="saas",
                    environment="prod",
                    criticality="medium",
                    owner=None,
                    exposure="external",
                    tags=["ShadowSaaS", "Notion", "Dropbox"],
                    cloud_provider="Multi-cloud",
                    business_unit="Unknown",
                    risk_score=58.0,
                )
            )
        if additions:
            db.add_all(additions)

    existing_rules = {rule.name for rule in db.query(MonitoringRule).all()}
    if "Suspicious External Login" not in existing_rules:
        db.add(
            MonitoringRule(
                name="Suspicious External Login",
                event_source="siem",
                event_type="suspicious_login",
                target_match="portal",
                action="queue_scan",
                tool="zap",
                enabled=True,
                metadata_json={"playbook": "identity-threat"},
            )
        )

    existing_templates = {template.name for template in db.query(ComplianceTemplate).all()}
    for name, framework, controls in [
        ("OWASP ASVS Baseline", "OWASP ASVS", ["Authentication", "Session Management", "Validation"]),
        ("NIST 800-53 Essentials", "NIST", ["RA-5", "SI-2", "CA-7"]),
        ("ISO 27001 Readiness", "ISO 27001", ["A.8", "A.12", "A.14"]),
    ]:
        if name not in existing_templates:
            db.add(ComplianceTemplate(name=name, framework=framework, controls=controls, enabled=True))

    if not db.query(AuthPolicy).filter(AuthPolicy.policy_name == "default").first():
        db.add(
            AuthPolicy(
                policy_name="default",
                captcha_enabled=False,
                mfa_required=False,
                sso_required=False,
                allow_local_login=True,
            )
        )

    existing_providers = {provider.name for provider in db.query(SSOProvider).all()}
    if "Corporate OIDC" not in existing_providers:
        db.add(
            SSOProvider(
                name="Corporate OIDC",
                provider_type="oidc",
                login_url="https://login.example.local/authorize",
                metadata_url="https://login.example.local/.well-known/openid-configuration",
                enabled=True,
            )
        )
    if db.query(Finding).count() == 0:
        from app.models.scan import Scan
        from sqlalchemy.sql import func
        scan = Scan(
            scan_name="System Default Audit",
            scan_type="network",
            tool="openvas",
            target="10.0.0.10",
            status="completed",
            finished_at=func.now()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        db.add_all([
            Finding(
                scan_id=scan.id,
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity="high",
                category="web",
                source="zap",
                status="open",
                port=443,
                protocol="tcp",
                state="open",
                cvss_score=7.5,
                cve_id="CVE-2023-28432",
                evidence="HTTPS target lacks Strict-Transport-Security header.",
                remediation="Configure Strict-Transport-Security header in web server config.",
                finding_metadata={"url": "https://portal-web-01.local/login", "host": "portal-web-01", "cwe_id": "319"}
            ),
            Finding(
                scan_id=scan.id,
                title="Reflected Cross-Site Scripting (XSS) in Search Route",
                severity="high",
                category="web",
                source="zap",
                status="open",
                port=80,
                protocol="tcp",
                state="open",
                cvss_score=7.2,
                cve_id=None,
                evidence="Reflected payload observed in search parameter `q`.",
                remediation="Implement contextual HTML output encoding and CSP.",
                finding_metadata={"url": "https://portal-web-01.local/search?q=", "host": "portal-web-01", "cwe_id": "79"}
            ),
            Finding(
                scan_id=scan.id,
                title="Open SSH Service with Password Authentication Allowed",
                severity="medium",
                category="network",
                source="openvas",
                status="open",
                port=22,
                protocol="tcp",
                state="open",
                cvss_score=5.8,
                cve_id="CVE-2023-38408",
                evidence="OpenSSH server accepts password authentication without public key enforcement.",
                remediation="Disable password authentication in sshd_config.",
                finding_metadata={"host": "10.0.0.10", "port": 22, "protocol": "tcp"}
            ),
            Finding(
                scan_id=scan.id,
                title="Unpatched Windows SMB Protocol Vulnerability (EternalBlue / SMBGhost)",
                severity="critical",
                category="network",
                source="openvas",
                status="open",
                port=445,
                protocol="tcp",
                state="open",
                cvss_score=9.8,
                cve_id="CVE-2020-0796",
                evidence="Remote SMBv3 compression vulnerability detected on target host 10.0.5.77.",
                remediation="Apply KB4551762 update and restrict port 445 on perimeter firewalls.",
                finding_metadata={"host": "10.0.5.77", "port": 445, "protocol": "tcp"}
            ),
        ])

    db.commit()

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.user import User
from app.services.security import hash_password


def seed_demo_data(db: Session) -> None:
    if db.query(User).count() == 0:
        db.add(
            User(
                username="admin",
                email="admin@vapt.local",
                password_hash=hash_password("ChangeMe123!"),
                role="admin",
                auth_source="local",
                mfa_enabled=True,
            )
        )

    if db.query(Asset).count() == 0:
        db.add_all(
            [
                Asset(
                    asset_name="Edge Gateway",
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
            ]
        )

    db.commit()

"""Delete the misconfiguration rows the retired engine invented without scanning anything.

The old misconfiguration engine stored the same fixed issues for every target (for example a
Cisco IOS XE RCE on any private IP). Those rows are already hidden from the API; this removes
them, plus any misconfig_asset rows left with no issues.

Usage (inside the api container):
    python -m app.scripts.purge_fabricated_misconfigs            # dry run: count only
    python -m app.scripts.purge_fabricated_misconfigs --apply    # delete
"""
import sys

from sqlalchemy import not_

from app.database import SessionLocal
from app.models.misconfiguration import MisconfigAsset, Misconfiguration
from app.services.misconfig_scanner import fabricated_filter


def main() -> int:
    apply = "--apply" in sys.argv
    db = SessionLocal()
    try:
        fake = db.query(Misconfiguration).filter(not_(fabricated_filter(Misconfiguration)))
        count = fake.count()
        print(f"{count} fabricated misconfiguration row(s) found.")
        if not apply:
            print("Dry run; pass --apply to delete them.")
            return 0
        fake.delete(synchronize_session=False)
        db.commit()
        empty = db.query(MisconfigAsset).filter(~MisconfigAsset.misconfigurations.any())
        orphans = empty.count()
        empty.delete(synchronize_session=False)
        db.commit()
        print(f"Deleted {count} row(s) and {orphans} empty misconfig asset(s).")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

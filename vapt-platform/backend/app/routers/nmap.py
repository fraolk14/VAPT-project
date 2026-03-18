from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.nmap_service import process_nmap_scan
from app.models.scan import Scan

router = APIRouter(prefix="/nmap", tags=["Nmap"])


@router.post("/scan")
def start_nmap_scan(payload: dict, db: Session = Depends(get_db)):
    scan = Scan(
        scan_name=f"Nmap Scan {payload['target']}",
        scan_type="network",
        tool="nmap",
        status="running"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    process_nmap_scan(db, payload["target"])

    scan.status = "completed"
    db.commit()

    return {"scan_id": str(scan.id), "status": "completed"}

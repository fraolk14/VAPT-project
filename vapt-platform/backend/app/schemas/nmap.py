from pydantic import BaseModel


class NmapScanRequest(BaseModel):
    target: str

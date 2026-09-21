from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict

class EventIn(BaseModel):
    timestamp: Optional[datetime] = None
    source: str = "unknown"
    event_type: str
    event_id: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    message: Optional[str] = None
    metadata_json: dict[str, Any] = {}

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    rule: str
    title: str
    severity: str
    score: int
    status: str
    source_ip: Optional[str]
    username: Optional[str]
    mitre_technique: Optional[str]
    mitre_name: Optional[str]
    evidence: list[Any]

class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    title: str
    severity: str
    status: str
    alert_ids: list[Any]
    notes: str

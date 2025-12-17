from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List
from app.models.incident import IncidentStatus, IncidentSeverity, IncidentType

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    type: IncidentType
    status: IncidentStatus = IncidentStatus.OPEN
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    assigned_to: Optional[int] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    type: Optional[IncidentType] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[int] = None

class Incident(IncidentBase):
    id: int
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

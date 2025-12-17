from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from app.models.alert import AlertStatus, AlertSeverity, AlertType

class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    type: AlertType
    status: AlertStatus = AlertStatus.OPEN
    severity: AlertSeverity = AlertSeverity.MEDIUM
    source: str

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    type: Optional[AlertType] = None
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    source: Optional[str] = None

class Alert(AlertBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

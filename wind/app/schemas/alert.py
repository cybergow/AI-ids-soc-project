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

class Alert(AlertBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

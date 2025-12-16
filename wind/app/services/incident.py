from sqlalchemy.orm import Session
from typing import List, Optional

from app.models.incident import Incident as IncidentModel
from app.schemas.incident import IncidentCreate, Incident as IncidentSchema

def get_incident(db: Session, incident_id: int) -> Optional[IncidentModel]:
    return db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()

def get_incidents(db: Session, skip: int = 0, limit: int = 100) -> List[IncidentModel]:
    return db.query(IncidentModel).offset(skip).limit(limit).all()

def create_incident(db: Session, incident: IncidentCreate) -> IncidentModel:
    db_incident = IncidentModel(**incident.dict())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident

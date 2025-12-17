from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import or_

from app.models.incident import Incident as IncidentModel
from app.schemas.incident import IncidentCreate, IncidentUpdate, Incident as IncidentSchema

def get_incident(db: Session, incident_id: int) -> Optional[IncidentModel]:
    return db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()

def get_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    type_: Optional[str] = None,
    assigned_to: Optional[int] = None,
    q: Optional[str] = None,
) -> List[IncidentModel]:
    query = db.query(IncidentModel)
    if status:
        query = query.filter(IncidentModel.status == status)
    if severity:
        query = query.filter(IncidentModel.severity == severity)
    if type_:
        query = query.filter(IncidentModel.type == type_)
    if assigned_to:
        query = query.filter(IncidentModel.assigned_to == assigned_to)
    if q:
        search_filter = or_(
            IncidentModel.title.ilike(f"%{q}%"),
            IncidentModel.description.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)
    return query.offset(skip).limit(limit).all()

def create_incident(db: Session, incident: IncidentCreate) -> IncidentModel:
    db_incident = IncidentModel(**incident.dict())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident

def update_incident(db: Session, incident_id: int, incident_update: IncidentUpdate) -> Optional[IncidentModel]:
    db_incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not db_incident:
        return None
    update_data = incident_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_incident, field, value)
    db.commit()
    db.refresh(db_incident)
    return db_incident

def delete_incident(db: Session, incident_id: int) -> Optional[IncidentModel]:
    db_incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not db_incident:
        return None
    db.delete(db_incident)
    db.commit()
    return db_incident

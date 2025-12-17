from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.schemas.incident import Incident, IncidentCreate, IncidentUpdate
from app.services.incident import get_incidents, create_incident, get_incident, update_incident, delete_incident
from app.core.rbac import require_admin_or_analyst, require_any_authenticated
from app.models.user import User

router = APIRouter()

@router.get("/", response_model=List[Incident])
def read_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    assigned_to: Optional[int] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
):
    incidents = get_incidents(db, skip=skip, limit=limit, status=status, severity=severity, type_=type, assigned_to=assigned_to, q=q)
    return incidents

@router.post("/", response_model=Incident, status_code=status.HTTP_201_CREATED)
def create_new_incident(incident: IncidentCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    return create_incident(db=db, incident=incident)

@router.get("/{incident_id}", response_model=Incident)
def read_incident(incident_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_any_authenticated)):
    db_incident = get_incident(db, incident_id=incident_id)
    if db_incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return db_incident

@router.put("/{incident_id}", response_model=Incident)
def update_incident_endpoint(incident_id: int, incident_update: IncidentUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    db_incident = update_incident(db, incident_id=incident_id, incident_update=incident_update)
    if db_incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return db_incident

@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident_endpoint(incident_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    db_incident = delete_incident(db, incident_id=incident_id)
    if db_incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return None

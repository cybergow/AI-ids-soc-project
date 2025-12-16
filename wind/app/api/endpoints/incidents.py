from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.session import get_db
from app.schemas.incident import Incident, IncidentCreate
from app.services.incident import get_incidents, create_incident

router = APIRouter()

@router.get("/", response_model=List[Incident])
def read_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    incidents = get_incidents(db, skip=skip, limit=limit)
    return incidents

@router.post("/", response_model=Incident, status_code=status.HTTP_201_CREATED)
def create_new_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    return create_incident(db=db, incident=incident)

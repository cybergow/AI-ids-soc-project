from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.session import get_db
from app.schemas.alert import Alert, AlertCreate
from app.services.alert import get_alerts, create_alert

router = APIRouter()

@router.get("/", response_model=List[Alert])
def read_alerts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    alerts = get_alerts(db, skip=skip, limit=limit)
    return alerts

@router.post("/", response_model=Alert, status_code=status.HTTP_201_CREATED)
def create_new_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    return create_alert(db=db, alert=alert)

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.schemas.alert import Alert, AlertCreate, AlertUpdate
from app.services.alert import get_alerts, create_alert, get_alert, update_alert, delete_alert
from app.core.rbac import require_admin_or_analyst, require_any_authenticated
from app.models.user import User

router = APIRouter()

@router.get("/", response_model=List[Alert])
def read_alerts(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
):
    alerts = get_alerts(db, skip=skip, limit=limit, status=status, severity=severity, type_=type, source=source, q=q)
    return alerts

@router.post("/", response_model=Alert, status_code=status.HTTP_201_CREATED)
def create_new_alert(alert: AlertCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    return create_alert(db=db, alert=alert)

@router.get("/{alert_id}", response_model=Alert)
def read_alert(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_any_authenticated)):
    db_alert = get_alert(db, alert_id=alert_id)
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return db_alert

@router.put("/{alert_id}", response_model=Alert)
def update_alert_endpoint(alert_id: int, alert_update: AlertUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    db_alert = update_alert(db, alert_id=alert_id, alert_update=alert_update)
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return db_alert

@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert_endpoint(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin_or_analyst)):
    db_alert = delete_alert(db, alert_id=alert_id)
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return None

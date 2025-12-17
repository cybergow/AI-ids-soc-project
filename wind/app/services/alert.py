from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import and_, or_

from app.models.alert import Alert as AlertModel
from app.schemas.alert import AlertCreate, AlertUpdate, Alert as AlertSchema

def get_alert(db: Session, alert_id: int) -> Optional[AlertModel]:
    return db.query(AlertModel).filter(AlertModel.id == alert_id).first()

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    type_: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = None,
) -> List[AlertModel]:
    query = db.query(AlertModel)
    if status:
        query = query.filter(AlertModel.status == status)
    if severity:
        query = query.filter(AlertModel.severity == severity)
    if type_:
        query = query.filter(AlertModel.type == type_)
    if source:
        query = query.filter(AlertModel.source == source)
    if q:
        search_filter = or_(
            AlertModel.title.ilike(f"%{q}%"),
            AlertModel.description.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)
    return query.offset(skip).limit(limit).all()

def create_alert(db: Session, alert: AlertCreate) -> AlertModel:
    db_alert = AlertModel(**alert.dict())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

def update_alert(db: Session, alert_id: int, alert_update: AlertUpdate) -> Optional[AlertModel]:
    db_alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not db_alert:
        return None
    update_data = alert_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_alert, field, value)
    db.commit()
    db.refresh(db_alert)
    return db_alert

def delete_alert(db: Session, alert_id: int) -> Optional[AlertModel]:
    db_alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not db_alert:
        return None
    db.delete(db_alert)
    db.commit()
    return db_alert

from sqlalchemy.orm import Session
from typing import List, Optional

from app.models.alert import Alert as AlertModel
from app.schemas.alert import AlertCreate, Alert as AlertSchema

def get_alert(db: Session, alert_id: int) -> Optional[AlertModel]:
    return db.query(AlertModel).filter(AlertModel.id == alert_id).first()

def get_alerts(db: Session, skip: int = 0, limit: int = 100) -> List[AlertModel]:
    return db.query(AlertModel).offset(skip).limit(limit).all()

def create_alert(db: Session, alert: AlertCreate) -> AlertModel:
    db_alert = AlertModel(**alert.dict())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

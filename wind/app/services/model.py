from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import or_

from app.models.model import MLModel
from app.schemas.model import ModelCreate, ModelUpdate, Model as ModelSchema

def get_model(db: Session, model_id: int) -> Optional[MLModel]:
    return db.query(MLModel).filter(MLModel.id == model_id).first()

def get_model_by_name(db: Session, name: str) -> Optional[MLModel]:
    return db.query(MLModel).filter(MLModel.name == name).first()

def get_models(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    model_type: Optional[str] = None,
    q: Optional[str] = None,
) -> List[MLModel]:
    query = db.query(MLModel)
    if status:
        query = query.filter(MLModel.status == status)
    if model_type:
        query = query.filter(MLModel.model_type == model_type)
    if q:
        search_filter = or_(
            MLModel.name.ilike(f"%{q}%"),
            MLModel.description.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)
    return query.offset(skip).limit(limit).all()

def create_model(db: Session, model: ModelCreate, created_by: Optional[int] = None) -> MLModel:
    db_model = MLModel(**model.dict(), created_by=created_by)
    db.add(db_model)
    db.commit()
    db.refresh(db_model)
    return db_model

def update_model(db: Session, model_id: int, model_update: ModelUpdate) -> Optional[MLModel]:
    db_model = db.query(MLModel).filter(MLModel.id == model_id).first()
    if not db_model:
        return None
    update_data = model_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_model, field, value)
    db.commit()
    db.refresh(db_model)
    return db_model

def delete_model(db: Session, model_id: int) -> Optional[MLModel]:
    db_model = db.query(MLModel).filter(MLModel.id == model_id).first()
    if not db_model:
        return None
    db.delete(db_model)
    db.commit()
    return db_model

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.schemas.model import Model, ModelCreate, ModelUpdate, ModelRetrainRequest, ModelRetrainResponse
from app.services.model import get_models, create_model, get_model, get_model_by_name, update_model, delete_model
from app.core.rbac import require_admin_or_analyst, require_any_authenticated
from app.models.user import User

router = APIRouter()

@router.get("/", response_model=List[Model])
def list_models(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    model_type: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
):
    models = get_models(db, skip=skip, limit=limit, status=status, model_type=model_type, q=q)
    return models

@router.post("/", response_model=Model, status_code=status.HTTP_201_CREATED)
def register_model(
    model: ModelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_analyst),
):
    existing = get_model_by_name(db, name=model.name)
    if existing:
        raise HTTPException(status_code=400, detail="Model with this name already exists")
    return create_model(db=db, model=model, created_by=current_user.id)

@router.get("/{model_id}", response_model=Model)
def get_model_detail(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
):
    db_model = get_model(db, model_id=model_id)
    if db_model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return db_model

@router.put("/{model_id}", response_model=Model)
def update_model_endpoint(
    model_id: int,
    model_update: ModelUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_analyst),
):
    db_model = update_model(db, model_id=model_id, model_update=model_update)
    if db_model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return db_model

@router.delete("/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_model_endpoint(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_analyst),
):
    db_model = delete_model(db, model_id=model_id)
    if db_model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return None

@router.post("/{model_id}/retrain", response_model=ModelRetrainResponse)
def retrain_model(
    model_id: int,
    request: Optional[ModelRetrainRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_analyst),
):
    db_model = get_model(db, model_id=model_id)
    if db_model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    # Placeholder: In a real system, this would enqueue a job and return a job ID
    # For now, we just acknowledge the request
    return ModelRetrainResponse(
        message="Model retrain request submitted (placeholder)",
        model_id=model_id,
        status="queued"
    )

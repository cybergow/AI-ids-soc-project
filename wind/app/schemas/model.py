from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from app.models.model import ModelStatus, ModelType

class ModelBase(BaseModel):
    name: str
    version: str
    description: Optional[str] = None
    model_type: ModelType
    status: ModelStatus = ModelStatus.TRAINING
    is_active: bool = True
    metadata_json: Optional[str] = None

class ModelCreate(ModelBase):
    pass

class ModelUpdate(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    model_type: Optional[ModelType] = None
    status: Optional[ModelStatus] = None
    is_active: Optional[bool] = None
    metadata_json: Optional[str] = None

class Model(ModelBase):
    id: int
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class ModelRetrainRequest(BaseModel):
    parameters: Optional[dict] = None

class ModelRetrainResponse(BaseModel):
    message: str
    model_id: int
    status: str

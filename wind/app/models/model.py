from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Enum
from sqlalchemy.orm import relationship
from app.models.base import Base
import enum
from datetime import datetime

class ModelStatus(str, enum.Enum):
    TRAINING = "training"
    READY = "ready"
    FAILED = "failed"
    DEPRECATED = "deprecated"

class ModelType(str, enum.Enum):
    CLASSIFICATION = "classification"
    ANOMALY_DETECTION = "anomaly_detection"
    REGRESSION = "regression"
    CLUSTERING = "clustering"

class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    version = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    model_type = Column(Enum(ModelType), nullable=False)
    status = Column(Enum(ModelStatus), default=ModelStatus.TRAINING, nullable=False)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    metadata_json = Column(Text, nullable=True)  # JSON string for extra config

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "model_type": self.model_type.value,
            "status": self.status.value,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "is_active": self.is_active,
            "metadata_json": self.metadata_json,
        }

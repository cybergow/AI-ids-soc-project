from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from sqlalchemy.orm import Session
from app.core.config import settings

@as_declarative()
class Base:
    id: Any
    __name__: str
    
    # Generate __tablename__ automatically
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()
    
    # Common columns
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        return {
            column.name: getattr(self, column.name)
            if not isinstance(getattr(self, column.name), datetime)
            else getattr(self, column.name).isoformat()
            for column in self.__table__.columns
        }
    
    def update(self, db: Session, **kwargs) -> None:
        """Update model instance with provided fields."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        db.commit()
        db.refresh(self)
    
    def delete(self, db: Session) -> None:
        """Delete model instance from database."""
        db.delete(self)
        db.commit()
    
    @classmethod
    def get_by_id(cls, db: Session, id: int) -> Optional[Any]:
        """Get model instance by ID."""
        return db.query(cls).filter(cls.id == id).first()
    
    @classmethod
    def get_all(cls, db: Session, skip: int = 0, limit: int = 100) -> list:
        """Get all model instances with pagination."""
        return db.query(cls).offset(skip).limit(limit).all()
    
    @classmethod
    def create(cls, db: Session, **kwargs) -> Any:
        """Create a new model instance."""
        instance = cls(**kwargs)
        db.add(instance)
        db.commit()
        db.refresh(instance)
        return instance

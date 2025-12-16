from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, String, Integer, Enum, JSON, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from app.models.base import Base
import enum

class EntityType(str, enum.Enum):
    HOST = "host"
    USER = "user"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    PROCESS = "process"
    FILE = "file"
    SERVICE = "service"

class Entity(Base):
    __tablename__ = "entities"
    
    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum(EntityType), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    name = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=True)
    entity_metadata = Column('metadata', JSON, default=dict, nullable=True)
    risk_score = Column(Integer, default=0, nullable=False)  # 0-100
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_whitelisted = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    related_alerts = relationship("AlertEntity", back_populates="entity")
    related_incidents = relationship("IncidentEntity", back_populates="entity")
    
    def __repr__(self):
        return f"<Entity(id={self.id}, type='{self.type}', value='{self.value}')>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "name": self.name,
            "description": self.description,
            "metadata": self.entity_metadata or {},
            "risk_score": self.risk_score,
            "last_seen": self.last_seen.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "is_whitelisted": self.is_whitelisted,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    def update_last_seen(self, db):
        """Update the last_seen timestamp to now."""
        self.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(self)
        return self

class EntityTag(Base):
    __tablename__ = "entity_tags"
    
    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    tag = Column(String(100), nullable=False, index=True)
    source = Column(String(100), nullable=True)  # e.g., 'user', 'system', 'import'
    
    # Relationships
    entity = relationship("Entity", backref="tags")
    
    def __repr__(self):
        return f"<EntityTag(id={self.id}, entity_id={self.entity_id}, tag='{self.tag}')>"
    
    def to_dict(self):
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "tag": self.tag,
            "source": self.source,
            "created_at": self.created_at.isoformat()
        }

from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, String, Integer, Enum, JSON, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from app.models.base import Base
import enum

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    CONTAINED = "contained"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentType(str, enum.Enum):
    MALWARE = "malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    DENIAL_OF_SERVICE = "denial_of_service"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    COMPROMISED_ACCOUNT = "compromised_account"
    CONFIGURATION_ERROR = "configuration_error"
    OTHER = "other"

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    type = Column(Enum(IncidentType), nullable=False, index=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False, index=True)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False, index=True)
    
    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # Relationships
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Impact and details
    impact = Column(String(100), nullable=True)  # e.g., "low", "medium", "high", "critical"
    business_impact = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    
    # Metadata
    tags = Column(JSON, nullable=True)  # List of tags for categorization
    custom_fields = Column(JSON, nullable=True)  # For additional custom fields
    
    # Relationships
    created_by_user = relationship("User", foreign_keys=[created_by])
    assigned_to_user = relationship("User", foreign_keys=[assigned_to])
    alerts = relationship("Alert", back_populates="incident")
    entities = relationship("IncidentEntity", back_populates="incident", cascade="all, delete-orphan")
    comments = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan")
    timeline_events = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Incident(id={self.id}, title='{self.title}', status='{self.status}')>"
    
    def to_dict(self, include_related: bool = True) -> Dict[str, Any]:
        """Convert incident to dictionary, with option to include related objects."""
        result = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "type": self.type.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "impact": self.impact,
            "detected_at": self.detected_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "contained_at": self.contained_at.isoformat() if self.contained_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "business_impact": self.business_impact,
            "root_cause": self.root_cause,
            "resolution": self.resolution,
            "tags": self.tags or [],
            "custom_fields": self.custom_fields or {},
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "alerts_count": len(self.alerts) if hasattr(self, 'alerts') else 0
        }
        
        if include_related:
            if hasattr(self, 'alerts'):
                result["alerts"] = [alert.to_dict(include_related=False) for alert in self.alerts]
            if hasattr(self, 'comments'):
                result["comments"] = [comment.to_dict() for comment in self.comments]
            if hasattr(self, 'timeline_events'):
                result["timeline_events"] = [event.to_dict() for event in sorted(
                    self.timeline_events, key=lambda x: x.occurred_at or datetime.min
                )]
            
            if hasattr(self, 'created_by_user') and self.created_by_user:
                result["created_by_user"] = {
                    "id": self.created_by_user.id,
                    "email": self.created_by_user.email,
                    "full_name": self.created_by_user.full_name
                }
                
            if hasattr(self, 'assigned_to_user') and self.assigned_to_user:
                result["assigned_to_user"] = {
                    "id": self.assigned_to_user.id,
                    "email": self.assigned_to_user.email,
                    "full_name": self.assigned_to_user.full_name
                }
        
        return result


class IncidentEntity(Base):
    """Association table for many-to-many relationship between Incident and Entity."""
    __tablename__ = "incident_entities"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(100), nullable=True)

    incident = relationship("Incident", back_populates="entities")
    entity = relationship("Entity", back_populates="related_incidents")


class IncidentComment(Base):
    """Comments on incidents for collaboration and documentation."""
    __tablename__ = "incident_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False, nullable=False)  # For internal notes vs. public comments
    
    # Relationships
    incident = relationship("Incident", back_populates="comments")
    user = relationship("User")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "content": self.content,
            "is_internal": self.is_internal,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "user": {
                "id": self.user.id,
                "email": self.user.email,
                "full_name": self.user.full_name
            } if self.user else None
        }


class IncidentTimeline(Base):
    """Timeline of events for an incident."""
    __tablename__ = "incident_timeline"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(100), nullable=False)  # e.g., 'status_change', 'comment', 'alert_added', etc.
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    occurred_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # For storing event-specific data
    timeline_metadata = Column('metadata', JSON, nullable=True)
    
    # Relationships
    incident = relationship("Incident", back_populates="timeline_events")
    user = relationship("User", foreign_keys=[created_by])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "occurred_at": self.occurred_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "metadata": self.timeline_metadata or {},
            "user": {
                "id": self.user.id,
                "email": self.user.email,
                "full_name": self.user.full_name
            } if self.user else None
        }

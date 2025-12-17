from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, String, Integer, Enum, JSON, ForeignKey, DateTime, Text, Float, Boolean
from sqlalchemy.orm import relationship
from app.models.base import Base
import enum

class AlertStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"

class AlertSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertType(str, enum.Enum):
    # Network Alerts
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_CONNECTION = "suspicious_connection"
    DATA_EXFILTRATION = "data_exfiltration"
    
    # Host-based Alerts
    SUSPICIOUS_PROCESS = "suspicious_process"
    FILE_MODIFICATION = "file_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Authentication Alerts
    FAILED_LOGIN = "failed_login"
    MULTIPLE_FAILED_LOGINS = "multiple_failed_logins"
    ACCOUNT_LOCKOUT = "account_lockout"
    
    # ML-based Alerts
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    UNUSUAL_ACTIVITY = "unusual_activity"
    
    # Custom Alerts
    CUSTOM = "custom"
    THREAT_INTEL_MATCH = "threat_intel_match"

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    type = Column(Enum(AlertType), nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN, nullable=False, index=True)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False, index=True)
    confidence = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    source = Column(String(100), nullable=False)  # e.g., 'ids', 'edr', 'ml_model', 'siem'
    source_ref = Column(String(255), nullable=True)  # Reference ID from the source system
    
    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # Relationships
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    
    # Metadata and raw data
    raw_data = Column(JSON, nullable=True)  # Original alert data
    alert_metadata = Column('metadata', JSON, nullable=True)  # Additional metadata
    
    # Relationships
    created_by_user = relationship("User", foreign_keys=[created_by])
    assigned_to_user = relationship("User", foreign_keys=[assigned_to])
    incident = relationship("Incident", back_populates="alerts")
    entities = relationship("AlertEntity", back_populates="alert")
    comments = relationship("AlertComment", back_populates="alert", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Alert(id={self.id}, type='{self.type}', status='{self.status}')>"
    
    def to_dict(self, include_related: bool = True) -> Dict[str, Any]:
        """Convert alert to dictionary, with option to include related objects."""
        result = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "type": self.type.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "source": self.source,
            "source_ref": self.source_ref,
            "metadata": self.alert_metadata or {},
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "incident_id": self.incident_id
        }
        
        if include_related:
            result["entities"] = [e.to_dict() for e in self.entities]
            result["comments"] = [c.to_dict() for c in self.comments]
            
            if self.created_by_user:
                result["created_by_user"] = {
                    "id": self.created_by_user.id,
                    "username": self.created_by_user.username,
                    "email": self.created_by_user.email
                }
                
            if self.assigned_to_user:
                result["assigned_to_user"] = {
                    "id": self.assigned_to_user.id,
                    "username": self.assigned_to_user.username,
                    "email": self.assigned_to_user.email
                }
        
        return result
    
    def acknowledge(self, user_id: int, db) -> 'Alert':
        """Mark the alert as acknowledged."""
        self.status = AlertStatus.IN_PROGRESS
        self.assigned_to = user_id
        self.acknowledged_at = datetime.utcnow()
        db.commit()
        db.refresh(self)
        return self
    
    def close(self, status: AlertStatus = AlertStatus.CLOSED, user_id: int = None) -> 'Alert':
        """Close the alert with the given status."""
        self.status = status
        self.closed_at = datetime.utcnow()
        if user_id:
            self.assigned_to = user_id
        return self

class AlertEntity(Base):
    """Association table for many-to-many relationship between Alert and Entity."""
    __tablename__ = "alert_entities"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(100), nullable=True)  # e.g., 'source', 'destination', 'target'
    
    # Relationships
    alert = relationship("Alert", back_populates="entities")
    entity = relationship("Entity", back_populates="related_alerts")
    
    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "entity_id": self.entity_id,
            "role": self.role,
            "entity": self.entity.to_dict() if self.entity else None
        }

class AlertComment(Base):
    """Comments on alerts for collaboration and documentation."""
    __tablename__ = "alert_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False, nullable=False)  # Internal notes vs. user comments
    
    # Relationships
    alert = relationship("Alert", back_populates="comments")
    user = relationship("User")
    
    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "content": self.content,
            "is_internal": self.is_internal,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "user": {
                "id": self.user.id,
                "username": self.user.username,
                "email": self.user.email
            } if self.user else None
        }

# app/models/__init__.py
from .base import Base
from .user import User
from .alert import Alert, AlertEntity, AlertComment
from .incident import Incident, IncidentEntity, IncidentComment, IncidentTimeline
from .entity import Entity
from .model import MLModel

# Import all models here to ensure they are registered with SQLAlchemy
__all__ = [
    "Base",
    "User",
    "Alert",
    "AlertEntity",
    "AlertComment",
    "Incident",
    "IncidentEntity",
    "IncidentComment",
    "IncidentTimeline",
    "Entity",
    "MLModel",
]
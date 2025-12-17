from fastapi import APIRouter
from . import auth, users, alerts, incidents, models, monitoring
api_router = APIRouter()
api_router.include_router(auth.router, prefix='/auth', tags=['Authentication'])
api_router.include_router(users.router, prefix='/users', tags=['Users'])
api_router.include_router(alerts.router, prefix='/alerts', tags=['Alerts'])
api_router.include_router(incidents.router, prefix='/incidents', tags=['Incidents'])
api_router.include_router(models.router, prefix='/models', tags=['Models'])
api_router.include_router(monitoring.router, prefix='/monitoring', tags=['Monitoring'])
__all__ = ['api_router']

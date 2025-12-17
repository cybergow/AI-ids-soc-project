from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
router = APIRouter()
@router.get('/status')
async def get_status():
    return {'status': 'monitoring working'}

import logging
from typing import Optional
from fastapi import WebSocket, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from app.core.config import settings
from app.models.user import User

async def get_current_user_ws(token: str, db: Session) -> User:
    """Get current user from WebSocket token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return user

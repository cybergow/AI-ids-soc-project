from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token, verify_password
from app.db.session import get_db
from app.models.user import User
from app.services.user import get_user_by_email, get_user_by_username

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user_by_username(db, username=username)
    if user is None:
        user = get_user_by_email(db, email=username)
    if user is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token)
    if not payload:
        raise credentials_exception

    username = payload.get("sub")
    if not username:
        raise credentials_exception

    user = get_user_by_username(db, username=username)
    if user is None:
        user = get_user_by_email(db, email=username)
    if user is None:
        raise credentials_exception

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

from typing import List, Union
from fastapi import Depends, HTTPException, status
from app.core.auth import get_current_active_user
from app.models.user import User, UserRole

def require_roles(*allowed_roles: UserRole):
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user
    return role_checker

# Common role dependencies
require_admin = require_roles(UserRole.ADMIN)
require_admin_or_analyst = require_roles(UserRole.ADMIN, UserRole.ANALYST)
require_any_authenticated = require_roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)

# app/schemas/user.py
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from app.models.user import UserRole

class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    is_active: bool = True
    role: UserRole = UserRole.VIEWER

class UserCreate(UserBase):
    password: str

class UserInDBBase(UserBase):
    id: int
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None

class User(UserInDBBase):
    pass

class UserInDB(UserInDBBase):
    hashed_password: str
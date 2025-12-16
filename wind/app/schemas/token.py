# app/schemas/token.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: list[str] = []

class TokenCreate(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime

class TokenPayload(BaseModel):
    sub: Optional[int] = None
    exp: Optional[int] = None
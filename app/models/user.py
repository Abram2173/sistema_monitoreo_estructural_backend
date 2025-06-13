from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str  # "inspector" o "supervisor"
    disabled: Optional[bool] = False
    last_activity: Optional[datetime] = None  # Nuevo campo

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    role: str
    name: str
    password: str
    last_activity: Optional[datetime] = None  # Nuevo campo
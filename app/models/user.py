from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str  # "inspector" o "supervisor"
    disabled: Optional[bool] = False

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    role: str
    name: str
    password: str
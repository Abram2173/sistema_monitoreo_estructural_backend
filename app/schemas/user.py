from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str
    role: str  # Puede ser "admin", "supervisor" o "inspector"

class UserOut(BaseModel):
    id: str
    username: str
    name: str
    email: EmailStr
    role: str
    canManageReports: Optional[bool] = None

    class Config:
        from_attributes = True
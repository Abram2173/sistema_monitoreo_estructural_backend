# app/models/status.py
from pydantic import BaseModel

class StatusCreate(BaseModel):
    structure_id: str
    status: str
    description: str

class StatusUpdate(BaseModel):
    status: str | None = None
    description: str | None = None
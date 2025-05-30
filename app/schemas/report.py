from pydantic import BaseModel
from typing import Dict, Optional

class ReportCreate(BaseModel):
    location: str
    description: str
    measurements: Dict[str, float]
    risk_level: str
    comments: Optional[str] = None

class ReportUpdate(BaseModel):
    status: Optional[str] = None
    recommendations: Optional[str] = None
    assigned_supervisor: Optional[str] = None  # Nuevo campo para asignar supervisor

class ReportOut(BaseModel):
    id: str
    inspector_id: str
    inspector_name: str
    location: str
    description: str
    measurements: Dict[str, float]
    risk_level: str
    comments: Optional[str] = None
    status: str
    created_at: str
    recommendations: Optional[str] = None
    assigned_supervisor: Optional[str] = None  # Nuevo campo para asignar supervisor
    image_path: Optional[str] = None  # Nuevo campo para la ruta de la imagen
from pydantic import BaseModel
from typing import Optional, List

class Report(BaseModel):
    inspector_id: str
    location: str
    comments: str
    risk_level: str  # "Bajo", "Medio", "Alto"
    photos: List[str]  # Lista de URLs o nombres de archivo (simulados por ahora)
    status: str = "Pendiente"  # "Pendiente", "Aprobado", "Rechazado"
    recommendations: Optional[str] = None
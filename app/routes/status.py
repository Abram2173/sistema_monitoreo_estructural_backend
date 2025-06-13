# app/routes/status.py
from fastapi import APIRouter, Depends, HTTPException
from app.config.database import status_collection
from app.dependencies.auth import get_current_user
from app.models.status import StatusCreate, StatusUpdate

router = APIRouter()

@router.post("/status")
async def create_status(status: StatusCreate, current_user: dict = Depends(get_current_user)):
    try:
        status_dict = status.dict()
        status_dict["created_by"] = current_user["email"]
        await status_collection.insert_one(status_dict)
        return {"message": "Estatus creado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def get_status(current_user: dict = Depends(get_current_user)):
    try:
        status_list = await status_collection.find().to_list(100)
        return status_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/status/{status_id}")
async def update_status(status_id: str, status: StatusUpdate, current_user: dict = Depends(get_current_user)):
    try:
        result = await status_collection.update_one(
            {"_id": status_id},
            {"$set": status.dict(exclude_unset=True)}
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Estatus no encontrado")
        return {"message": "Estatus actualizado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
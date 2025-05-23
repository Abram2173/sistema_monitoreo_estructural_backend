from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict
from app.config.database import users_collection, reports_collection
from app.dependencies.auth import get_current_admin_user
from app.models.user import UserCreate
from firebase_admin import auth as firebase_auth
from pydantic import BaseModel
from bson import ObjectId

router = APIRouter()

# Modelo para la creación de usuarios
class UserCreate(BaseModel):
    username: str
    email: str
    role: str
    name: str
    password: str

# Modelo para asignar reportes
class ReportAssign(BaseModel):
    report_id: str
    supervisor_username: str

@router.get("/admin/users", response_model=List[Dict])
async def get_all_users(current_user: dict = Depends(get_current_admin_user)):
    """
    Obtiene una lista de todos los usuarios (solo accesible para administradores).
    """
    try:
        users = []
        async for user in users_collection.find():
            user_dict = {
                "username": user.get("username"),
                "email": user.get("email"),
                "role": user.get("role"),
                "name": user.get("name")
            }
            users.append(user_dict)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los usuarios: {str(e)}")

@router.get("/admin/supervisors", response_model=List[Dict])
async def get_supervisors(current_user: dict = Depends(get_current_admin_user)):
    """
    Obtiene una lista de todos los supervisores (solo accesible para administradores).
    """
    try:
        supervisors = []
        async for user in users_collection.find({"role": "supervisor"}):
            supervisor_dict = {
                "username": user.get("username"),
                "name": user.get("name")
            }
            supervisors.append(supervisor_dict)
        return supervisors
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los supervisores: {str(e)}")

@router.post("/admin/users", response_model=Dict)
async def create_user(user: UserCreate, current_user: dict = Depends(get_current_admin_user)):
    """
    Crea un nuevo usuario (solo accesible para administradores).
    Registra el usuario en MongoDB y Firebase, y configura el custom claim 'role'.
    """
    try:
        existing_user = await users_collection.find_one({
            "$or": [{"username": user.username}, {"email": user.email}]
        })
        if existing_user:
            raise HTTPException(status_code=400, detail="El username o email ya está en uso")

        try:
            firebase_user = firebase_auth.create_user(
                email=user.email,
                password=user.password,
                display_name=user.name
            )
            # Configurar el custom claim automáticamente
            await firebase_auth.set_custom_user_claims(firebase_user.uid, {"role": user.role})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al crear el usuario en Firebase: {str(e)}")

        user_dict = {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "name": user.name
        }
        await users_collection.insert_one(user_dict)

        return {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "name": user.name
        }
    except HTTPException as e:
        try:
            firebase_auth.delete_user(firebase_user.uid)
        except:
            pass
        raise e
    except Exception as e:
        try:
            firebase_auth.delete_user(firebase_user.uid)
        except:
            pass
        raise HTTPException(status_code=500, detail=f"Error al crear el usuario: {str(e)}")

@router.delete("/admin/users/{username}")
async def delete_user(username: str, current_user: dict = Depends(get_current_admin_user)):
    """
    Elimina un usuario por su username (solo accesible para administradores).
    No permite eliminar al propio usuario administrador.
    """
    try:
        if username == current_user["username"]:
            raise HTTPException(status_code=403, detail="No puedes eliminarte a ti mismo")

        user = await users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        try:
            firebase_user = firebase_auth.get_user_by_email(user["email"])
            firebase_auth.delete_user(firebase_user.uid)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al eliminar el usuario de Firebase: {str(e)}")

        if user["role"] == "inspector":
            await reports_collection.delete_many({"inspector_id": username})

        await users_collection.delete_one({"username": username})
        return {"message": f"Usuario {username} eliminado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar el usuario: {str(e)}")

@router.post("/admin/assign-report")
async def assign_report(assignment: ReportAssign, current_user: dict = Depends(get_current_admin_user)):
    """
    Asigna un reporte a un supervisor (solo accesible para administradores).
    """
    try:
        # Verificar si el reporte existe
        report = await reports_collection.find_one({"_id": ObjectId(assignment.report_id)})
        if not report:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")

        # Verificar si el supervisor existe y tiene el rol correcto
        supervisor = await users_collection.find_one({"username": assignment.supervisor_username})
        if not supervisor:
            raise HTTPException(status_code=404, detail="Supervisor no encontrado")
        if supervisor["role"] != "supervisor":
            raise HTTPException(status_code=400, detail="El usuario no es un supervisor")

        # Asignar el reporte al supervisor
        await reports_collection.update_one(
            {"_id": ObjectId(assignment.report_id)},
            {"$set": {"assigned_supervisor": assignment.supervisor_username}}
        )

        return {"message": f"Reporte {assignment.report_id} asignado a {assignment.supervisor_username}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al asignar el reporte: {str(e)}")
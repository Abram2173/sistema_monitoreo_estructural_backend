from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.responses import StreamingResponse
from app.config.database import reports_collection, users_collection
from app.schemas.report import ReportCreate, ReportUpdate, ReportOut
from app.dependencies.auth import get_current_inspector_or_supervisor_user, get_current_user_with_report_access, get_current_admin_user
from datetime import datetime
from typing import List, Dict, Optional
from bson import ObjectId
import json
import io

router = APIRouter()

@router.post("/reports", response_model=ReportOut)
async def create_report(
    location: str = File(...),
    description: str = File(...),
    measurements: str = File(...),
    risk_level: str = File(...),
    comments: Optional[str] = File(None),
    image: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_inspector_or_supervisor_user)
):
    try:
        inspector_email = current_user["username"]
        print(f"Inspector Email: {inspector_email}")

        user = await users_collection.find_one({"email": inspector_email})
        if not user:
            print(f"Usuario no encontrado: {inspector_email}")
            raise HTTPException(status_code=404, detail="Inspector no encontrado en la base de datos")
        
        inspector_id = user["username"]
        inspector_name = user.get("name", inspector_id)
        print(f"Inspector ID: {inspector_id}, Inspector Name: {inspector_name}")

        # Validar risk_level
        valid_risk_levels = ["bajo", "medio", "alto"]
        if risk_level.lower() not in valid_risk_levels:
            raise HTTPException(status_code=400, detail=f"risk_level debe ser uno de {valid_risk_levels}")

        # Parsear measurements
        try:
            measurements_dict = json.loads(measurements)
            if not isinstance(measurements_dict, dict):
                raise ValueError("measurements debe ser un objeto JSON")
        except json.JSONDecodeError as e:
            print(f"Error al parsear measurements: {str(e)}")
            raise HTTPException(status_code=400, detail="Formato de measurements inválido")

        # Procesar la imagen
        image_data = None
        content_type = None
        if image:
            file_extension = image.filename.split(".")[-1].lower()
            if file_extension not in ["jpg", "jpeg", "png"]:
                raise HTTPException(status_code=400, detail="Solo se permiten imágenes JPG o PNG")
            if image.size > 5 * 1024 * 1024:  # Límite de 5MB
                raise HTTPException(status_code=400, detail="La imagen no puede superar 5MB")
            
            image_data = await image.read()
            content_type = image.content_type
            print(f"Imagen procesada: {len(image_data)} bytes, tipo: {content_type}")

        # Crear el diccionario del reporte
        report_dict = {
            "location": location,
            "description": description,
            "measurements": measurements_dict,
            "risk_level": risk_level.lower(),
            "comments": comments,
            "inspector_id": inspector_id,
            "inspector_name": inspector_name,
            "status": "Pendiente",
            "created_at": datetime.utcnow().isoformat(),
            "assigned_supervisor": None,
            "image_data": image_data,  # Datos binarios de la imagen
            "content_type": content_type  # Tipo de contenido (ej. image/jpeg)
        }
        print(f"Reporte a insertar: {report_dict}")

        result = await reports_collection.insert_one(report_dict)

        response_dict = report_dict.copy()
        response_dict["id"] = str(result.inserted_id)
        response_dict["recommendations"] = None
        response_dict.pop("image_data", None)  # No devolver datos binarios en la respuesta
        response_dict.pop("content_type", None)

        print(f"Reporte insertado con ID: {response_dict['id']}")
        print(f"Datos de respuesta: {response_dict}")

        return ReportOut(**response_dict)
    except HTTPException as e:
        print(f"Error HTTP: {str(e)}")
        raise e
    except Exception as e:
        print(f"Error al crear el reporte: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")

@router.get("/reports", response_model=List[ReportOut])
async def get_reports(
    current_user: dict = Depends(get_current_user_with_report_access)
):
    try:
        reports = []
        if current_user["role"] == "inspector":
            user = await users_collection.find_one({"email": current_user["username"]})
            if not user:
                print(f"Usuario no encontrado: {current_user['username']}")
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            inspector_id = user["username"]
            print(f"Obteniendo reportes para inspector: {inspector_id}")
            cursor = reports_collection.find({"inspector_id": inspector_id})
        elif current_user["role"] == "supervisor":
            print(f"Obteniendo reportes para supervisor: {current_user['username']}")
            cursor = reports_collection.find({"assigned_supervisor": current_user["username"]})
        else:  # Admin
            print("Obteniendo todos los reportes (admin)")
            cursor = reports_collection.find()

        async for report in cursor:
            report_dict = {
                "id": str(report["_id"]),
                "inspector_id": str(report.get("inspector_id", "")),
                "inspector_name": str(report.get("inspector_name", "")),
                "location": str(report.get("location", "")),
                "description": str(report.get("description", "")),
                "measurements": report.get("measurements", {}),
                "risk_level": str(report.get("risk_level", "")),
                "comments": report.get("comments"),
                "status": str(report.get("status", "Pendiente")),
                "created_at": str(report.get("created_at", "")),
                "recommendations": report.get("recommendations"),
                "assigned_supervisor": report.get("assigned_supervisor"),
                "image_path": f"/api/reports/{str(report['_id'])}/image" if report.get("image_data") else None
            }
            print(f"Reporte procesado: {report_dict}")
            reports.append(ReportOut(**report_dict))
        
        print(f"Reportes devueltos: {len(reports)}")
        return reports
    except Exception as e:
        print(f"Error al obtener los reportes: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al obtener los reportes: {str(e)}")

@router.get("/reports/{report_id}/image")
async def get_report_image(report_id: str):
    try:
        report = await reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
        
        image_data = report.get("image_data")
        content_type = report.get("content_type", "image/jpeg")

        if not image_data:
            raise HTTPException(status_code=404, detail="El reporte no tiene una imagen")

        return StreamingResponse(io.BytesIO(image_data), media_type=content_type)
    except Exception as e:
        print(f"Error al obtener la imagen: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al obtener la imagen: {str(e)}")

@router.put("/reports/{report_id}", response_model=ReportOut)
async def update_report(
    report_id: str,
    update_data: ReportUpdate,
    current_user: dict = Depends(get_current_user_with_report_access)
):
    try:
        if current_user["role"] != "supervisor":
            print(f"Error: {current_user['username']} no es supervisor (rol: {current_user['role']})")
            raise HTTPException(status_code=403, detail="Only supervisors can update reports")

        report = await reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            print(f"Reporte no encontrado: {report_id}")
            raise HTTPException(status_code=404, detail="Report not found")

        if report.get("assigned_supervisor") != current_user["username"]:
            print(f"Error: {current_user['username']} no está asignado al reporte {report_id}")
            raise HTTPException(status_code=403, detail="No estás asignado a este reporte")

        update_dict = update_data.dict(exclude_unset=True)
        if "status" in update_dict and update_dict["status"] not in ["Aprobado", "Rechazado"]:
            raise HTTPException(status_code=400, detail="El estado debe ser 'Aprobado' o 'Rechazado'")
        print(f"Actualizando reporte {report_id} con datos: {update_dict}")

        await reports_collection.update_one(
            {"_id": ObjectId(report_id)},
            {"$set": update_dict}
        )

        updated_report = await reports_collection.find_one({"_id": ObjectId(report_id)})
        report_dict = {
            "id": str(updated_report["_id"]),
            "inspector_id": str(updated_report.get("inspector_id", "")),
            "inspector_name": str(updated_report.get("inspector_name", "")),
            "location": str(updated_report.get("location", "")),
            "description": str(updated_report.get("description", "")),
            "measurements": updated_report.get("measurements", {}),
            "risk_level": str(updated_report.get("risk_level", "")),
            "comments": updated_report.get("comments"),
            "status": str(updated_report.get("status", "Pendiente")),
            "created_at": str(updated_report.get("created_at", "")),
            "recommendations": updated_report.get("recommendations"),
            "assigned_supervisor": updated_report.get("assigned_supervisor"),
            "image_path": f"/api/reports/{str(updated_report['_id'])}/image" if updated_report.get("image_data") else None
        }

        print(f"Reporte actualizado: {report_dict}")
        return ReportOut(**report_dict)
    except Exception as e:
        print(f"Error al actualizar el reporte: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al actualizar el reporte: {str(e)}")

@router.delete("/reports/{report_id}")
async def delete_report(report_id: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        report = await reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            print(f"Reporte no encontrado: {report_id}")
            raise HTTPException(status_code=404, detail="Reporte no encontrado")

        await reports_collection.delete_one({"_id": ObjectId(report_id)})
        print(f"Reporte {report_id} eliminado de MongoDB")

        return {"message": f"Reporte {report_id} eliminado exitosamente"}
    except Exception as e:
        print(f"Error al eliminar el reporte: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al eliminar el reporte: {str(e)}")
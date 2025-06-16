from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
import os
import base64
import json
import time
import secrets
from typing import List, Optional
from pydantic import BaseModel
import asyncio
from app.config.database import users_collection
from datetime import datetime
import requests
from PIL import Image
import numpy as np
import io
import uuid

app = FastAPI(
    title="Sistema de Monitoreo Estructural",
    description="API para gestionar reportes de monitoreo estructural con autenticación de usuarios e IA básica.",
    version="1.0.0"
)

# Middleware para medir el tiempo de las solicitudes
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    print(f"Tiempo de procesamiento para {request.url}: {process_time:.2f} segundos")
    response.headers["X-Process-Time"] = str(process_time)
    return response

print("Iniciando la aplicación...")

# Inicializar Firebase Admin SDK
firebase_credentials = os.getenv("FIREBASE_CREDENTIALS")
if not firebase_admin._apps:
    if not firebase_credentials:
        print("FIREBASE_CREDENTIALS no está configurado en las variables de entorno")
        raise Exception("FIREBASE_CREDENTIALS no está configurado en las variables de entorno")
    try:
        print("Decodificando FIREBASE_CREDENTIALS...")
        decoded_credentials = base64.b64decode(firebase_credentials).decode('utf-8')
        print("FIREBASE_CREDENTIALS decodificado correctamente")
        cred_data = json.loads(decoded_credentials)
        required_fields = ["type", "project_id", "private_key_id", "private_key", "client_email", "client_id"]
        if not all(field in cred_data for field in required_fields):
            raise ValueError("Credenciales de Firebase incompletas o inválidas")
        cred = credentials.Certificate(cred_data)
        print("Inicializando Firebase Admin SDK...")
        firebase_admin.initialize_app(cred, {'storageBucket': 'loginfirebase-3585d.appspot.com'})
        print("Firebase Admin SDK inicializado correctamente")
    except Exception as e:
        print(f"Error al inicializar Firebase Admin SDK: {str(e)}")
        raise Exception(f"Error al inicializar Firebase Admin SDK: {str(e)}")

# Configurar CORS para permitir solicitudes desde el frontend
origins = [
    "http://localhost:3000",
    "https://eclectic-frangipane-39ee69.netlify.app",
    "https://monitoreoestructural.net",
    "https://www.monitoreoestructural.net"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo para los datos de usuario
class UserRequest(BaseModel):
    username: str
    name: str
    email: str
    role: str
    password: str

# Modelo para los datos de reporte
class ReportRequest(BaseModel):
    location: str
    description: str
    measurements: dict
    risk_level: str
    comments: Optional[str] = None

# Modelo para los datos de análisis de imágenes
class ImageAnalysisRequest(BaseModel):
    image_urls: Optional[List[str]] = None
    files: Optional[List[UploadFile]] = None

# Dependencia para obtener el usuario autenticado
async def get_current_user(authorization: str = Header(None)):
    uid = None
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Token de autenticación no proporcionado o inválido")
        token = authorization.split("Bearer ")[1]
        print(f"Token extraído del encabezado (completo): {token}")  # Depuración completa
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        role = decoded_token.get('custom_claims', {}).get('role', 'user')
        print(f"Token decodificado - UID: {uid}, Role: {role}")  # Depuración
        return {"uid": uid, "role": role}
    except firebase_auth.InvalidIdTokenError as e:
        print(f"Error al validar el token: {str(e)} - Token: {token[:50]}...")  # Depuración
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        print(f"Error al verificar el token: {str(e)} - Token: {token[:50]}...")  # Depuración
        raise HTTPException(status_code=500, detail=f"Error al verificar el token: {str(e)}")
    finally:
        if uid is None:
            raise HTTPException(status_code=401, detail="No se pudo obtener el UID del token")

# Función para asegurar que el administrador exista en Firebase Authentication
def ensure_admin_user():
    try:
        print("Verificando si existe admin@example.com...")
        user = firebase_auth.get_user_by_email("admin@example.com")
        print("Usuario administrador ya existe:", user.email)
        if 'role' not in (user.custom_claims or {}):
            firebase_auth.set_custom_user_claims(user.uid, {'role': 'admin'})
            print("Asignado custom claim 'role: admin' al usuario")
    except firebase_auth.UserNotFoundError:
        print("Creando usuario administrador...")
        admin_password = secrets.token_urlsafe(16)
        print(f"Contraseña generada para admin: {admin_password}")
        user = firebase_auth.create_user(
            email="admin@example.com",
            password=admin_password,
            email_verified=True
        )
        firebase_auth.set_custom_user_claims(user.uid, {'role': 'admin'})
        print("Usuario administrador creado: admin@example.com")
    except Exception as e:
        print(f"Error al verificar/crear administrador: {str(e)}")
        raise Exception(f"Error al verificar/crear administrador: {str(e)}")

async def update_users_last_activity():
    print("Iniciando actualización de last_activity para usuarios existentes...")
    async for user in users_collection.find():
        if "last_activity" not in user or not user["last_activity"]:
            await users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_activity": datetime.utcnow().isoformat() + "+00:00"}}
            )
            print(f"Actualizado last_activity para {user['username']}")
    print("Actualización completada.")

@app.on_event("startup")
async def startup_event():
    print("Ejecutando evento de startup...")
    ensure_admin_user()
    if os.getenv("INITIAL_UPDATE_DONE", "false") == "false":
        await update_users_last_activity()
        os.environ["INITIAL_UPDATE_DONE"] = "true"
    print("Evento de startup completado")

# Incluir las rutas de los diferentes módulos
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api/admin", tags=["Administración"])

# Endpoint para análisis de imágenes con IA
@app.post("/api/analyze_images")
async def analyze_images(token: dict = Depends(get_current_user), request_data: ImageAnalysisRequest = None):
    uid = token["uid"] if token else None
    try:
        print(f"Token recibido en /api/analyze_images: {token}")
        print(f"Datos recibidos en /api/analyze_images: {request_data.dict() if request_data else None}")
        # Validar que se envíen datos
        if not request_data.files and not request_data.image_urls:
            raise HTTPException(status_code=400, detail="Se requieren archivos o URLs de imágenes")
        if (request_data.files and len(request_data.files) > 2) or (request_data.image_urls and len(request_data.image_urls) > 2):
            raise HTTPException(status_code=400, detail="Se permiten máximo 2 imágenes o URLs")

        image_content = None
        if request_data.files and request_data.files[0]:
            image_content = await request_data.files[0].read()
        elif request_data.image_urls and request_data.image_urls[0]:
            try:
                response = requests.get(request_data.image_urls[0], timeout=10)
                response.raise_for_status()
                image_content = response.content
                print(f"Imagen descargada, tamaño: {len(image_content)} bytes")
            except requests.RequestException as e:
                raise HTTPException(status_code=400, detail=f"Error al descargar la imagen desde URL: {str(e)}")

        if not image_content:
            raise HTTPException(status_code=400, detail="No se proporcionó una imagen válida")

        # Análisis básico con Pillow y numpy
        try:
            image = Image.open(io.BytesIO(image_content))
            print(f"Imagen abierta con éxito, formato: {image.format}, tamaño: {image.size}")
            image_array = np.array(image.convert('L'))  # Convertir a escala de grises
            print(f"Imagen convertida a escala de grises, forma: {image_array.shape}")
            contrast = np.std(image_array)  # Desviación estándar como medida de contraste
            print(f"Contraste calculado: {contrast}")
            has_crack = bool(contrast > 50)  # Convertir a bool nativo de Python
            evaluation = f"Análisis básico: {'posibles grietas o daños detectados' if has_crack else 'ningún daño evidente detectado'} (contraste: {contrast:.2f})"
            recommendation = f"Acción: {'revisar manualmente para confirmar daño' if has_crack else 'continuar monitoreo rutinario'}"
            description = (
                f"Descripción: La imagen muestra una estructura con un contraste de {contrast:.2f}. "
                f"{'Se observan variaciones que podrían indicar grietas o daños; se recomienda una inspección detallada.' if has_crack else 'La superficie parece uniforme sin indicios claros de daño; el monitoreo rutinario es suficiente.'}"
            )
            print(f"Evaluación: {evaluation}, Recomendación: {recommendation}, Descripción: {description}")
        except ValueError as ve:
            raise HTTPException(status_code=500, detail=f"Error de formato de imagen: {str(ve)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al procesar la imagen: {str(e)}")

        # Actualizar el reporte con el resultado de la IA
        if request_data.image_urls and request_data.image_urls[0]:
            report_id = request_data.image_urls[0].split('/api/reports/')[1].split('/')[0]  # Extraer ID del reporte
            await users_collection.update_one(
                {"report_id": report_id},
                {"$set": {"data.evaluation": evaluation, "data.has_crack": has_crack, "data.recommendation": recommendation, "data.description": description}}
            )
            print(f"Reporte {report_id} actualizado con análisis: {evaluation}, recomendación: {recommendation}, descripción: {description}")

        return {"evaluation": evaluation, "has_crack": has_crack, "recommendation": recommendation, "description": description}
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al analizar imágenes: {str(e)}")
    finally:
        if uid:
            user_ref = firestore.client().collection('users').document(uid)
            user_ref.set({'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
            await users_collection.update_one({"_id": uid}, {"$set": {"last_seen": datetime.utcnow().isoformat() + "+00:00"}}, upsert=True)

# Endpoint para obtener usuarios (solo para administradores)
@app.get("/api/admin/users")
async def get_users(token: dict = Depends(get_current_user)):
    try:
        if token["role"] != "admin":
            raise HTTPException(status_code=403, detail="Solo administradores pueden ver la lista de usuarios")
        users = []
        async for user in users_collection.find():
            user_data = {
                "username": user.get("username"),
                "name": user.get("name"),
                "email": user.get("email"),
                "role": user.get("role")
            }
            users.append(user_data)
        return users
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener usuarios: {str(e)}")

# Endpoint para eliminar usuario (solo para administradores)
@app.delete("/api/admin/users/{username}")
async def delete_user(username: str, token: dict = Depends(get_current_user)):
    try:
        if token["role"] != "admin":
            raise HTTPException(status_code=403, detail="Solo administradores pueden eliminar usuarios")
        existing_user = await users_collection.find_one({"username": username})
        if not existing_user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Eliminar usuario de Firebase Authentication
        firebase_user = firebase_auth.get_user_by_email(existing_user["email"])
        firebase_auth.delete_user(firebase_user.uid)
        # Eliminar de MongoDB
        await users_collection.delete_one({"username": username})
        print(f"Usuario {username} eliminado exitosamente")
        return {"message": f"Usuario {username} eliminado exitosamente"}
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en Firebase")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar usuario: {str(e)}")

# Endpoint para crear usuario manualmente (solo para administradores)
@app.post("/api/admin/users")
async def create_user(token: dict = Depends(get_current_user), user: UserRequest = None):
    try:
        if token["role"] != "admin":
            raise HTTPException(status_code=403, detail="Solo administradores pueden crear usuarios")
        if not user:
            raise HTTPException(status_code=400, detail="Se requieren datos del usuario")
        # Verificar si el usuario ya existe
        existing_user = await users_collection.find_one({"username": user.username})
        if existing_user:
            raise HTTPException(status_code=400, detail="El username ya está en uso")
        existing_email = await users_collection.find_one({"email": user.email})
        if existing_email:
            raise HTTPException(status_code=400, detail="El email ya está en uso")
        # Crear usuario en Firebase Authentication
        new_user = firebase_auth.create_user(
            email=user.email,
            password=user.password,
            display_name=user.name
        )
        # Asignar rol
        firebase_auth.set_custom_user_claims(new_user.uid, {"role": user.role})
        # Guardar en MongoDB
        await users_collection.insert_one({
            "username": user.username,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "last_activity": datetime.utcnow().isoformat() + "+00:00"
        })
        print(f"Usuario {user.username} creado exitosamente con email {user.email}")
        return {"message": f"Usuario {user.username} creado exitosamente", "user": {"username": user.username, "name": user.name, "email": user.email, "role": user.role}}
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear usuario: {str(e)}")

# Endpoint para obtener reportes
@app.get("/api/reports")
async def get_reports(token: dict = Depends(get_current_user), assigned_supervisor: Optional[str] = None):
    try:
        print(f"Token recibido en /api/reports: {token}")
        email = firebase_auth.get_user(token["uid"]).email
        print(f"Email extraído del token: {email}")
        role = token["role"]
        print(f"Rol extraído para {email}: {role}")
        print(f"Verificando acceso a reportes para {email}, rol: {role}")

        if role not in ["supervisor", "admin"]:
            raise HTTPException(status_code=403, detail="Acceso denegado. Solo supervisores y administradores pueden ver reportes.")

        query = {}
        if assigned_supervisor:
            query["data.assigned_supervisor"] = assigned_supervisor
        elif role == "supervisor":
            query["data.assigned_supervisor"] = email

        print(f"Obteniendo reportes para supervisor: {email if role == 'supervisor' else assigned_supervisor}")
        reports = []
        async for report in users_collection.find(query):
            report_data = report.get("data", {})
            report_data["id"] = report["report_id"]
            report_data["inspector_id"] = report["inspector_id"]
            report_data["inspector_name"] = await get_inspector_name(report["inspector_id"])  # Función hipotética
            reports.append(report_data)
            print(f"Reporte procesado: {report_data}")
        print(f"Reportes devueltos: {len(reports)}")
        return reports
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener reportes: {str(e)}")

# Endpoint para subir reportes
@app.post("/api/reports")
async def create_report(token: dict = Depends(get_current_user), report: ReportRequest = None, files: List[UploadFile] = File(None)):
    uid = token["uid"] if token else None
    try:
        # Verificar permisos
        if not uid or token["role"] not in ['inspector', 'admin']:
            raise HTTPException(status_code=403, detail="Solo inspectores o administradores pueden crear reportes")

        if not report or not files:
            raise HTTPException(status_code=400, detail="Se requieren datos del reporte y al menos una imagen")
        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        # Procesar el reporte
        report_data = report.dict()
        report_data["id"] = str(uuid.uuid4())
        report_data["inspector_id"] = uid
        report_data["created_at"] = datetime.utcnow().isoformat() + "+00:00"
        report_data["status"] = "Pendiente"

        # Guardar en MongoDB
        await users_collection.insert_one({
            "report_id": report_data["id"],
            "inspector_id": uid,
            "data": report_data,
            "files": [file.filename for file in files]
        })
        print(f"Reporte recibido: {report_data}")
        for file in files:
            print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

        # Actualizar estado del usuario
        user_ref = firestore.client().collection('users').document(uid)
        user_ref.set({'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
        await users_collection.update_one({"_id": uid}, {"$set": {"status": "active", "last_seen": datetime.utcnow().isoformat() + "+00:00"}}, upsert=True)

        return {"success": True, "message": "Reporte creado exitosamente", "id": report_data["id"]}
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")
    finally:
        if uid:
            user_ref = firestore.client().collection('users').document(uid)
            user_ref.set({'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
            await users_collection.update_one({"_id": uid}, {"$set": {"last_seen": datetime.utcnow().isoformat() + "+00:00"}}, upsert=True)

# Función hipotética para obtener el nombre del inspector (ajustar según tu implementación)
async def get_inspector_name(inspector_id):
    # Implementa esta lógica según tu base de datos
    return "Juan"  # Ejemplo

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
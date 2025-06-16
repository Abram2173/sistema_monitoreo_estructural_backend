from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends
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
from google.cloud import vision
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

# Inicializar Google Cloud Vision con depuración
client = None
google_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if google_credentials:
    try:
        print("Intentando inicializar Google Cloud Vision con credenciales...")
        if google_credentials.startswith("ew"):
            decoded_credentials = base64.b64decode(google_credentials).decode('utf-8')
            cred_data = json.loads(decoded_credentials)
            with open("temp_credentials.json", "w") as f:
                json.dump(cred_data, f)
            client = vision.ImageAnnotatorClient.from_service_account_json("temp_credentials.json")
            os.remove("temp_credentials.json")
        else:
            client = vision.ImageAnnotatorClient.from_service_account_json(google_credentials)
        print("Google Cloud Vision inicializado correctamente")
    except Exception as e:
        print(f"Error al inicializar Google Cloud Vision: {str(e)}. Usando simulación de IA.")
else:
    print("GOOGLE_APPLICATION_CREDENTIALS no está configurado o es inválido. Usando simulación de IA.")

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

# Modelo para los datos de reporte
class ReportRequest(BaseModel):
    location: str
    description: str
    measurements: dict
    risk_level: str
    comments: Optional[str] = None

# Dependencia para obtener el usuario autenticado
async def get_current_user(token: str = Depends(lambda: None)):
    uid = None
    try:
        if not token:
            raise HTTPException(status_code=401, detail="Token de autenticación requerido")
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        role = decoded_token.get('custom_claims', {}).get('role', 'user')
        return {"uid": uid, "role": role}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
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
app.include_router(admin.router, prefix="/api", tags=["Administración"])

# Fragmento relevante de main.py (endpoint /api/analyze_images)
@app.post("/api/analyze_images")
async def analyze_images(token: dict = Depends(get_current_user), files: List[UploadFile] = File(None), image_urls: List[str] = None):
    uid = token["uid"] if token else None
    try:
        # Validar que se envíen datos
        if not files and not image_urls:
            raise HTTPException(status_code=400, detail="Se requieren archivos o URLs de imágenes")
        if (files and len(files) > 2) or (image_urls and len(image_urls) > 2):
            raise HTTPException(status_code=400, detail="Se permiten máximo 2 imágenes o URLs")

        image_content = None
        if files and files[0]:
            image_content = await files[0].read()
        elif image_urls and image_urls[0]:
            try:
                response = requests.get(image_urls[0], timeout=10, headers={'Authorization': f'Bearer {token["uid"]}' if token else ''})
                response.raise_for_status()
                image_content = response.content
            except requests.RequestException as e:
                raise HTTPException(status_code=400, detail=f"Error al descargar la imagen desde URL: {str(e)}")

        if not image_content:
            raise HTTPException(status_code=400, detail="No se proporcionó una imagen válida")

        # Análisis con Google Cloud Vision si está disponible
        if client:
            try:
                image = vision.Image(content=image_content)
                response = client.label_detection(image=image)
                labels = [label.description.lower() for label in response.label_annotations]
                has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
                evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error al procesar la imagen con Google Cloud Vision: {str(e)}")
        else:
            evaluation = "Simulación de IA: Análisis no disponible (Google Cloud Vision no configurado)"
            has_crack = False

        # Actualizar estado del usuario
        if uid:
            user_ref = firestore.client().collection('users').document(uid)
            user_ref.set({'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
            await users_collection.update_one({"_id": uid}, {"$set": {"status": "active", "last_seen": datetime.utcnow().isoformat() + "+00:00"}}, upsert=True)

        return {"evaluation": evaluation, "has_crack": has_crack}
    except HTTPException as http_err:
        raise http_err
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno al analizar imágenes: {str(e)}")
    finally:
        if uid:
            user_ref = firestore.client().collection('users').document(uid)
            user_ref.set({'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
            await users_collection.update_one({"_id": uid}, {"$set": {"last_seen": datetime.utcnow().isoformat() + "+00:00"}}, upsert=True)

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

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
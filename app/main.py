import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import os
import base64
import json
import time
import secrets
import uuid
from typing import List, Optional
from pydantic import BaseModel
from google.cloud import vision
import requests
from fastapi.security import OAuth2PasswordBearer
from app.image_analyzer import analyze_image, get_image_content_from_url

# Inicializar Firebase globalmente antes de cualquier otra cosa
firebase_credentials = os.getenv("FIREBASE_CREDENTIALS")
if not firebase_admin._apps:
    if not firebase_credentials:
        print("FIREBASE_CREDENTIALS no está configurado en las variables de entorno")
        raise Exception("FIREBASE_CREDENTIALS no está configurado")
    try:
        print("Decodificando FIREBASE_CREDENTIALS...")
        decoded_credentials = base64.b64decode(firebase_credentials).decode('utf-8')
        print("FIREBASE_CREDENTIALS decodificado correctamente")
        cred_data = json.loads(decoded_credentials)
        required_fields = ["type", "project_id", "private_key_id", "private_key", "client_email", "client_id"]
        if not all(field in cred_data for field in required_fields):
            raise ValueError("Credenciales de Firebase incompletas o inválidas")
        cred = credentials.Certificate(cred_data)
        firebase_admin.initialize_app(cred, {
            'projectId': cred_data['project_id'],
            'storageBucket': f"{cred_data['project_id']}.appspot.com"
        })
        print("Firebase Admin SDK inicializado correctamente")
    except Exception as e:
        print(f"Error al inicializar Firebase Admin SDK: {str(e)}")
        raise Exception(f"Error al inicializar Firebase Admin SDK: {str(e)}")

# Inicializar Firestore globalmente
db = firestore.client()

app = FastAPI(
    title="Sistema de Monitoreo Estructural",
    description="API para gestionar reportes de monitoreo estructural con autenticación de usuarios e IA básica.",
    version="1.0.0"
)

# Definir la URL base de la aplicación
BASE_URL = "https://sistema-monitoreo-backend-2d6d5d68221a.herokuapp.com"

# Configuración de OAuth2 para autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

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
    evaluation: Optional[str] = None
    has_crack: Optional[bool] = None

# Función para asegurar que el administrador exista en Firebase Authentication
def ensure_admin_user():
    try:
        print("Verificando si existe admin@example.com...")
        user = firebase_admin.auth.get_user_by_email("admin@example.com")
        print("Usuario administrador ya existe:", user.email)
        # Asegurarse de que el admin tenga el custom claim
        if 'admin' not in (user.custom_claims or {}):
            firebase_admin.auth.set_custom_user_claims(user.uid, {'admin': True, 'role': 'admin'})
            print("Asignado custom claim 'admin' y 'role: admin' al usuario")
            print("Nota: El usuario debe refrescar su token para aplicar los nuevos claims")
    except firebase_admin.auth.UserNotFoundError:
        print("Creando usuario administrador...")
        admin_password = secrets.token_urlsafe(16)
        print(f"Contraseña generada para admin: {admin_password}")  # Quitar en producción
        user = firebase_admin.auth.create_user(
            email="admin@example.com",
            password=admin_password,
            email_verified=True
        )
        firebase_admin.auth.set_custom_user_claims(user.uid, {'admin': True, 'role': 'admin'})
        print("Usuario administrador creado: admin@example.com con claims 'admin' y 'role: admin'")
    except Exception as e:
        print(f"Error al verificar/crear administrador: {str(e)}")
        raise Exception(f"Error al verificar/crear administrador: {str(e)}")

@app.on_event("startup")
async def startup_event():
    print("Ejecutando evento de startup...")
    ensure_admin_user()
    print("Evento de startup completado")

# Incluir las rutas de los diferentes módulos
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api", tags=["Administración"])

# Inicializar cliente de Google Cloud Vision con verificación
google_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if not google_credentials:
    print("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
    raise Exception("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
try:
    if google_credentials.startswith("ew"):  # Suponiendo base64
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
    print(f"Error al inicializar Google Cloud Vision: {str(e)}")
    raise Exception(f"Error al inicializar Google Cloud Vision: {str(e)}")

# Dependency para obtener el rol del usuario
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_admin.auth.verify_id_token(token)
        uid = decoded_token['uid']
        user = firebase_admin.auth.get_user(uid)
        role = user.custom_claims.get('role', 'user') if user.custom_claims else 'user'
        return {"uid": uid, "role": role}
    except firebase_admin.auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")

# Endpoint para análisis de imágenes
@app.post("/api/analyze_images")
async def analyze_images(current_user=Depends(get_current_user), files: list[UploadFile] = File(None), image_urls: list[str] = None):
    uid = current_user["uid"]
    role = current_user["role"]
    print(f"Usuario autenticado: {uid}, rol: {role}")

    user_ref = db.collection('users').document(uid)
    user_ref.set({'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

    if not files and not image_urls:
        raise HTTPException(status_code=400, detail="Se requieren archivos o URLs de imágenes")
    if files and len(files) > 2:
        raise HTTPException(status_code=400, detail="Se permiten máximo 2 imágenes")
    if image_urls and len(image_urls) > 2:
        raise HTTPException(status_code=400, detail="Se permiten máximo 2 URLs de imágenes")

    image_content = None
    if files and files[0]:
        image_content = await files[0].read()
        print(f"Procesando archivo: {files[0].filename}, tamaño: {len(image_content)} bytes")
    elif image_urls and image_urls[0]:
        headers = {'Authorization': f'Bearer {oauth2_scheme}'}
        image_content = get_image_content_from_url(f"{BASE_URL}{image_urls[0]}", headers)

    if not image_content:
        raise HTTPException(status_code=400, detail="No se proporcionó una imagen válida")

    result = analyze_image(image_content)
    return result

# Endpoint para obtener estado de usuarios
@app.get("/api/users/status")
async def get_user_status(current_user=Depends(get_current_user)):
    uid = current_user["uid"]
    role = current_user["role"]
    print(f"Usuario autenticado: {uid}, rol: {role}")

    if 'admin' not in (firebase_admin.auth.get_user(uid).custom_claims or {}):
        raise HTTPException(status_code=403, detail="Solo administradores pueden ver el estado de usuarios")

    users_ref = db.collection('users')
    users = users_ref.get()
    status_list = []
    for user_doc in users:
        user_data = user_doc.to_dict()
        status_list.append({
            'uid': user_doc.id,
            'email': user_data.get('email', ''),
            'status': user_data.get('status', 'inactive'),
            'last_seen': user_data.get('last_seen', None)
        })
    return status_list or []

# Endpoint para subir reportes
@app.post("/api/reports")
async def create_report(report: ReportRequest, files: list[UploadFile] = File(...), current_user=Depends(get_current_user)):
    uid = current_user["uid"]
    role = current_user["role"]
    print(f"Usuario autenticado: {uid}, rol: {role}")

    if role not in ['inspector', 'admin']:
        raise HTTPException(status_code=403, detail="Solo inspectores o administradores pueden crear reportes")

    user_ref = db.collection('users').document(uid)
    user_ref.set({'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

    if len(files) != 2:
        raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

    image_content = await files[0].read()
    image = vision.Image(content=image_content)
    response = client.label_detection(image=image)
    labels = [label.description.lower() for label in response.label_annotations]
    has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
    evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")

    updated_report = report.dict()
    updated_report["evaluation"] = evaluation
    updated_report["has_crack"] = has_crack
    updated_report["id"] = str(uuid.uuid4())
    updated_report["inspector_id"] = uid

    print(f"Reporte recibido: {updated_report}")
    for file in files:
        print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

    return {"success": True, "message": "Reporte creado exitosamente", "evaluation": evaluation, "has_crack": has_crack, "id": updated_report["id"]}

# Endpoint para actualizar reportes
@app.put("/api/reports/{report_id}")
async def update_report(report_id: str, update_data: dict, current_user=Depends(get_current_user)):
    uid = current_user["uid"]
    role = current_user["role"]
    print(f"Usuario autenticado: {uid}, rol: {role}")

    if role not in ['supervisor', 'admin']:
        raise HTTPException(status_code=403, detail="Solo supervisores o administradores pueden actualizar reportes")

    user_ref = db.collection('users').document(uid)
    user_ref.set({'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

    print(f"Reporte {report_id} actualizado con: {update_data}")
    return {"success": True, "message": "Reporte actualizado exitosamente"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))  # Usa el puerto de Heroku o 8000 por defecto
    uvicorn.run(app, host="0.0.0.0", port=port)
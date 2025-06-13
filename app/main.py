from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import os
import base64
import json
import time
import secrets
from typing import List, Optional
from pydantic import BaseModel
import cv2
import numpy as np

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
        firebase_admin.initialize_app(cred)
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

# Modelo para los datos de reporte
class ReportRequest(BaseModel):
    location: str
    description: str
    measurements: dict
    risk_level: str
    comments: Optional[str] = None

# Función para asegurar que el administrador exista en Firebase Authentication
def ensure_admin_user():
    try:
        print("Verificando si existe admin@example.com...")
        user = firebase_auth.get_user_by_email("admin@example.com")
        print("Usuario administrador ya existe:", user.email)
    except firebase_auth.UserNotFoundError:
        print("Creando usuario administrador...")
        admin_password = secrets.token_urlsafe(16)
        print(f"Contraseña generada para admin: {admin_password}")
        firebase_auth.create_user(
            email="admin@example.com",
            password=admin_password,
            email_verified=True
        )
        print("Usuario administrador creado: admin@example.com")
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

# Función de autenticación personalizada
async def get_current_user(token: str):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")

# Nuevo endpoint para análisis de imágenes con IA manual usando OpenCV
@app.post("/api/analyze_image_manual")
async def analyze_image_manual(file: UploadFile = File(...), token: str = Depends(get_current_user)):
    try:
        uid = token['uid']
        print(f"Usuario autenticado: {uid}")

        # Leer y procesar la imagen con OpenCV
        image_content = await file.read()
        image = cv2.imdecode(np.frombuffer(image_content, np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            raise HTTPException(status_code=400, detail="Imagen no válida")

        # Análisis básico con Canny para detectar bordes (simplificado para grietas)
        edges = cv2.Canny(image, 100, 200)
        has_crack = np.sum(edges) > 1000  # Umbral simple para bordes
        evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente")

        return {"evaluation": evaluation, "has_crack": has_crack}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar imagen: {str(e)}")

# Endpoint para análisis de imágenes (usando el manual como ejemplo)
@app.post("/api/analyze_images")
async def analyze_images(token: str = Depends(get_current_user), files: List[UploadFile] = File(...)):
    try:
        uid = token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        # Usar el endpoint manual para la primera imagen como ejemplo
        image_analysis = await analyze_image_manual(files[0], token=token)
        return image_analysis
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar imágenes: {str(e)}")

# Endpoint para subir reportes
@app.post("/api/reports")
async def create_report(report: ReportRequest, files: List[UploadFile] = File(...), token: str = Depends(get_current_user)):
    try:
        uid = token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        print(f"Reporte recibido: {report.dict()}")
        for file in files:
            print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

        return {"success": True, "message": "Reporte creado exitosamente"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")

print("Aplicación configurada correctamente, iniciando servidor...")
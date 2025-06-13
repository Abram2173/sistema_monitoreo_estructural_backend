from fastapi import FastAPI, Request, UploadFile, File, HTTPException
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
        # Validar campos esenciales de las credenciales
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
        admin_password = secrets.token_urlsafe(16)  # Contraseña segura
        print(f"Contraseña generada para admin: {admin_password}")  # Quitar en producción
        firebase_auth.create_user(
            email="admin@example.com",
            password=admin_password,
            email_verified=True
        )
        print("Usuario administrador creado: admin@example.com")
        # En producción, guarda la contraseña en un lugar seguro (e.g., variable de entorno)
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

# Nuevo endpoint para análisis de imágenes con IA
@app.post("/api/analyze_images")
async def analyze_images(token: str, files: List[UploadFile] = File(...)):
    try:
        # Verificar el token de autenticación
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        # Simulación básica de análisis de IA (reemplazar con un modelo real)
        evaluation = "Análisis preliminar: posible grieta detectada en una imagen"
        has_crack = True  # Lógica de IA aquí (por ejemplo, usando una API externa)

        return {"evaluation": evaluation, "has_crack": has_crack}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar imágenes: {str(e)}")

# Nuevo endpoint para subir reportes
@app.post("/api/reports")
async def create_report(token: str, report: ReportRequest, files: List[UploadFile] = File(...)):
    try:
        # Verificar el token de autenticación
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        # Simulación de almacenamiento o procesamiento del reporte
        # En producción, guarda las imágenes y datos en una base de datos o sistema de archivos
        print(f"Reporte recibido: {report.dict()}")
        for file in files:
            print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

        return {"success": True, "message": "Reporte creado exitosamente"}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")

print("Aplicación configurada correctamente, iniciando servidor...") 
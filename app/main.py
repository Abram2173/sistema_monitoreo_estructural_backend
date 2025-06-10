from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import os
import base64
import json
import time

app = FastAPI(
    title="Sistema de Monitoreo Estructural",
    description="API para gestionar reportes de monitoreo estructural con autenticación de usuarios.",
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
        cred = credentials.Certificate(json.loads(decoded_credentials))
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
    "https://monitoreoestructural.net",  # Añade tu dominio aquí
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Función para asegurar que el administrador exista en Firebase Authentication
def ensure_admin_user():
    try:
        print("Verificando si existe admin@example.com...")
        user = firebase_auth.get_user_by_email("admin@example.com")
        print("Usuario administrador ya existe:", user.email)
    except firebase_auth.UserNotFoundError:
        print("Creando usuario administrador...")
        firebase_auth.create_user(
            email="admin@example.com",
            password="admin123",
            email_verified=True
        )
        print("Usuario administrador creado: admin@example.com")
    except Exception as e:
        print(f"Error al verificar/crear administrador: {str(e)}")

@app.on_event("startup")
async def startup_event():
    print("Ejecutando evento de startup...")
    ensure_admin_user()
    print("Evento de startup completado")

# Incluir las rutas de los diferentes módulos
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api", tags=["Administración"])

print("Aplicación configurada correctamente, iniciando servidor...")
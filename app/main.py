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
from google.cloud import vision
import requests
from fastapi.security import OAuth2PasswordBearer

app = FastAPI(
    title="Sistema de Monitoreo Estructural",
    description="API para gestionar reportes de monitoreo estructural con autenticación de usuarios e IA básica.",
    version="1.0.0"
)

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
    evaluation: Optional[str] = None
    has_crack: Optional[bool] = None

# Función para asegurar que el administrador exista en Firebase Authentication
def ensure_admin_user():
    try:
        print("Verificando si existe admin@example.com...")
        user = firebase_auth.get_user_by_email("admin@example.com")
        print("Usuario administrador ya existe:", user.email)
    except firebase_auth.UserNotFoundError:
        print("Creando usuario administrador...")
        admin_password = secrets.token_urlsafe(16)
        print(f"Contraseña generada para admin: {admin_password}")  # Quitar en producción
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

# Inicializar cliente de Google Cloud Vision con verificación
google_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if not google_credentials:
    print("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
    raise Exception("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
try:
    # Si es base64, decodificar; si es ruta, usar directamente
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

# Nuevo endpoint para análisis de imágenes con IA (acepta archivos o URLs)
@app.post("/api/analyze_images")
async def analyze_images(token: str = Depends(oauth2_scheme), files: list[UploadFile] = File(None), image_urls: list[str] = None):
    try:
        # Verificar el token de autenticación con Firebase
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

        # Verificar si se enviaron archivos o URLs
        if not files and not image_urls:
            raise HTTPException(status_code=400, detail="Se requieren archivos o URLs de imágenes")
        if files and len(files) > 2:
            raise HTTPException(status_code=400, detail="Se permiten máximo 2 imágenes")
        if image_urls and len(image_urls) > 2:
            raise HTTPException(status_code=400, detail="Se permiten máximo 2 URLs de imágenes")

        # Usar la primera imagen disponible (archivo o URL)
        image_content = None
        if files and files[0]:
            image_content = await files[0].read()
        elif image_urls and image_urls[0]:
            try:
                response = requests.get(image_urls[0], headers={'Authorization': f'Bearer {token}'}, timeout=10)
                if response.status_code != 200:
                    raise HTTPException(status_code=400, detail=f"URL de imagen no accesible: {response.status_code}")
                image_content = response.content
            except requests.exceptions.RequestException as e:
                raise HTTPException(status_code=400, detail=f"Error al descargar la URL: {str(e)}")

        if not image_content:
            raise HTTPException(status_code=400, detail="No se proporcionó una imagen válida")

        # Analizar la imagen con Google Cloud Vision
        image = vision.Image(content=image_content)
        response = client.label_detection(image=image)
        labels = [label.description.lower() for label in response.label_annotations]

        # Detectar riesgos (grietas, daños, deformaciones)
        has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
        evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")

        return {"evaluation": evaluation, "has_crack": has_crack}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Error al descargar la URL: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar imágenes: {str(e)}")

# Nuevo endpoint para subir reportes (almacena resultados de IA)
@app.post("/api/reports")
async def create_report(report: ReportRequest, files: list[UploadFile] = File(...), token: str = Depends(oauth2_scheme)):
    try:
        # Verificar el token de autenticación
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        # Analizar la primera imagen con Google Cloud Vision
        image_content = await files[0].read()
        image = vision.Image(content=image_content)
        response = client.label_detection(image=image)
        labels = [label.description.lower() for label in response.label_annotations]
        has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
        evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")

        # Actualizar el reporte con los resultados de IA
        updated_report = report.dict()
        updated_report["evaluation"] = evaluation
        updated_report["has_crack"] = has_crack

        # Simulación de almacenamiento (en producción, guarda en MongoDB)
        print(f"Reporte recibido: {updated_report}")
        for file in files:
            print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

        return {"success": True, "message": "Reporte creado exitosamente", "evaluation": evaluation, "has_crack": has_crack}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")

# Endpoint para actualizar reportes (manejo de acciones del supervisor)
@app.put("/api/reports/{report_id}")
async def update_report(report_id: str, update_data: dict, token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid} actualizando reporte {report_id}")

        # Simulación de actualización (en producción, actualiza en MongoDB)
        # Aquí deberías buscar y actualizar el reporte en tu base de datos
        print(f"Reporte {report_id} actualizado con: {update_data}")
        return {"success": True, "message": "Reporte actualizado exitosamente"}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar el reporte: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))  # Usa el puerto de Heroku o 8000 por defecto
    uvicorn.run(app, host="0.0.0.0", port=port)
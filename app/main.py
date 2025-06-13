from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import os
import base64
import json
import time
import secrets
from typing import Optional
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer

app = FastAPI(
    title="Sistema de Monitoreo Estructural",
    description="API para gestionar reportes de monitoreo estructural con autenticación de usuarios e IA básica.",
    version="1.0.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    print(f"Tiempo de procesamiento para {request.url}: {process_time:.2f} segundos")
    response.headers["X-Process-Time"] = str(process_time)
    return response

print("Iniciando la aplicación...")

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

class UserInfo(BaseModel):
    role: str

@app.get("/api/auth/me", response_model=UserInfo)
async def get_user_info(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        role = decoded_token.get('role', 'user')  # Asume 'user' si no hay rol
        return {"role": role}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")

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

app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api", tags=["Administración"])

google_credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
if not google_credentials:
    print("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
    raise Exception("GOOGLE_APPLICATION_CREDENTIALS no está configurado en las variables de entorno")
try:
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
    print(f"Error al inicializar Google Cloud Vision: {str(e)}")
    raise Exception(f"Error al inicializar Google Cloud Vision: {str(e)}")

@app.post("/api/analyze_images")
async def analyze_images(token: str = Depends(oauth2_scheme), files: list[UploadFile] = File(...)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

        if len(files) != 2:
            raise HTTPException(status_code=400, detail="Se requieren exactamente 2 imágenes")

        image_content = await files[0].read()
        image = vision.Image(content=image_content)
        response = client.label_detection(image=image)
        labels = [label.description.lower() for label in response.label_annotations]
        has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
        evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")

        return {"evaluation": evaluation, "has_crack": has_crack}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar imágenes: {str(e)}")

@app.post("/api/reports")
async def create_report(report: ReportRequest, files: list[UploadFile] = File(...), token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token['uid']
        print(f"Usuario autenticado: {uid}")

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

        print(f"Reporte recibido: {updated_report}")
        for file in files:
            print(f"Imagen recibida: {file.filename}, tamaño: {file.size} bytes")

        return {"success": True, "message": "Reporte creado exitosamente", "evaluation": evaluation, "has_crack": has_crack}
    except firebase_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token de autenticación inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el reporte: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
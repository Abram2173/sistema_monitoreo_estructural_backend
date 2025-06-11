from fastapi import FastAPI, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
import os
import base64
import json
import time
from pydantic import BaseModel
from sklearn.linear_model import LogisticRegression
import numpy as np
import cv2
from io import BytesIO
from PIL import Image

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

# Configurar CORS
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

# Función para asegurar que el administrador exista
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

# Incluir las rutas
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api", tags=["Administración"])

# Modelo de IA para predicción de riesgo
class RiskPrediction(BaseModel):
    deformation: float
    temperature: float
    vibration: float

model = LogisticRegression()
X_train = np.array([[0, 20, 0], [10, 30, 5], [20, 40, 10]])
y_train = np.array(["bajo", "medio", "alto"])
model.fit(X_train, y_train)

@app.post("/api/predict_risk")
async def predict_risk(data: RiskPrediction):
    input_data = np.array([[data.deformation, data.temperature, data.vibration]])
    prediction = model.predict(input_data)[0]
    return {"risk_level": prediction}

# Análisis de imágenes para detectar fallos
@app.post("/api/analyze_images")
async def analyze_images(image1: UploadFile = File(...), image2: UploadFile = File(...)):
    contents1 = await image1.read()
    contents2 = await image2.read()
    img1 = Image.open(BytesIO(contents1)).convert('L')  # Convertir a escala de grises
    img2 = Image.open(BytesIO(contents2)).convert('L')
    img1_np = np.array(img1)
    img2_np = np.array(img2)

    # Detección de bordes (simple para grietas)
    edges1 = cv2.Canny(img1_np, 100, 200)
    edges2 = cv2.Canny(img2_np, 100, 200)
    edge_count1 = np.sum(edges1 > 0)
    edge_count2 = np.sum(edges2 > 0)

    # Evaluación preliminar
    has_crack1 = edge_count1 > 1000  # Umbral simple
    has_crack2 = edge_count2 > 1000
    evaluation = "Posible grieta detectada" if has_crack1 or has_crack2 else "No se detectaron grietas"

    return {"evaluation": evaluation, "has_crack": has_crack1 or has_crack2}

print("Aplicación configurada correctamente, iniciando servidor...")
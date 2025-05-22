from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, reports, admin
import firebase_admin
from firebase_admin import credentials
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

   # Inicializar Firebase Admin SDK solo si no está inicializado
firebase_credentials = os.getenv("FIREBASE_CREDENTIALS")
if not firebase_admin._apps:
       if firebase_credentials:
           decoded_credentials = base64.b64decode(firebase_credentials).decode('utf-8')
           cred = credentials.Certificate(json.loads(decoded_credentials))
           firebase_admin.initialize_app(cred)
       else:
           cred = credentials.Certificate("serviceAccountKey.json")
           firebase_admin.initialize_app(cred)

   # Configurar CORS para permitir solicitudes desde el frontend
origins = [
       "http://localhost:3000",
       "https://eclectic-frangipane-39ee69.netlify.app",  # URL de Netlify
   ]

app.add_middleware(
       CORSMiddleware,
       allow_origins=origins,
       allow_credentials=True,
       allow_methods=["*"],
       allow_headers=["*"],
   )

   # Incluir las rutas de los diferentes módulos
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api", tags=["Reportes"])
app.include_router(admin.router, prefix="/api", tags=["Administración"])
from motor.motor_asyncio import AsyncIOMotorClient
import os

# Configuración de la conexión a MongoDB con opciones de optimización
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb+srv://Admin:Lni2hOGoUgRIWxzt@sistema-monitoreo-clust.rmyuy03.mongodb.net/?retryWrites=true&w=majority&appName=sistema-monitoreo-cluster")
client = AsyncIOMotorClient(
    MONGODB_URI,
    maxPoolSize=10,  # Tamaño máximo del pool de conexiones
    minPoolSize=1,   # Tamaño mínimo del pool de conexiones
    connectTimeoutMS=5000,  # Tiempo de espera para la conexión
)
db = client["sistema_monitoreo"]

users_collection = db.get_collection("users")
reports_collection = db.get_collection("reports")

async def get_database():
    yield db
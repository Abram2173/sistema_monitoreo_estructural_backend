import firebase_admin
from firebase_admin import credentials, firestore
import os
import base64
import json

def initialize_firebase():
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
    return firestore.client()
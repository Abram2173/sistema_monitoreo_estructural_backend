import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth as firebase_auth  # Renombramos 'auth' a 'firebase_auth'

# Inicializar Firebase Admin
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

# Exportamos firebase_auth para usarlo en otros módulos
__all__ = ['firebase_auth']
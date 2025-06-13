# set_custom_claims.py
from firebase_admin import credentials, initialize_app, auth

# Inicializa la aplicación con las credenciales
cred = credentials.Certificate('serviceAccountKey.json')  # Ajusta la ruta si es diferente
initialize_app(cred)

users = [
    {"uid": "qGBpZFG5w6Xy71mJiZBOiZVZ8tO2", "role": "admin", "email": "admin@example.com"},
    {"uid": "qUNM4zGDtvTgWXZkrgAaNZwS1ap1", "role": "supervisor", "email": "supervisor3@gmail.com"},
]

for user in users:
    try:
        auth.set_custom_user_claims(user["uid"], {"role": user["role"]})
        print(f"Custom claim 'role: {user['role']}' asignado a {user['email']} (UID: {user['uid']})")
    except Exception as e:
        print(f"Error al asignar claim a {user['email']}: {str(e)}")
print("Proceso completado.")
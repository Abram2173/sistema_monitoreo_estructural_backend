# set_custom_claims.py
from firebase_admin import credentials, initialize_app, auth

# Inicializa la aplicación con las credenciales
cred = credentials.Certificate('serviceAccountKey.json')  # Ajusta la ruta si es diferente
initialize_app(cred)

# Lista de usuarios y sus roles
users = [
    {"uid": "qGBpZFG5w6Xy71mJiZBOiZVY8tO2", "role": "admin", "email": "admin@example.com"},
    {"uid": "qUNM4zGDtvTgWZakrgAaNZwS1ap1", "role": "supervisor", "email": "supervisor3@gmail.com"},
    {"uid": "Nm54ECsr1fZmdAKY7phvD", "role": "inspector", "email": "inspector1@gmail.com"},
    # Agrega más usuarios si los tienes (verifica sus UID en Firebase Console)
]

# Asigna los custom claims
for user in users:
    try:
        # Verifica si el UID es correcto
        existing_user = auth.get_user(user["uid"])
        auth.set_custom_user_claims(user["uid"], {"role": user["role"]})
        print(f"Custom claim 'role: {user['role']}' asignado al usuario {user['email']} (UID: {user['uid']})")
    except Exception as e:
        print(f"Error al asignar claim a {user['email']} (UID: {user['uid']}): {str(e)}")

print("Proceso de asignación de custom claims completado.")
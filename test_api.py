import requests

BASE_URL = "http://127.0.0.1:8000"

# Autenticarse como admin1
print("Autenticando como admin1...")
login_url = f"{BASE_URL}/api/auth/login"
login_data = {
    "username": "admin1",
    "password": "Admin123"
}

response = requests.post(login_url, data=login_data)
if response.status_code != 200:
    print("Error al autenticarse:", response.json())
    exit()

token = response.json().get("access_token")
print("Token obtenido:", token)

# Obtener la lista de usuarios
print("\nObteniendo lista de usuarios...")
get_users_url = f"{BASE_URL}/api/admin/users"
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

response = requests.get(get_users_url, headers=headers)
if response.status_code == 200:
    print("Usuarios:", response.json())
else:
    print("Error al obtener usuarios:", response.json())
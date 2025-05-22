import requests

BASE_URL = "http://127.0.0.1:8000"

# Autenticarse como inspector3
print("Autenticando como inspector3...")
login_url = f"{BASE_URL}/api/auth/login"
login_data = {
    "username": "inspector3",
    "password": "Inspector789"
}

response = requests.post(login_url, data=login_data)
if response.status_code != 200:
    print("Error al autenticarse:", response.text)
    exit()

token = response.json().get("access_token")
print("Token obtenido:", token)

# Subir un reporte
print("\nSubiendo un reporte...")
create_report_url = f"{BASE_URL}/api/reports"
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}
report_data = {
    "location": "Edificio Central, Piso 3",
    "comments": "Grietas visibles en la pared norte, posible daño estructural.",
    "risk_level": "Alto",
    "photos": ["foto1.jpg", "foto2.jpg"]
}

response = requests.post(create_report_url, json=report_data, headers=headers)
print("Código de estado:", response.status_code)
print("Respuesta del servidor:", response.text)
if response.status_code == 200:
    print("Reporte creado:", response.json())
else:
    print("Error al crear reporte:", response.text)
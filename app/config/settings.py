# app/config/settings.py

# Clave secreta para firmar los tokens JWT
SECRET_KEY = "da39b8cf8e0b379cca49a633d11344bea88b9561f3346c3d94bbfa52df0d5819"  # Cambia esto por una clave secreta segura

# Algoritmo para firmar los tokens JWT
ALGORITHM = "HS256"

# Tiempo de expiración del token (en minutos)
ACCESS_TOKEN_EXPIRE_MINUTES = 30
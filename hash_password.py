from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password = "Admin123"  # Contraseña para el supervisor
hashed_password = pwd_context.hash(password)
print(hashed_password)
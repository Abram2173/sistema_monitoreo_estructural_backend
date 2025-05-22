from passlib.context import CryptContext

# Configuración del contexto de hash (debe coincidir con la configuración en utils/security.py)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Hash almacenado en MongoDB para admin1
stored_hash = "$2b$12$GIILxkEUNDsjgghcv6CKZ.GGjSx4NlVbOTMANZHx6.ORUZuklciaW"

# Contraseña que estás intentando usar
password = "Admin123"

# Verificar si coinciden
is_correct = pwd_context.verify(password, stored_hash)
print("¿La contraseña coincide?", is_correct)

# Si no coincide, generar un nuevo hash para la contraseña
if not is_correct:
    new_hash = pwd_context.hash(password)
    print("Nuevo hash para 'Admin123':", new_hash)
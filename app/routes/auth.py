from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.config.database import users_collection
from firebase_admin import auth
import os
from cachetools import TTLCache
from firebase_admin import firestore  # Importar solo para referencia, no inicialización

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
cache = TTLCache(maxsize=100, ttl=300)
db = firestore.client()  # Usar la instancia global inicializada en main.py

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        # Invalidar el caché para este token al iniciar una nueva sesión
        if token in cache:
            print(f"Invalidando caché para el token: {token}")
            del cache[token]

        decoded_token = auth.verify_id_token(token)
        email = decoded_token.get("email")
        if not email:
            print("Error: No se pudo obtener el email del token")
            raise HTTPException(status_code=401, detail="Token inválido")

        print(f"Email extraído del token: {email}")

        # Obtener custom claims como fuente principal del rol
        custom_claims = decoded_token.get("custom_claims", {})
        role = custom_claims.get("role", "user")  # Default a 'user' si no hay rol
        print(f"Custom claims obtenidos del token: {custom_claims}, rol: {role}")

        # Consultar MongoDB con timeout más bajo para evitar bloqueos
        user = None
        try:
            user = await users_collection.find_one({"email": email}, serverSelectionTimeoutMS=5000)
        except Exception as e:
            print(f"Timeout o error al consultar MongoDB para {email}: {str(e)}, usando solo custom claims")
            user = None

        if not user:
            print(f"Usuario no encontrado en MongoDB, creando uno nuevo para {email}")
            username = email.split("@")[0]
            new_user = {
                "username": username,
                "email": email,
                "role": role,  # Usar el rol del custom claim
                "name": username.capitalize()
            }
            try:
                await users_collection.insert_one(new_user)
            except Exception as e:
                print(f"Error al insertar usuario en MongoDB: {str(e)}")
            user = new_user
        else:
            print(f"Usuario encontrado en MongoDB: {user}")
            # Actualizar rol en MongoDB si difiere del custom claim
            if user.get("role") != role:
                print(f"Actualizando rol en MongoDB para {email} de {user['role']} a {role}")
                try:
                    await users_collection.update_one(
                        {"email": email},
                        {"$set": {"role": role}}
                    )
                    user["role"] = role
                except Exception as e:
                    print(f"Error al actualizar rol en MongoDB: {str(e)}")

        # Actualizar estado en Firestore
        uid = decoded_token['uid']
        user_ref = db.collection('users').document(uid)
        user_ref.set({'email': email, 'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

        user_data = {"username": user["username"], "role": role}
        cache[token] = user_data
        print(f"Datos de usuario almacenados en caché: {user_data}")
        return user_data
    except auth.InvalidIdTokenError as e:
        print(f"Error al verificar el token: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")
    except Exception as e:
        print(f"Error inesperado al verificar el token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    print(f"Devolviendo datos del usuario: {current_user}")
    return current_user

@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        if token in cache:
            del cache[token]
            print(f"Caché invalidado para el token: {token}")
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_ref = db.collection('users').document(uid)
        user_ref.set({'status': 'inactive', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)
        return {"message": "Sesión cerrada exitosamente"}
    except auth.InvalidIdTokenError as e:
        print(f"Error al verificar el token en logout: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")
    except Exception as e:
        print(f"Error al cerrar sesión: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al cerrar sesión: {str(e)}")
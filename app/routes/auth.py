from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.config.database import users_collection
from firebase_admin import auth
import os
from cachetools import TTLCache
from datetime import datetime

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
cache = TTLCache(maxsize=100, ttl=300)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        if token in cache:
            print(f"Invalidando caché para el token: {token}")
            del cache[token]

        decoded_token = auth.verify_id_token(token)
        email = decoded_token.get("email")
        if not email:
            print("Error: No se pudo obtener el email del token")
            raise HTTPException(status_code=401, detail="Token inválido")

        print(f"Email extraído del token: {email}")

        custom_claims = decoded_token.get("role", None)
        print(f"Custom claims obtenidos del token: {custom_claims}")

        user = await users_collection.find_one({"email": email})
        if not user:
            print(f"Usuario no encontrado en MongoDB, creando uno nuevo para {email}")
            username = email.split("@")[0]
            if email == "admin@example.com":
                role = "admin"
            else:
                role = "supervisor" if "supervisor" in email else "inspector"
                if "admin" in email:
                    role = "admin"
            new_user = {
                "username": username,
                "email": email,
                "role": role,
                "name": username.capitalize(),
                "last_activity": datetime.utcnow().isoformat() + "+00:00"
            }
            await users_collection.insert_one(new_user)
            user = new_user
        else:
            print(f"Usuario encontrado en MongoDB: {user}")
            # Actualizar last_activity al autenticarse
            await users_collection.update_one(
                {"email": email},
                {"$set": {"last_activity": datetime.utcnow().isoformat() + "+00:00"}}
            )

        role = custom_claims if custom_claims else user["role"]
        print(f"Rol determinado para {email}: {role}")

        if email == "admin@example.com" and role != "admin":
            print(f"Correo {email} debería ser admin, corrigiendo rol...")
            role = "admin"
            await users_collection.update_one(
                {"email": email},
                {"$set": {"role": "admin"}}
            )
            firebase_user = auth.get_user_by_email(email)
            auth.set_custom_user_claims(firebase_user.uid, {"role": "admin"})
            print(f"Custom claim actualizado para {email}: role=admin")

        user_data = {"username": user["username"], "role": role}
        cache[token] = user_data
        print(f"Datos de usuario almacenados en caché: {user_data}")
        return user_data
    except Exception as e:
        print(f"Error al verificar el token: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")

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
        return {"message": "Sesión cerrada exitosamente"}
    except Exception as e:
        print(f"Error al cerrar sesión: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al cerrar sesión: {str(e)}")
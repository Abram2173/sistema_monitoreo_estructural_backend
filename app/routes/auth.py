# app/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.config.database import users_collection
from firebase_admin import auth
from cachetools import TTLCache
from typing import Optional
import firebase_admin
from firebase_admin import firestore

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="https://sistema-monitoreo-backend-2d6d5d68221a.herokuapp.com/api/auth/login")
cache = TTLCache(maxsize=100, ttl=300)

def get_db():
    from app.main import db
    return db

async def get_mongo_db():
    from app.config.database import get_database
    async for database in get_database():
        yield database

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = auth.get_user_by_email(form_data.username)
        custom_token = auth.create_custom_token(user.uid)
        return {"token": custom_token.decode('utf-8'), "message": "Login exitoso"}
    except auth.AuthError as e:
        raise HTTPException(status_code=401, detail=f"Credenciales inválidas: {str(e)}")

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db), mongo_db=Depends(get_mongo_db)):
    try:
        decoded_token = auth.verify_id_token(token)
        email = decoded_token.get("email")
        if not email:
            print("Error: No se pudo obtener el email del token")
            raise HTTPException(status_code=401, detail="Token inválido")

        print(f"Email extraído del token: {email}")

        # Obtener rol desde los custom claims
        custom_claims = decoded_token.get("custom_claims", {})
        role = custom_claims.get("role", "user")  # Usar el rol del custom claim, no de MongoDB por defecto
        print(f"Custom claims obtenidos del token: {custom_claims}, rol: {role}")

        users_coll = mongo_db.get_collection("users")
        user = await users_coll.find_one({"email": email})

        if not user:
            print(f"Usuario no encontrado en MongoDB, verificando duplicados para {email}")
            existing_user = await users_coll.find_one({"email": email})
            if not existing_user:
                username = email.split("@")[0]
                new_user = {
                    "username": username,
                    "email": email,
                    "role": role,  # Usar el rol del token
                    "name": username.capitalize()
                }
                try:
                    await users_coll.insert_one(new_user)
                    print(f"Usuario creado: {new_user}")
                except Exception as e:
                    print(f"Error al insertar usuario en MongoDB: {str(e)}")
                user = new_user
            else:
                print(f"Usuario ya existe en MongoDB: {existing_user}")
                user = existing_user
        else:
            print(f"Usuario encontrado en MongoDB: {user}")
            if user.get("role") != role:
                print(f"Actualizando rol en MongoDB para {email} de {user['role']} a {role}")
                try:
                    await users_coll.update_one(
                        {"email": email},
                        {"$set": {"role": role}}
                    )
                    user["role"] = role
                except Exception as e:
                    print(f"Error al actualizar rol en MongoDB: {str(e)}")

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
async def logout(token: str = Depends(oauth2_scheme), db=Depends(get_db), mongo_db=Depends(get_mongo_db)):
    try:
        if token in cache:
            del cache[token]
            print(f"Caché invalidado para el token: {token}")
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_ref = db.collection('users').document(uid)
        user_ref.set({'status': 'inactive', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

        users_coll = mongo_db.get_collection("users")
        await users_coll.update_one({"_id": uid}, {"$set": {"status": "inactive", "last_seen": firestore.SERVER_TIMESTAMP}}, upsert=True)
        return {"message": "Sesión cerrada exitosamente"}
    except auth.InvalidIdTokenError as e:
        print(f"Error al verificar el token en logout: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")
    except Exception as e:
        print(f"Error al cerrar sesión: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error al cerrar sesión: {str(e)}")
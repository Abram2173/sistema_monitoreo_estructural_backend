# app/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from firebase_admin import auth
from cachetools import TTLCache
from app.config.database import users_collection
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

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db), mongo_db=Depends(get_mongo_db)):
    try:
        decoded_token = auth.verify_id_token(token)
        email = decoded_token.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Token inválido: No se encontró email")

        custom_claims = decoded_token.get("claims", {})
        role = custom_claims.get("role", "user")
        print(f"Rol obtenido de custom claims: {role}")

        users_coll = mongo_db.get_collection("users")
        user = await users_coll.find_one({"email": email})
        if not user:
            username = email.split("@")[0]
            new_user = {
                "username": username,
                "email": email,
                "role": role,
                "name": username.capitalize()
            }
            await users_coll.insert_one(new_user)
            user = new_user
        elif user.get("role") != role:
            await users_coll.update_one({"email": email}, {"$set": {"role": role}})
            user["role"] = role

        uid = decoded_token['uid']
        user_ref = db.collection('users').document(uid)
        user_ref.set({'email': email, 'status': 'active', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

        user_data = {"username": user["username"], "role": role}
        cache[token] = user_data
        return user_data
    except auth.InvalidIdTokenError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), db=Depends(get_db), mongo_db=Depends(get_mongo_db)):
    try:
        if token in cache:
            del cache[token]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        user_ref = db.collection('users').document(uid)
        user_ref.set({'status': 'inactive', 'last_seen': firestore.SERVER_TIMESTAMP}, merge=True)

        users_coll = mongo_db.get_collection("users")
        await users_coll.update_one({"_id": uid}, {"$set": {"status": "inactive"}}, upsert=True)
        return {"message": "Sesión cerrada exitosamente"}
    except auth.InvalidIdTokenError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cerrar sesión: {str(e)}")
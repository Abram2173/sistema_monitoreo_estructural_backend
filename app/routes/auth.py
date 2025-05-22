from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from app.config.database import users_collection
from firebase_admin import auth
import os
from cachetools import TTLCache

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
cache = TTLCache(maxsize=100, ttl=300)

async def get_current_user(token: str = Depends(oauth2_scheme)):
       try:
           if token in cache:
               return cache[token]

           decoded_token = auth.verify_id_token(token)
           email = decoded_token.get("email")
           if not email:
               raise HTTPException(status_code=401, detail="Token inválido")

           user = await users_collection.find_one({"email": email})
           if not user:
               username = email.split("@")[0]
               # Si el correo es admin@example.com, siempre asignar rol admin
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
                   "name": username.capitalize()
               }
               await users_collection.insert_one(new_user)
               user = new_user
           # Asegurar que admin@example.com siempre tenga rol admin
           if email == "admin@example.com" and user["role"] != "admin":
               await users_collection.update_one(
                   {"email": email},
                   {"$set": {"role": "admin"}}
               )
               user["role"] = "admin"

           user_data = {"username": user["username"], "role": user["role"]}
           cache[token] = user_data
           return user_data
       except Exception as e:
           raise HTTPException(status_code=401, detail=f"Token inválido: {str(e)}")

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
       return current_user
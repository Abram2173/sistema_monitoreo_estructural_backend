from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config.database import users_collection
from app.firebase_admin_config import firebase_auth

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        email = decoded_token.get("email")
        print(f"Email extraído del token: {email}")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await users_collection.find_one({"email": email})
        if not user:
            username = email.split("@")[0]
            role = "supervisor" if "supervisor" in email else "inspector"
            new_user = {
                "username": username,
                "email": email,
                "role": role,
                "name": username.capitalize()
            }
            await users_collection.insert_one(new_user)
            user = new_user
            print(f"Usuario creado automáticamente: {user}")
        return {"username": user["username"], "role": user["role"]}
    except Exception as e:
        print(f"Error al verificar el token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_inspector_or_supervisor_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["inspector", "supervisor"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

async def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized: Admin access required")
    return current_user

async def get_current_user_with_report_access(current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["inspector", "supervisor", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user
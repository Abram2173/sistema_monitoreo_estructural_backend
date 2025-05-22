from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from firebase_admin import auth as firebase_auth

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        email = decoded_token.get("email")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No se pudo obtener el email del token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        print(f"Email extraído del token: {email}")
        user = firebase_auth.get_user_by_email(email)
        return {"username": user.email, "role": "user"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token inválido: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_inspector_or_supervisor_user(current_user: dict = Depends(get_current_user)):
    email = current_user["username"]
    try:
        user = firebase_auth.get_user_by_email(email)
        custom_claims = user.custom_claims or {}
        role = custom_claims.get("role", "user")
        if role not in ["inspector", "supervisor"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para acceder a esta funcionalidad. Debes ser inspector o supervisor.",
            )
        return {"username": user.email, "role": role}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Error al verificar permisos: {str(e)}",
        )

async def get_current_user_with_report_access(current_user: dict = Depends(get_current_user)):
    email = current_user["username"]
    try:
        user = firebase_auth.get_user_by_email(email)
        custom_claims = user.custom_claims or {}
        role = custom_claims.get("role", "user")
        if role not in ["inspector", "supervisor", "admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para acceder a reportes.",
            )
        return {"username": user.email, "role": role}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Error al verificar permisos: {str(e)}",
        )

async def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    email = current_user["username"]
    try:
        user = firebase_auth.get_user_by_email(email)
        custom_claims = user.custom_claims or {}
        role = custom_claims.get("role", "user")
        if role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para acceder a esta funcionalidad. Debes ser administrador.",
            )
        return {"username": user.email, "role": role}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Error al verificar permisos de administrador: {str(e)}",
        )
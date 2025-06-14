import asyncio
from app.config.database import users_collection
from datetime import datetime

async def update_users_last_activity():
    print("Iniciando actualización de last_activity para usuarios existentes...")
    async for user in users_collection.find():
        if "last_activity" not in user or not user["last_activity"]:
            await users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_activity": datetime.utcnow().isoformat() + "+00:00"}}
            )
            print(f"Actualizado last_activity para {user['username']}")
        else:
            # Verificar y corregir el formato si no es válido
            last_activity_str = str(user["last_activity"])
            try:
                datetime.fromisoformat(last_activity_str.replace("Z", "+00:00"))
            except ValueError:
                await users_collection.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"last_activity": datetime.utcnow().isoformat() + "+00:00"}}
                )
                print(f"Corregido formato de last_activity para {user['username']}")
    print("Actualización completada.")

if __name__ == "__main__":
    asyncio.run(update_users_last_activity())
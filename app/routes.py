from fastapi import APIRouter, HTTPException
from app.models import users_collection, user_helper
from app.schemas import UserRegisterSchema
from app.auth import hash_password
from bson import ObjectId

user_router = APIRouter()

# User registration endpoint
@user_router.post("/register")
async def register_user(user: UserRegisterSchema):
    # Check if the user already exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email is already registered")

    # Hash the user's password
    hashed_password = hash_password(user.password)

    # Create a new user document
    new_user = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "role": user.role
    }

    # Insert user into MongoDB
    inserted_user = await users_collection.insert_one(new_user)

    # Return the user data (except the password)
    user_data = user_helper(await users_collection.find_one({"_id": ObjectId(inserted_user.inserted_id)}))
    return user_data

# from fastapi import FastAPI

# app = FastAPI()

# @app.get("/")
# def read_root():
#     return {"message": "Welcome to the User Management API!"}

from fastapi import FastAPI, HTTPException, Depends
from app.models import UserCreate, UserInDB, Token
from app.utils import hash_password, verify_password, create_access_token
from app.database import users_collection
from app.auth import get_current_user, admin_required  # Import relevant functions
from datetime import datetime, timedelta

app = FastAPI()

# Print the current UTC time (just for testing)
current_time = datetime.utcnow()
print("Current UTC Time:", current_time)

# Endpoint for user registration (already working)
@app.post("/register/")
async def register_user(user: UserCreate):
    # Check if email already exists
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password
    hashed_password = hash_password(user.password)

    # Insert user into the database
    user_in_db = UserInDB(**user.dict(), hashed_password=hashed_password)
    users_collection.insert_one(user_in_db.dict())

    return {"msg": "User registered successfully"}

# Endpoint for user login (updated to return a Token model)
@app.post("/login/", response_model=Token)
async def login_user(email: str, password: str):
    # Find the user by email
    user = users_collection.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Verify the password
    if not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    # Create the JWT access token
    access_token = create_access_token(
        data={"sub": user["email"]},  # "sub" is a standard claim in JWT
        expires_delta=timedelta(minutes=30)
    )
    
    return Token(access_token=access_token, token_type="bearer")

# Example of a protected route (accessible only with a valid JWT token)
@app.get("/profile/")
async def get_user_profile(current_user: UserInDB = Depends(get_current_user)):
    return {"email": current_user.email, "username": current_user.username}

# Example of an admin-only route (optional)
@app.get("/admin/dashboard/")
async def admin_dashboard(current_user: UserInDB = Depends(admin_required)):
    return {"msg": "Welcome to the admin dashboard!"}

from pydantic import BaseModel, EmailStr
from typing import Optional

# Model for user creation input
class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    role: str  # can be 'user' or 'admin'

# Model for storing user data in the database
class UserInDB(UserCreate):
    hashed_password: str

# Model for handling token data (JWT)
class Token(BaseModel):
    access_token: str
    token_type: str

# Model for extracting token payload
class TokenData(BaseModel):
    email: Optional[str] = None

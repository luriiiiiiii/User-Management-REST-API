from pydantic import BaseModel, EmailStr

# User registration schema
class UserRegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"  # Default role is user

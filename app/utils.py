from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

#This will handle hashing and verifying passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Secret key for JWT signing
SECRET_KEY = "1234lors!@#$LORS"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Hash a password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

#Verify a password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

#Create access token (JWT)
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
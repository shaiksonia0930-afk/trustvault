import os
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import uuid
from dotenv import load_dotenv

load_dotenv()

# Redis with memory fallback - VS Code lo Redis lekunna run avvadaniki
try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False
    redis_client = None
    _blacklist_memory = {}

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_TO_32_CHAR_SECRET_KEY_123")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "jti": jti, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti, expire

def blacklist_token(jti: str, expire: datetime):
    now = datetime.now(timezone.utc)
    ttl = int((expire - now).total_seconds())
    if ttl <= 0:
        ttl = 1
    if REDIS_AVAILABLE:
        redis_client.setex(f"blacklist:{jti}", ttl, "true")
    else:
        _blacklist_memory[f"blacklist:{jti}"] = True

def is_token_blacklisted(jti: str) -> bool:
    if REDIS_AVAILABLE:
        return redis_client.exists(f"blacklist:{jti}") == 1
    else:
        return f"blacklist:{jti}" in _blacklist_memory

# get_db ni models nundi import chesi circular avoid cheyadaniki late import
def get_current_user(token: str = Depends(oauth2_scheme)):
    from app.models import SessionLocal, User
    db = SessionLocal()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        jti: str = payload.get("jti")
        if email is None or jti is None:
            raise credentials_exception
        if is_token_blacklisted(jti):
            raise HTTPException(status_code=401, detail="Token revoked. Please login again.")
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception
    finally:
        db.close()

def get_current_active_user(current_user = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
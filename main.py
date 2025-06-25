
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from db import SessionLocal
from schemas import UserCreate
from models import User
from datetime import datetime, timedelta
import os
from cryptography.fernet import Fernet

app = FastAPI()

# === Security and Encryption Setup ===
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
fernet_key = Fernet.generate_key()  # In production, load from .env
fernet = Fernet(fernet_key)

# === Password Hashing ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

# === OAuth2 Setup ===
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# === Upload Folder ===
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# === Database Dependency ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Auth Helpers ===
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role")
        if email is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return {"email": email, "role": role}
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

def require_role(required_role: str):
    def role_dependency(user: dict = Depends(get_current_user)):
        if user["role"] != required_role:
            raise HTTPException(status_code=403, detail=f"Access denied. Only '{required_role}' users allowed.")
        return user
    return role_dependency

# === Routes ===
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI"}

@app.post("/client/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        hashed_password=hash_password(user.password),
        role="client",
        is_verified=0
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = fernet.encrypt(new_user.email.encode()).decode()
    verification_url = f"/client/verify-email/{token}"

    return {
        "message": "User created successfully. Please verify your email.",
        "verify_url": verification_url
    }

@app.get("/client/verify-email/{token}")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        email = fernet.decrypt(token.encode()).decode()
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_verified = 1
        db.commit()
        return {"message": f"Email {email} verified successfully"}
    except:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if user.is_verified == 0:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/ops/upload")
def upload_file_ops(file: UploadFile = File(...), user=Depends(require_role("ops"))):
    allowed_exts = [".docx", ".pptx", ".xlsx"]
    _, ext = os.path.splitext(file.filename)
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail="Only .docx, .pptx, .xlsx files are allowed.")

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())

    return {"message": f"File '{file.filename}' uploaded by OPS user '{user['email']}'."}

@app.get("/client/files")
def list_files(user=Depends(require_role("client"))):
    files = os.listdir(UPLOAD_FOLDER)
    return {"files": files}

@app.get("/generate-link/{filename}")
def generate_secure_link(filename: str, user=Depends(require_role("client"))):
    token = fernet.encrypt(filename.encode()).decode()
    return {"secure_url": f"/secure-download/{token}"}

@app.get("/secure-download/{token}")
def download_from_secure_link(token: str, user=Depends(require_role("client"))):
    try:
        filename = fernet.decrypt(token.encode()).decode()
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        return FileResponse(path=file_path, filename=filename, media_type='application/octet-stream')
    except:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

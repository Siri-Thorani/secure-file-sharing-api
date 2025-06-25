# Backend Intern Test – Secure File Sharing System

## ✅ Features
- Client and Ops user registration
- Email verification before login
- JWT-based authentication
- Role-based access (only Ops can upload, only Clients can download)
- Upload support for `.docx`, `.pptx`, `.xlsx` files
- Encrypted download links using Fernet
- SQLite database with SQLAlchemy

## 📦 API Endpoints

### 🔐 Authentication
- `POST /client/signup` – Register a client user
- `GET /client/verify-email/{token}` – Verify email via token
- `POST /login` – Get JWT token

### 📤 OPS Only
- `POST /ops/upload` – Upload files (requires `ops` role)

### 📥 Client Only
- `GET /client/files` – List uploaded files
- `GET /generate-link/{filename}` – Get secure download link
- `GET /secure-download/{token}` – Download using encrypted link

## 🚀 Running the Project

```bash
# Step 1: Install dependencies
pip install -r requirements.txt

# Step 2: Create tables
python create_tables.py

# Step 3: Start the server
uvicorn main:app --reload --port 8001

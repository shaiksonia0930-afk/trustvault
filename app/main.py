# app/main.py - COMPLETE FILE - TrustVault
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="TrustVault - Secure Document Vault",
    description="Security Project - IDOR, JWT Revoke, Per-Person Sharing, Audit Logs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== API ROUTERS - IDI LEKAPOTHE DOCS LO "No operations" VASTHUNDI =====
from app.api import router as api_router
app.include_router(api_router)

# ===== HOMEPAGE - Docs lo kanipinchakudadu ani include_in_schema=False =====
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "index.html")

@app.get("/features", include_in_schema=False)
def features():
    return FileResponse(BASE_DIR / "features.html")

@app.get("/vault", include_in_schema=False)
def vault():
    return FileResponse(BASE_DIR / "vault.html")

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}
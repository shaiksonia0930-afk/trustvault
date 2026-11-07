import os
from fastapi import HTTPException

ALLOWED_MIMES = {
    "application/pdf": ".pdf",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx"
}
MAX_SIZE = 10 * 1024 * 1024  # 10MB

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

def validate_file(file_bytes: bytes, filename: str):
    if len(file_bytes) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Max 10MB allowed")

    mime = None
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_buffer(file_bytes, mime=True)
        except Exception:
            pass

    if mime is None:
        ext = os.path.splitext(filename)[1].lower()
        reverse_map = {v: k for k, v in ALLOWED_MIMES.items()}
        mime = reverse_map.get(ext)

    if mime not in ALLOWED_MIMES:
        raise HTTPException(status_code=400, detail=f"File type not allowed: {mime}. Allowed: pdf, png, jpg, docx")

    # Dummy ClamAV check
    if b"virus" in file_bytes[:200].lower():
        raise HTTPException(status_code=400, detail="Malicious content detected by AV")

    return mime
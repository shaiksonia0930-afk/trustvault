import os
import uuid

STORAGE_PATH = os.getenv("STORAGE_PATH", "./storage")
os.makedirs(STORAGE_PATH, exist_ok=True)

def save_file_service(file_bytes: bytes, mime_type: str):
    ext_map = {
        "application/pdf": ".pdf",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx"
    }
    ext = ext_map.get(mime_type, ".bin")
    stored_name = f"{uuid.uuid4()}{ext}"
    file_path = os.path.join(STORAGE_PATH, stored_name)
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    return stored_name, file_path

def get_file_path_service(stored_filename: str):
    return os.path.join(STORAGE_PATH, stored_filename)

def delete_file_service(stored_filename: str):
    path = get_file_path_service(stored_filename)
    if os.path.exists(path):
        os.remove(path)
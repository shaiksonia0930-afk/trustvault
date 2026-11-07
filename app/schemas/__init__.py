from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: str = "OWNER"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class DocumentOut(BaseModel):
    id: int
    filename: str
    mime_type: str
    file_size: int
    owner_id: int
    created_at: datetime
    class Config:
        from_attributes = True

class PermissionCreate(BaseModel):
    user_email: EmailStr
    can_read: bool = True
    can_edit: bool = False

class AuditOut(BaseModel):
    id: int
    user_id: Optional[int]
    document_id: Optional[int]
    action: str
    ip_address: Optional[str]
    details: Optional[str]
    timestamp: datetime
    class Config:
        from_attributes = True
"""
Response models for the Syft Reviewer Allowlist API
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class AllowlistResponse(BaseModel):
    """Response model for getting the allowlist."""
    emails: List[str]


class AllowlistUpdateRequest(BaseModel):
    """Request model for updating the allowlist."""
    emails: List[str]


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


class JobHistoryItem(BaseModel):
    """Model for a job history item."""
    signature: str
    name: str
    description: Optional[str] = None
    requester_email: str
    tags: List[str] = []
    created_at: Optional[str] = None
    stored_at: Optional[str] = None
    is_trusted_code: bool = False
    code_files: Optional[Dict[str, Any]] = None


class JobHistoryResponse(BaseModel):
    """Response model for job history."""
    jobs: List[JobHistoryItem]
    total_count: int


class TrustedCodeItem(BaseModel):
    """Model for a trusted code item."""
    signature: str
    name: str
    description: Optional[str] = None
    original_requester_email: str
    tags: List[str] = []
    marked_as_trusted_at: Optional[str] = None
    created_at: Optional[str] = None


class TrustedCodeResponse(BaseModel):
    """Response model for trusted code list."""
    trusted_jobs: List[TrustedCodeItem]
    total_count: int


class JobSignatureRequest(BaseModel):
    """Request model for calculating job signature."""
    name: str
    description: Optional[str] = None
    tags: List[str] = []
    code_files: Dict[str, str] = {}


class JobSignatureResponse(BaseModel):
    """Response model for job signature calculation."""
    signature: str
    name: str
    description: Optional[str] = None
    tags: List[str]
    is_trusted: bool = False
    matches_trusted_job: Optional[TrustedCodeItem] = None 
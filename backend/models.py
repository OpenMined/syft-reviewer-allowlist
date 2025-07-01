"""Data models for syft-reviewer-allowlist API."""

from pydantic import BaseModel
from typing import List


class AllowlistResponse(BaseModel):
    """Response model for allowlist endpoints."""
    emails: List[str]


class AllowlistUpdateRequest(BaseModel):
    """Request model for updating the allowlist."""
    emails: List[str]


class MessageResponse(BaseModel):
    """General message response."""
    message: str 
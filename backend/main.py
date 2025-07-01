"""
FastAPI backend for syft-reviewer-allowlist with SyftBox integration
"""

import os
from datetime import datetime
from typing import Dict, Any, List

from fastapi import FastAPI, Depends, HTTPException, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from pathlib import Path as PathLib
from loguru import logger
from syft_core import Client

from .models import (
    AllowlistResponse, AllowlistUpdateRequest, MessageResponse,
    JobHistoryResponse, JobHistoryItem, TrustedCodeResponse, TrustedCodeItem,
    JobSignatureRequest, JobSignatureResponse
)
from .utils import (
    get_allowlist, 
    save_allowlist, 
    add_email_to_allowlist, 
    remove_email_from_allowlist,
    is_email_in_allowlist,
    get_email_file_info,
    # Trusted code functions
    get_job_history,
    store_job_in_history,
    get_trusted_code_list,
    mark_job_as_trusted_code,
    unmark_job_as_trusted_code,
    is_job_trusted_code,
    calculate_job_signature
)


# Initialize SyftBox connection
def get_client() -> Client:
    """Get SyftBox client."""
    try:
        return Client.load()
    except Exception as e:
        logger.error(f"Failed to load SyftBox client: {e}")
        raise HTTPException(status_code=500, detail="SyftBox client not available")


app = FastAPI(
    title="Syft Reviewer Allowlist API",
    description="Manage auto-approval allowlist for code job reviews with individual file permissions and trusted code patterns",
    version="0.3.0",
)

# Add CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:*",
        "http://127.0.0.1:*"
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now()}


@app.get("/api/status")
async def get_status(client: Client = Depends(get_client)) -> Dict[str, Any]:
    """Get application status."""
    return {
        "app": "Syft Reviewer Allowlist",
        "version": "0.3.0",
        "timestamp": datetime.now(),
        "syftbox": {
            "status": "connected",
            "user_email": client.email
        },
        "components": {
            "backend": "running",
            "allowlist": "available",
            "storage": "individual_files",
            "trusted_code": "available"
        }
    }


# === ADMIN ENDPOINTS (Full allowlist management) ===

@app.get(
    "/api/v1/allowlist",
    response_model=AllowlistResponse,
    tags=["allowlist", "admin"],
    summary="Get the complete allowlist (Admin)",
    description="Retrieve the complete list of emails that are auto-approved for code jobs (Admin access)"
)
async def get_allowlist_endpoint(
    client: Client = Depends(get_client),
) -> AllowlistResponse:
    """Get the current allowlist."""
    try:
        emails = get_allowlist(client)
        return AllowlistResponse(emails=emails)
    except Exception as e:
        logger.error(f"Error getting allowlist: {e}")
        raise HTTPException(status_code=500, detail="Failed to get allowlist")


@app.post(
    "/api/v1/allowlist",
    response_model=MessageResponse,
    tags=["allowlist", "admin"],
    summary="Update the complete allowlist (Admin)",
    description="Update the complete list of emails that are auto-approved for code jobs (Admin access)"
)
async def update_allowlist_endpoint(
    client: Client = Depends(get_client),
    emails: List[str] = Body(..., description="List of emails to auto-approve"),
) -> MessageResponse:
    """Update the allowlist."""
    try:
        # Clean the email list (remove empty strings and whitespace)
        cleaned_emails = [email.strip() for email in emails if email.strip()]
        
        # Save the updated allowlist
        save_allowlist(client, cleaned_emails)
        
        logger.info(f"Updated allowlist with {len(cleaned_emails)} emails: {cleaned_emails}")
        
        return MessageResponse(
            message=f"Allowlist updated with {len(cleaned_emails)} emails"
        )
    except Exception as e:
        logger.error(f"Error updating allowlist: {e}")
        raise HTTPException(status_code=500, detail="Failed to update allowlist")


# === PERSONAL ACCESS ENDPOINTS ===

@app.get(
    "/api/v1/allowlist/me",
    tags=["allowlist", "personal"],
    summary="Check if current user is in allowlist",
    description="Check if the current SyftBox user's email is in the allowlist"
)
async def check_my_allowlist_status(
    client: Client = Depends(get_client),
) -> Dict[str, Any]:
    """Check if current user is in the allowlist."""
    try:
        user_email = client.email
        is_allowed = is_email_in_allowlist(client, user_email)
        
        result = {
            "email": user_email,
            "is_in_allowlist": is_allowed
        }
        
        if is_allowed:
            try:
                file_info = get_email_file_info(client, user_email)
                result["file_info"] = file_info
            except Exception as e:
                logger.warning(f"Could not get file info for {user_email}: {e}")
        
        return result
    except Exception as e:
        logger.error(f"Error checking allowlist status for current user: {e}")
        raise HTTPException(status_code=500, detail="Failed to check allowlist status")


@app.get(
    "/api/v1/allowlist/check/{email}",
    tags=["allowlist", "personal"],
    summary="Check if specific email is in allowlist",
    description="Check if a specific email address is in the allowlist (for personal verification)"
)
async def check_email_allowlist_status(
    email: str = Path(..., description="Email address to check"),
    client: Client = Depends(get_client),
) -> Dict[str, Any]:
    """Check if a specific email is in the allowlist."""
    try:
        is_allowed = is_email_in_allowlist(client, email)
        
        result = {
            "email": email,
            "is_in_allowlist": is_allowed
        }
        
        # Only provide file info if the requester is checking their own email
        # or if they're an admin (for now, we'll be restrictive)
        current_user = client.email
        if is_allowed and (email == current_user):
            try:
                file_info = get_email_file_info(client, email)
                result["file_info"] = file_info
            except Exception as e:
                logger.warning(f"Could not get file info for {email}: {e}")
        
        return result
    except Exception as e:
        logger.error(f"Error checking allowlist status for {email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to check allowlist status")


@app.post(
    "/api/v1/allowlist/add/{email}",
    response_model=MessageResponse,
    tags=["allowlist", "admin"],
    summary="Add email to allowlist (Admin)",
    description="Add a single email to the allowlist (Admin access)"
)
async def add_email_endpoint(
    email: str = Path(..., description="Email address to add"),
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Add a single email to the allowlist."""
    try:
        add_email_to_allowlist(client, email.strip())
        logger.info(f"Added {email} to allowlist")
        
        return MessageResponse(message=f"Email {email} added to allowlist")
    except Exception as e:
        logger.error(f"Error adding {email} to allowlist: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add {email} to allowlist")


@app.delete(
    "/api/v1/allowlist/remove/{email}",
    response_model=MessageResponse,
    tags=["allowlist", "admin"],
    summary="Remove email from allowlist (Admin)",
    description="Remove a single email from the allowlist (Admin access)"
)
async def remove_email_endpoint(
    email: str = Path(..., description="Email address to remove"),
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Remove a single email from the allowlist."""
    try:
        remove_email_from_allowlist(client, email.strip())
        logger.info(f"Removed {email} from allowlist")
        
        return MessageResponse(message=f"Email {email} removed from allowlist")
    except Exception as e:
        logger.error(f"Error removing {email} from allowlist: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove {email} from allowlist")


# === TRUSTED CODE ENDPOINTS ===

@app.get(
    "/api/v1/trusted-code/history",
    response_model=JobHistoryResponse,
    tags=["trusted-code", "admin"],
    summary="Get job history",
    description="Get the history of completed jobs that can be marked as trusted code"
)
async def get_job_history_endpoint(
    limit: int = 50,
    client: Client = Depends(get_client),
) -> JobHistoryResponse:
    """Get job history."""
    try:
        jobs_data = get_job_history(client, limit=limit)
        
        jobs = []
        for job_data in jobs_data:
            jobs.append(JobHistoryItem(
                signature=job_data.get("signature", ""),
                name=job_data.get("name", ""),
                description=job_data.get("description"),
                requester_email=job_data.get("requester_email", ""),
                tags=job_data.get("tags", []),
                created_at=job_data.get("created_at"),
                stored_at=job_data.get("stored_at"),
                is_trusted_code=job_data.get("is_trusted_code", False),
                code_files=job_data.get("code_files")
            ))
        
        return JobHistoryResponse(jobs=jobs, total_count=len(jobs))
    except Exception as e:
        logger.error(f"Error getting job history: {e}")
        raise HTTPException(status_code=500, detail="Failed to get job history")


@app.get(
    "/api/v1/trusted-code",
    response_model=TrustedCodeResponse,
    tags=["trusted-code", "admin"],
    summary="Get trusted code list",
    description="Get the list of jobs marked as trusted code patterns"
)
async def get_trusted_code_endpoint(
    client: Client = Depends(get_client),
) -> TrustedCodeResponse:
    """Get trusted code list."""
    try:
        trusted_jobs_data = get_trusted_code_list(client)
        
        trusted_jobs = []
        for job_data in trusted_jobs_data:
            trusted_jobs.append(TrustedCodeItem(
                signature=job_data.get("signature", ""),
                name=job_data.get("name", ""),
                description=job_data.get("description"),
                original_requester_email=job_data.get("requester_email", ""),
                tags=job_data.get("tags", []),
                marked_as_trusted_at=job_data.get("marked_as_trusted_at"),
                created_at=job_data.get("created_at")
            ))
        
        return TrustedCodeResponse(trusted_jobs=trusted_jobs, total_count=len(trusted_jobs))
    except Exception as e:
        logger.error(f"Error getting trusted code list: {e}")
        raise HTTPException(status_code=500, detail="Failed to get trusted code list")


@app.post(
    "/api/v1/trusted-code/mark/{job_signature}",
    response_model=MessageResponse,
    tags=["trusted-code", "admin"],
    summary="Mark job as trusted code (Admin)",
    description="Mark a job from history as trusted code that will be auto-approved from any sender"
)
async def mark_trusted_code_endpoint(
    job_signature: str = Path(..., description="Job signature to mark as trusted"),
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Mark a job as trusted code."""
    try:
        mark_job_as_trusted_code(client, job_signature)
        logger.info(f"Marked job as trusted code: {job_signature[:12]}...")
        
        return MessageResponse(message=f"Job marked as trusted code")
    except Exception as e:
        logger.error(f"Error marking job as trusted code: {e}")
        raise HTTPException(status_code=500, detail="Failed to mark job as trusted code")


@app.delete(
    "/api/v1/trusted-code/unmark/{job_signature}",
    response_model=MessageResponse,
    tags=["trusted-code", "admin"],
    summary="Remove job from trusted code (Admin)",
    description="Remove a job from the trusted code list"
)
async def unmark_trusted_code_endpoint(
    job_signature: str = Path(..., description="Job signature to remove from trusted code"),
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Remove a job from trusted code."""
    try:
        unmark_job_as_trusted_code(client, job_signature)
        logger.info(f"Removed job from trusted code: {job_signature[:12]}...")
        
        return MessageResponse(message=f"Job removed from trusted code")
    except Exception as e:
        logger.error(f"Error removing job from trusted code: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove job from trusted code")


@app.post(
    "/api/v1/trusted-code/check-signature",
    response_model=JobSignatureResponse,
    tags=["trusted-code", "utility"],
    summary="Calculate and check job signature",
    description="Calculate a job signature and check if it matches any trusted code pattern"
)
async def check_job_signature_endpoint(
    job_request: JobSignatureRequest,
    client: Client = Depends(get_client),
) -> JobSignatureResponse:
    """Calculate and check job signature."""
    try:
        job_data = job_request.model_dump()
        signature = calculate_job_signature(job_data)
        
        # Check if this matches any trusted code
        trusted_match = is_job_trusted_code(client, job_data)
        is_trusted = trusted_match is not None
        
        matches_trusted_job = None
        if trusted_match:
            matches_trusted_job = TrustedCodeItem(
                signature=trusted_match.get("signature", ""),
                name=trusted_match.get("name", ""),
                description=trusted_match.get("description"),
                original_requester_email=trusted_match.get("requester_email", ""),
                tags=trusted_match.get("tags", []),
                marked_as_trusted_at=trusted_match.get("marked_as_trusted_at"),
                created_at=trusted_match.get("created_at")
            )
        
        return JobSignatureResponse(
            signature=signature,
            name=job_request.name,
            description=job_request.description,
            tags=job_request.tags,
            is_trusted=is_trusted,
            matches_trusted_job=matches_trusted_job
        )
    except Exception as e:
        logger.error(f"Error checking job signature: {e}")
        raise HTTPException(status_code=500, detail="Failed to check job signature")


@app.post(
    "/api/v1/trusted-code/add-to-history",
    response_model=MessageResponse,
    tags=["trusted-code", "admin"],
    summary="Add job to history (Admin)",
    description="Manually add a job to the history (typically done automatically when jobs complete)"
)
async def add_job_to_history_endpoint(
    job_request: JobSignatureRequest,
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Add a job to the history."""
    try:
        job_data = job_request.model_dump()
        signature = store_job_in_history(client, job_data)
        
        return MessageResponse(message=f"Job added to history with signature: {signature[:12]}...")
    except Exception as e:
        logger.error(f"Error adding job to history: {e}")
        raise HTTPException(status_code=500, detail="Failed to add job to history")


# Serve the HTML interface
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main allowlist management interface."""
    try:
        html_file = PathLib(__file__).parent / "templates" / "index.html"
        if html_file.exists():
            return HTMLResponse(html_file.read_text())
        else:
            return HTMLResponse("""
                <html>
                    <body>
                        <h1>Syft Reviewer Allowlist</h1>
                        <p>HTML template not found. API is running at <a href="/docs">/docs</a></p>
                        <p>Storage: Individual files with permissions</p>
                        <p>Features: Email allowlist + Trusted code patterns</p>
                    </body>
                </html>
            """)
    except Exception as e:
        logger.error(f"Error serving HTML: {e}")
        return HTMLResponse(f"<html><body><h1>Error</h1><p>{e}</p></body></html>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002) 
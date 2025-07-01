"""
FastAPI backend for syft-reviewer-allowlist with SyftBox integration
"""

import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Union

from fastapi import FastAPI, Depends, HTTPException, Body, Path, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from pathlib import Path as PathLib
from loguru import logger
from syft_core import Client

from .models import (
    AllowlistResponse, AllowlistUpdateRequest, MessageResponse,
    JobHistoryResponse, JobHistoryItem, TrustedCodeResponse, TrustedCodeItem,
    JobSignatureRequest, JobSignatureResponse, JobActionRequest
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
    calculate_job_signature,
    # Decision history functions
    get_decision_history,
    log_job_decision,
    clear_old_decisions
)

try:
    import syft_code_queue as q
except ImportError:
    logger.error("syft-code-queue not available - job browsing features will be limited")
    q = None


# Helper functions
def _get_file_type(file_path: str) -> str:
    """Determine file type based on extension."""
    file_path = str(file_path).lower()
    
    if file_path.endswith(('.py', '.pyw')):
        return 'python'
    elif file_path.endswith(('.js', '.mjs')):
        return 'javascript'
    elif file_path.endswith('.ts'):
        return 'typescript'
    elif file_path.endswith('.sh'):
        return 'shell'
    elif file_path.endswith('.md'):
        return 'markdown'
    elif file_path.endswith('.json'):
        return 'json'
    elif file_path.endswith(('.yml', '.yaml')):
        return 'yaml'
    elif file_path.endswith('.sql'):
        return 'sql'
    elif file_path.endswith('.csv'):
        return 'csv'
    elif file_path.endswith(('.txt', '.log')):
        return 'text'
    else:
        return 'text'


def _is_dummy_content(content: str) -> bool:
    """Check if content appears to be dummy/placeholder content."""
    dummy_indicators = [
        "Privacy-safe Customer Behavior Analysis",
        "using differential privacy techniques to ensure individual privacy protection",
        "This script performs privacy-preserving analysis",
        "# Privacy-safe customer behavior analysis script"
    ]
    return any(indicator in content for indicator in dummy_indicators)


def _try_reload_real_file_content(job_data: dict, file_path: str) -> Optional[str]:
    """Try to reload real file content using syft-code-queue if available."""
    try:
        if not q:
            return None
        
        # Try to find the job by UID
        job_uid = job_data.get("uid")
        if not job_uid:
            return None
        
        # Try to get the job from syft-code-queue
        job = q.get_job(job_uid)
        if not job:
            return None
        
        # Try to read the file content
        content = job.read_file(file_path)
        if content and not _is_dummy_content(content):
            return content
        
        # Also try the code structure approach
        if hasattr(job, 'get_code_structure'):
            structure = job.get_code_structure()
            if structure and 'files' in structure:
                file_info = structure['files'].get(file_path)
                if file_info and isinstance(file_info, dict):
                    structure_content = file_info.get('content')
                    if structure_content and not _is_dummy_content(structure_content):
                        return structure_content
        
        return None
    
    except Exception as e:
        logger.warning(f"Error trying to reload real content: {e}")
        return None


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
            "trusted_code": "available",
            "job_browser": "enabled" if q else "disabled"
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
    force: bool = False  # Add force parameter for power users
) -> MessageResponse:
    """Remove a single email from the allowlist."""
    try:
        # Get current allowlist
        current_allowlist = get_allowlist(client)
        logger.info(f"Current allowlist before removal: {current_allowlist}")
        
        # Safety check: prevent removing the last email unless forced
        if len(current_allowlist) <= 1 and not force:
            logger.warning(f"Attempted to remove last email {email} from allowlist (blocked for safety)")
            raise HTTPException(
                status_code=400, 
                detail="Cannot remove the last email from allowlist. Add another trusted sender first, or use ?force=true to override this safety check."
            )
        
        # Check if email is actually in the allowlist
        if email.strip() not in current_allowlist:
            logger.warning(f"Attempted to remove {email} but it's not in allowlist: {current_allowlist}")
            raise HTTPException(status_code=404, detail=f"Email {email} is not in the allowlist")
        
        # Remove the email
        remove_email_from_allowlist(client, email.strip())
        logger.info(f"Successfully removed {email} from allowlist")
        
        # Verify removal
        updated_allowlist = get_allowlist(client)
        logger.info(f"Updated allowlist after removal: {updated_allowlist}")
        
        if email.strip() in updated_allowlist:
            logger.error(f"Email {email} still in allowlist after removal attempt!")
            raise HTTPException(status_code=500, detail=f"Email {email} was not successfully removed from allowlist")
        
        return MessageResponse(message=f"Email {email} removed from allowlist")
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Error removing {email} from allowlist: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove {email} from allowlist: {str(e)}")


@app.get(
    "/api/v1/allowlist/senders",
    tags=["allowlist", "admin"],
    summary="Get all senders who have submitted jobs",
    description="Get list of all email addresses that have submitted jobs, along with their allowlist status"
)
async def get_all_senders_endpoint(
    client: Client = Depends(get_client),
) -> Dict[str, Any]:
    """Get all senders and their allowlist status."""
    try:
        # Get decision history to find all senders
        decisions = get_decision_history(client, limit=1000)
        
        # Get job history to find additional senders
        job_history = get_job_history(client, limit=1000)
        
        # Collect all unique email addresses
        all_emails = set()
        
        # From decision history
        for decision in decisions:
            if decision.get("requester_email"):
                all_emails.add(decision["requester_email"])
        
        # From job history
        for job in job_history:
            if job.get("requester_email"):
                all_emails.add(job["requester_email"])
        
        # Also try to get from syft-code-queue if available
        if q:
            try:
                # Get all jobs from syft-code-queue
                all_jobs = []
                try:
                    all_jobs.extend(q.jobs_for_me or [])
                except:
                    pass
                try:
                    all_jobs.extend(q.jobs_for_others or [])
                except:
                    pass
                
                for job in all_jobs:
                    if hasattr(job, 'requester_email') and job.requester_email:
                        all_emails.add(job.requester_email)
            except Exception as e:
                logger.warning(f"Could not get jobs from syft-code-queue: {e}")
        
        # Get current allowlist
        allowlist = get_allowlist(client)
        allowlist_set = set(allowlist)
        
        # Add all allowlist emails to the list (even if they haven't submitted jobs yet)
        all_emails.update(allowlist)
        
        # Create sender info
        senders = []
        for email in sorted(all_emails):
            # Count recent activity (last 100 decisions)
            recent_decisions = [d for d in decisions[:100] if d.get("requester_email") == email]
            
            sender_info = {
                "email": email,
                "is_trusted": email in allowlist_set,
                "recent_activity": len(recent_decisions),
                "last_seen": recent_decisions[0]["timestamp"] if recent_decisions else None,
                "actions": {
                    "approved": len([d for d in recent_decisions if d.get("action") == "approve"]),
                    "ignored": len([d for d in recent_decisions if d.get("action") == "ignore"]),
                    "failed": len([d for d in recent_decisions if d.get("action") == "failed_approval"])
                }
            }
            senders.append(sender_info)
        
        return {
            "senders": senders,
            "total_count": len(senders),
            "trusted_count": len(allowlist),
            "untrusted_count": len(senders) - len([s for s in senders if s["is_trusted"]])
        }
    
    except Exception as e:
        logger.error(f"Error getting senders: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get senders: {str(e)}")


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


# Job Browser Endpoints

@app.get("/api/v1/jobs/history-for-review")
async def get_job_history_for_review(client: Client = Depends(get_client)):
    """Get job history for code review and trusted code management."""
    try:
        job_history = get_job_history(client, limit=50)  # Get more jobs for review
        
        # Add trusted code status to each job
        trusted_patterns = get_trusted_code_list(client)
        trusted_signatures = {item["signature"] for item in trusted_patterns}
        
        for job in job_history:
            job["is_trusted"] = job["signature"] in trusted_signatures
        
        return {
            "jobs": job_history,
            "total_count": len(job_history)
        }
    
    except Exception as e:
        logger.error(f"Error getting job history for review: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get job history: {str(e)}")


@app.get("/api/v1/jobs/history/{signature}/files")
async def get_job_files_from_history(signature: str, client: Client = Depends(get_client)):
    """Get file listing for a job from history by signature."""
    try:
        job_history = get_job_history(client, limit=100)
        
        # Find the job with matching signature
        target_job = None
        for job in job_history:
            if job["signature"] == signature:
                target_job = job
                break
        
        if not target_job:
            raise HTTPException(status_code=404, detail="Job not found in history")
        
        # Extract file information from job data
        files = []
        code_files = target_job.get("code_files", {})
        
        if isinstance(code_files, dict):
            for file_path, content in code_files.items():
                file_info = {
                    "path": file_path,
                    "name": PathLib(file_path).name,
                    "size": len(str(content)) if content else 0,
                    "type": _get_file_type(file_path)
                }
                files.append(file_info)
        elif isinstance(code_files, list):
            for file_path in code_files:
                file_info = {
                    "path": file_path,
                    "name": PathLib(file_path).name,
                    "size": 0,  # Size unknown for file paths only
                    "type": _get_file_type(file_path)
                }
                files.append(file_info)
        
        return {"files": files}
    
    except Exception as e:
        logger.error(f"Error getting job files from history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get job files: {str(e)}")


@app.get("/api/v1/jobs/history/{signature}/files/{file_path:path}")
async def get_job_file_content_from_history(signature: str, file_path: str, client: Client = Depends(get_client)):
    """Get content of a specific file from a job in history."""
    try:
        job_history = get_job_history(client, limit=100)
        
        # Find the job with matching signature
        target_job = None
        for job in job_history:
            if job["signature"] == signature:
                target_job = job
                break
        
        if not target_job:
            raise HTTPException(status_code=404, detail="Job not found in history")
        
        # Get file content from job data
        code_files = target_job.get("code_files", {})
        content = None
        
        if isinstance(code_files, dict):
            content = code_files.get(file_path)
        
        if content is None:
            raise HTTPException(status_code=404, detail="File not found in job history")
        
        # Check if this is dummy content and try to reload real content
        if _is_dummy_content(str(content)):
            logger.info(f"Detected dummy content for {file_path}, attempting to reload real content")
            try:
                real_content = _try_reload_real_file_content(target_job, file_path)
                if real_content:
                    content = real_content
                    logger.info(f"Successfully reloaded real content for {file_path}")
            except Exception as e:
                logger.warning(f"Could not reload real content for {file_path}: {e}")
        
        return {
            "content": str(content),
            "file_path": file_path,
            "file_type": _get_file_type(file_path),
            "size": len(str(content)),
            "is_dummy": _is_dummy_content(str(content))
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job file content from history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get file content: {str(e)}")


@app.post("/api/v1/jobs/history/{signature}/mark-trusted")
async def mark_job_as_trusted_from_history(signature: str, client: Client = Depends(get_client)):
    """Mark a job from history as trusted code."""
    try:
        # Mark as trusted - the function will check if the job exists in history
        mark_job_as_trusted_code(client, signature)
        
        logger.info(f"🔒 Marked job as trusted code: {signature[:12]}... (Manual marking from code review)")
        return MessageResponse(message=f"Job marked as trusted code")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error marking job as trusted: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to mark as trusted: {str(e)}")


@app.post("/api/v1/jobs/history/refresh-content")
async def refresh_job_content(client: Client = Depends(get_client)):
    """Refresh job history content (convert filename lists to demo content)."""
    try:
        from .utils import get_job_history_dir_path, store_job_in_history
        import json
        
        history_dir = get_job_history_dir_path(client)
        if not history_dir.exists():
            return MessageResponse(message="No job history found")
        
        refreshed_count = 0
        for job_file in history_dir.glob("*.json"):
            try:
                job_data = json.loads(job_file.read_text())
                
                # Check if code_files is a list (filenames only)
                if isinstance(job_data.get("code_files"), list):
                    # Re-store the job to trigger content population
                    store_job_in_history(client, job_data)
                    refreshed_count += 1
                    
            except Exception as e:
                logger.warning(f"Could not refresh job {job_file.name}: {e}")
        
        return MessageResponse(message=f"Refreshed {refreshed_count} job(s) with demo content")
    
    except Exception as e:
        logger.error(f"Error refreshing job content: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to refresh content: {str(e)}")


# Decision History Endpoints

@app.get(
    "/api/v1/decisions/history",
    tags=["decisions", "admin"],
    summary="Get decision history",
    description="Get the history of decisions made by the auto-approval system"
)
async def get_decision_history_endpoint(
    limit: int = 100,
    client: Client = Depends(get_client),
) -> Dict[str, Any]:
    """Get the decision history."""
    try:
        decisions = get_decision_history(client, limit=limit)
        
        return {
            "decisions": decisions,
            "total_count": len(decisions)
        }
    
    except Exception as e:
        logger.error(f"Error getting decision history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get decision history: {str(e)}")


@app.delete(
    "/api/v1/decisions/history/clear",
    response_model=MessageResponse,
    tags=["decisions", "admin"],
    summary="Clear old decision history",
    description="Clear decision history older than specified days"
)
async def clear_decision_history_endpoint(
    keep_days: int = 30,
    client: Client = Depends(get_client),
) -> MessageResponse:
    """Clear old decision history."""
    try:
        cleared_count = clear_old_decisions(client, keep_days=keep_days)
        
        return MessageResponse(
            message=f"Cleared {cleared_count} decision record(s) older than {keep_days} days"
        )
    
    except Exception as e:
        logger.error(f"Error clearing decision history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear decision history: {str(e)}")


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
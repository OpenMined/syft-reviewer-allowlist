"""
FastAPI backend for syft-reviewer-allowlist with SyftBox integration
"""

import os
from datetime import datetime
from typing import Dict, Any, List

from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from pathlib import Path
from loguru import logger
from syft_core import Client

from .models import AllowlistResponse, AllowlistUpdateRequest, MessageResponse
from .utils import get_allowlist, save_allowlist


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
    description="Manage auto-approval allowlist for code job reviews",
    version="0.1.0",
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
        "version": "0.1.0",
        "timestamp": datetime.now(),
        "syftbox": {
            "status": "connected",
            "user_email": client.email
        },
        "components": {
            "backend": "running",
            "allowlist": "available"
        }
    }


@app.get(
    "/api/v1/allowlist",
    response_model=AllowlistResponse,
    tags=["allowlist"],
    summary="Get the allowlist",
    description="Retrieve the list of emails that are auto-approved for code jobs"
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
    tags=["allowlist"],
    summary="Update the allowlist",
    description="Update the list of emails that are auto-approved for code jobs"
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


# Serve the HTML interface
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main allowlist management interface."""
    try:
        html_file = Path(__file__).parent / "templates" / "index.html"
        if html_file.exists():
            return HTMLResponse(html_file.read_text())
        else:
            return HTMLResponse("""
                <html>
                    <body>
                        <h1>Syft Reviewer Allowlist</h1>
                        <p>HTML template not found. API is running at <a href="/docs">/docs</a></p>
                    </body>
                </html>
            """)
    except Exception as e:
        logger.error(f"Error serving HTML: {e}")
        return HTMLResponse(f"<html><body><h1>Error</h1><p>{e}</p></body></html>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002) 
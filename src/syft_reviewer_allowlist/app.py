#!/usr/bin/env python3
"""
Syft Reviewer Allowlist App - SyftBox Integration

This module runs as a SyftBox app, continuously polling for pending jobs
and auto-approving those from trusted senders in the allowlist or matching trusted code patterns.
"""

import time
import signal
import sys
from datetime import datetime
from time import sleep
from typing import List, Optional, Dict, Any

from loguru import logger

# Configure loguru to output to stdout for SyftUI logs
logger.remove()  # Remove default handler
logger.add(sys.stdout, format="{time:HH:mm:ss}\t{level}\t{message}", level="INFO")

def log_to_syftui(message: str, level: str = "INFO"):
    """Ensure logs appear in SyftUI by using both print and loguru."""
    print(f"{datetime.now().strftime('%H:%M:%S')}\t{level}\t{message}")
    sys.stdout.flush()  # Force immediate output

try:
    from syft_core import Client as SyftBoxClient
except ImportError:
    logger.warning("syft_core not available - using mock client")
    # Fallback for development/testing
    class MockSyftBoxClient:
        def __init__(self):
            self.email = "demo@example.com"
        
        @classmethod
        def load(cls):
            return cls()
    
    SyftBoxClient = MockSyftBoxClient

try:
    import syft_code_queue as q
except ImportError:
    logger.error("syft-code-queue not available - this is required for the app to function")
    sys.exit(1)

# Import our backend utils for allowlist and trusted code management
try:
    import sys
    import os
    # Add the backend directory to the Python path
    backend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "backend")
    sys.path.insert(0, backend_path)
    from utils import get_allowlist, is_job_trusted_code, store_job_in_history
except ImportError:
    log_to_syftui("⚠️ Backend utils not available - using basic functionality", "WARN")
    get_allowlist = None
    is_job_trusted_code = None
    store_job_in_history = None


class ReviewerAllowlistApp:
    """App that automatically approves jobs from trusted senders and trusted code patterns."""
    
    def __init__(self, poll_interval: int = 1):
        """
        Initialize the app.
        
        Args:
            poll_interval: Seconds between polling cycles
        """
        try:
            self.syftbox_client = SyftBoxClient.load()
            self.poll_interval = poll_interval
            self.allowlist = self._load_allowlist()
            
            log_to_syftui(f"✅ Initialized Reviewer Allowlist App for {self.email}")
            log_to_syftui(f"📝 Trusted senders: {', '.join(self.allowlist)}")
            log_to_syftui(f"🔒 Trusted code patterns: enabled")
            log_to_syftui(f"⏰ Polling every {poll_interval} second(s)")
            
        except Exception as e:
            log_to_syftui(f"❌ Could not initialize Reviewer Allowlist App: {e}", "ERROR")
            # Set up in demo mode
            self.syftbox_client = SyftBoxClient()
            self.poll_interval = poll_interval
            self.allowlist = ["andrew@openmined.org"]  # Fallback default
    
    @property
    def email(self) -> str:
        """Get the current user's email."""
        return self.syftbox_client.email
    
    def _load_allowlist(self) -> List[str]:
        """Load the allowlist from the saved file."""
        try:
            if get_allowlist is not None:
                allowlist = get_allowlist(self.syftbox_client)
                log_to_syftui(f"📂 Loaded allowlist from file: {allowlist}")
                return allowlist
            else:
                log_to_syftui("⚠️ Using fallback allowlist", "WARN")
                return ["andrew@openmined.org"]
        except Exception as e:
            log_to_syftui(f"❌ Error loading allowlist, using default: {e}", "ERROR")
            return ["andrew@openmined.org"]
    
    def _refresh_allowlist(self):
        """Refresh the allowlist from the file."""
        try:
            new_allowlist = self._load_allowlist()
            if new_allowlist != self.allowlist:
                old_list = self.allowlist.copy()
                self.allowlist = new_allowlist
                log_to_syftui(f"🔄 Allowlist updated: {old_list} → {new_allowlist}")
        except Exception as e:
            log_to_syftui(f"❌ Error refreshing allowlist: {e}", "ERROR")
    
    def _extract_job_data(self, job) -> Dict[str, Any]:
        """
        Extract job data for trusted code comparison.
        
        Args:
            job: CodeJob object from syft-code-queue
            
        Returns:
            Dictionary containing job data for signature calculation
        """
        try:
            # Get basic job information
            job_data = {
                "name": getattr(job, 'name', ''),
                "description": getattr(job, 'description', ''),
                "tags": getattr(job, 'tags', []),
                "requester_email": getattr(job, 'requester_email', ''),
                "code_files": {}
            }
            
            # Try to get code files if available
            try:
                if hasattr(job, 'get_review_data'):
                    review_data = job.get_review_data()
                    if review_data and 'code_files' in review_data:
                        job_data['code_files'] = review_data['code_files']
                elif hasattr(job, 'code_folder') and job.code_folder:
                    # Try to read code files directly
                    from pathlib import Path
                    code_folder = Path(job.code_folder)
                    if code_folder.exists():
                        for code_file in code_folder.rglob('*'):
                            if code_file.is_file():
                                try:
                                    relative_path = str(code_file.relative_to(code_folder))
                                    job_data['code_files'][relative_path] = code_file.read_text(encoding='utf-8', errors='ignore')
                                except Exception:
                                    # Skip files that can't be read
                                    pass
            except Exception as e:
                log_to_syftui(f"⚠️ Could not extract code files for job '{job_data['name']}': {e}", "WARN")
            
            return job_data
            
        except Exception as e:
            log_to_syftui(f"❌ Error extracting job data: {e}", "ERROR")
            return {
                "name": str(job),
                "description": "",
                "tags": [],
                "requester_email": getattr(job, 'requester_email', ''),
                "code_files": {}
            }
    
    def _store_completed_job_in_history(self, job):
        """Store a completed job in history for potential trusted code marking."""
        try:
            if store_job_in_history is not None:
                job_data = self._extract_job_data(job)
                signature = store_job_in_history(self.syftbox_client, job_data)
                log_to_syftui(f"📚 Stored job in history: {job_data['name']} -> {signature[:12]}...")
        except Exception as e:
            log_to_syftui(f"⚠️ Could not store job in history: {e}", "WARN")
    
    def run(self):
        """
        Start continuous job polling and auto-approval.
        """
        log_to_syftui(f"🔄 Starting continuous job polling...")
        log_to_syftui(f"⏰ Checking every {self.poll_interval} second(s) for jobs from trusted senders and trusted code")
        
        # Set up graceful shutdown
        def signal_handler(signum, frame):
            log_to_syftui("👋 Shutting down gracefully...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        cycle = 0
        while True:
            try:
                # Process one cycle
                self._process_cycle(cycle)
                cycle += 1
                
                # Sleep until next cycle
                sleep(self.poll_interval)
            
            except KeyboardInterrupt:
                log_to_syftui("👋 Shutting down...")
                break
            except Exception as e:
                log_to_syftui(f"❌ Error in processing cycle {cycle}: {e}", "ERROR")
                # Continue running despite errors
                sleep(self.poll_interval)
    
    def _process_cycle(self, cycle: int):
        """Process one polling cycle."""
        
        # Log cycle number periodically (every 60 cycles = 1 minute at 1s intervals)
        verbose_logging = cycle % 60 == 0
        if verbose_logging:
            log_to_syftui(f"⏰ Polling cycle {cycle} - checking for pending jobs...")
        
        # Refresh allowlist every 30 seconds (30 cycles at 1s intervals)
        if cycle % 30 == 0:
            self._refresh_allowlist()
        
        # Check for pending jobs and auto-approve from allowlist or trusted code
        self._auto_approve_jobs(verbose_logging=verbose_logging)
    
    def _auto_approve_jobs(self, verbose_logging: bool = False):
        """Auto-approve jobs from allowlist senders or matching trusted code patterns."""
        try:
            # Get all jobs pending for me
            pending_jobs = q.pending_for_me
            
            if not pending_jobs:
                # Don't log when no jobs - too verbose for continuous polling
                return
            
            # Only log detailed status every 60 seconds
            if verbose_logging:
                log_to_syftui(f"📋 Found {len(pending_jobs)} job(s) pending approval")
            
            # Separate jobs by approval reason
            email_approved_jobs = []
            trusted_code_jobs = []
            untrusted_jobs = []
            
            for job in pending_jobs:
                job_approved = False
                approval_reason = ""
                
                # Check email allowlist first
                if job.requester_email in self.allowlist:
                    email_approved_jobs.append(job)
                    approval_reason = f"trusted sender ({job.requester_email})"
                    job_approved = True
                    if verbose_logging:
                        log_to_syftui(f"✅ Job '{job.name}' from {job.requester_email} - TRUSTED SENDER")
                
                # If not from trusted sender, check trusted code patterns
                elif is_job_trusted_code is not None:
                    try:
                        job_data = self._extract_job_data(job)
                        trusted_match = is_job_trusted_code(self.syftbox_client, job_data)
                        if trusted_match:
                            trusted_code_jobs.append((job, trusted_match))
                            approval_reason = f"trusted code pattern (signature: {trusted_match.get('signature', 'unknown')[:12]}...)"
                            job_approved = True
                            if verbose_logging:
                                log_to_syftui(f"🔒 Job '{job.name}' from {job.requester_email} - TRUSTED CODE PATTERN")
                    except Exception as e:
                        log_to_syftui(f"⚠️ Error checking trusted code for job '{job.name}': {e}", "WARN")
                
                if not job_approved:
                    untrusted_jobs.append(job)
                    if verbose_logging:
                        log_to_syftui(f"⚠️  Job '{job.name}' from {job.requester_email} - NOT IN ALLOWLIST OR TRUSTED CODE")
            
            # Log summary if no approvals but jobs exist
            if not email_approved_jobs and not trusted_code_jobs:
                if verbose_logging and len(pending_jobs) > 0:
                    log_to_syftui("🚫 No jobs from trusted senders or matching trusted code found")
                return
            
            total_approved = len(email_approved_jobs) + len(trusted_code_jobs)
            log_to_syftui(f"🚀 Auto-approving {total_approved} job(s)...")
            
            # Auto-approve jobs from trusted senders
            approved_count = 0
            failed_count = 0
            
            # Process email-approved jobs
            for job in email_approved_jobs:
                success = self._approve_job(job, f"trusted sender ({job.requester_email})")
                if success:
                    approved_count += 1
                else:
                    failed_count += 1
            
            # Process trusted-code-approved jobs
            for job, trusted_match in trusted_code_jobs:
                signature = trusted_match.get('signature', 'unknown')[:12]
                success = self._approve_job(job, f"trusted code pattern ({signature}...)")
                if success:
                    approved_count += 1
                else:
                    failed_count += 1
            
            # Log summary
            if approved_count > 0 or failed_count > 0:
                log_to_syftui(f"📊 Summary: {approved_count} approved, {failed_count} failed")
            
        except Exception as e:
            log_to_syftui(f"❌ Error during auto-approval check: {e}", "ERROR")
    
    def _approve_job(self, job, reason: str) -> bool:
        """
        Approve a single job with the given reason.
        
        Args:
            job: CodeJob to approve
            reason: Reason for approval
            
        Returns:
            True if successful, False otherwise
        """
        try:
            approval_reason = f"Auto-approved ({reason}) at {datetime.now().isoformat()}"
            success = job.approve(approval_reason)
            
            if success:
                log_to_syftui(f"✅ Approved: '{job.name}' from {job.requester_email} ({reason})")
                
                # Store completed jobs in history for potential trusted code marking
                if job.status.value == 'completed':
                    self._store_completed_job_in_history(job)
                    
                return True
            else:
                log_to_syftui(f"❌ Failed to approve: '{job.name}' from {job.requester_email}", "ERROR")
                return False
                
        except Exception as e:
            log_to_syftui(f"❌ Error approving '{job.name}': {e}", "ERROR")
            return False


def main():
    """Main entry point for the SyftBox app."""
    
    log_to_syftui("🤖 Syft Reviewer Allowlist - Auto-approval Service")
    log_to_syftui("=" * 60)
    log_to_syftui("📝 Email allowlist managed via web UI")
    log_to_syftui("🔒 Trusted code patterns managed via web UI")
    log_to_syftui("🌐 Access the UI at your app's assigned port")
    
    try:
        app = ReviewerAllowlistApp(
            poll_interval=1  # Check every second
        )
        app.run()
        
    except Exception as e:
        log_to_syftui(f"❌ App failed: {e}", "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main() 
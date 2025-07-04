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
from typing import List, Optional, Dict, Any, Set

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
    from utils import get_allowlist, is_job_trusted_code, store_job_in_history, log_job_decision
except ImportError:
    log_to_syftui("⚠️ Backend utils not available - using basic functionality", "WARN")
    get_allowlist = None
    is_job_trusted_code = None
    store_job_in_history = None
    log_job_decision = None


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
            self.processed_job_ids: Set[str] = set()  # Track jobs we've already stored in history
            self.ignored_job_ids: Set[str] = set()  # Track jobs we've already ignored (to prevent spam)
            self.last_allowlist_update = datetime.now()  # Track when allowlist was last updated
            self.last_trusted_code_update = datetime.now()  # Track when trusted code was last updated
            
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
            self.processed_job_ids: Set[str] = set()
            self.ignored_job_ids: Set[str] = set()
            self.last_allowlist_update = datetime.now()
            self.last_trusted_code_update = datetime.now()
    
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
                self.last_allowlist_update = datetime.now()
                # Clear ignored jobs when allowlist changes - they should be re-evaluated
                self.ignored_job_ids.clear()
                log_to_syftui(f"🔄 Allowlist updated: {old_list} → {new_allowlist}")
                log_to_syftui(f"🔄 Cleared ignored jobs cache - will re-evaluate pending jobs")
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
                "description": getattr(job, 'description', '') or '',
                "tags": getattr(job, 'tags', []) or [],
                "requester_email": getattr(job, 'requester_email', ''),
                "created_at": getattr(job, 'created_at', None),
                "uid": str(getattr(job, 'uid', '')),
                "code_files": {}
            }
            
            # Try to get code files using various approaches
            code_files_found = False
            
            try:
                # Method 1: Try get_review_data
                if hasattr(job, 'get_review_data'):
                    review_data = job.get_review_data()
                    if review_data and 'code_files' in review_data:
                        job_data['code_files'] = review_data['code_files']
                        code_files_found = True
            except Exception as e:
                log_to_syftui(f"⚠️ Method 1 (get_review_data) failed: {e}", "WARN")
            
            if not code_files_found:
                try:
                    # Method 2: Try get_code_structure (most comprehensive approach)
                    if hasattr(job, 'get_code_structure'):
                        structure = job.get_code_structure()
                        if structure and 'files' in structure:
                            files_data = structure['files']
                            if files_data:
                                log_to_syftui(f"📁 Found code structure with {len(files_data)} files", "DEBUG")
                                for file_path, file_info in files_data.items():
                                    if isinstance(file_info, dict) and 'content' in file_info:
                                        content = file_info['content']
                                        if content and not content.startswith('<'):  # Skip binary/error files
                                            job_data['code_files'][file_path] = content
                                            code_files_found = True
                                            log_to_syftui(f"✅ Loaded file {file_path} from structure ({len(content)} chars)", "DEBUG")
                except Exception as e:
                    log_to_syftui(f"❌ Method 2a (get_code_structure) failed: {e}", "DEBUG")
            
            if not code_files_found:
                try:
                    # Method 2b: Try list_files and read_file (fallback)
                    if hasattr(job, 'list_files') and hasattr(job, 'read_file'):
                        files = job.list_files()
                        if files:
                            log_to_syftui(f"📁 Found {len(files)} files via list_files(): {files}", "DEBUG")
                            for filename in files:
                                try:
                                    content = job.read_file(filename)
                                    if content:
                                        job_data['code_files'][filename] = content
                                        code_files_found = True
                                        log_to_syftui(f"✅ Successfully read file {filename} ({len(content)} chars)", "DEBUG")
                                    else:
                                        log_to_syftui(f"⚠️ Empty content for file {filename}", "DEBUG")
                                except Exception as e:
                                    log_to_syftui(f"❌ Error reading file {filename}: {e}", "DEBUG")
                except Exception as e:
                    log_to_syftui(f"❌ Method 2b (list_files/read_file) failed: {e}", "DEBUG")
            
            if not code_files_found:
                try:
                    # Method 3: Try code_folder direct access
                    if hasattr(job, 'code_folder') and job.code_folder:
                        from pathlib import Path
                        code_folder = Path(job.code_folder)
                        if code_folder.exists():
                            for code_file in code_folder.rglob('*'):
                                if code_file.is_file():
                                    try:
                                        relative_path = str(code_file.relative_to(code_folder))
                                        content = code_file.read_text(encoding='utf-8', errors='ignore')
                                        job_data['code_files'][relative_path] = content
                                        code_files_found = True
                                    except Exception:
                                        pass
                except Exception:
                    pass
            
            if not code_files_found:
                try:
                    # Method 4: Try accessing job directory via syft-code-queue client
                    if hasattr(q, 'client') and hasattr(q.client, '_get_job_dir'):
                        job_dir = q.client._get_job_dir(job)
                        code_dir = job_dir / "code"
                        if code_dir.exists():
                            for code_file in code_dir.rglob('*'):
                                if code_file.is_file():
                                    try:
                                        relative_path = str(code_file.relative_to(code_dir))
                                        content = code_file.read_text(encoding='utf-8', errors='ignore')
                                        job_data['code_files'][relative_path] = content
                                        code_files_found = True
                                    except Exception:
                                        pass
                except Exception:
                    pass
            
            if not code_files_found:
                # Final fallback: Check if code_files is already a list of filenames
                if hasattr(job, 'code_files'):
                    code_files_attr = getattr(job, 'code_files')
                    if isinstance(code_files_attr, list):
                        # Store as list for now (filenames only - will be converted to demo content during storage)
                        job_data['code_files'] = code_files_attr
                        log_to_syftui(f"⚠️ Using fallback: storing filenames only {code_files_attr} - will create dummy content", "WARN")
            
            # Summary log
            if code_files_found and isinstance(job_data.get('code_files'), dict):
                file_count = len(job_data['code_files'])
                total_content_size = sum(len(str(content)) for content in job_data['code_files'].values())
                log_to_syftui(f"✅ Successfully extracted {file_count} files with real content ({total_content_size} total chars)")
            elif isinstance(job_data.get('code_files'), list):
                log_to_syftui(f"⚠️ Only extracted filenames, dummy content will be generated: {job_data['code_files']}")
            
            return job_data
            
        except Exception as e:
            log_to_syftui(f"❌ Error extracting job data: {e}", "ERROR")
            return {
                "name": str(job),
                "description": "",
                "tags": [],
                "requester_email": getattr(job, 'requester_email', ''),
                "created_at": None,
                "uid": str(getattr(job, 'uid', '')),
                "code_files": {}
            }
    
    def _store_completed_job_in_history(self, job):
        """Store a completed job in history for potential trusted code marking."""
        try:
            if store_job_in_history is not None:
                job_id = str(getattr(job, 'uid', ''))
                
                # Skip if we've already processed this job
                if job_id in self.processed_job_ids:
                    return
                
                job_data = self._extract_job_data(job)
                signature = store_job_in_history(self.syftbox_client, job_data)
                self.processed_job_ids.add(job_id)
                
                log_to_syftui(f"📚 Stored job in history: {job_data['name']} -> {signature[:12]}...")
        except Exception as e:
            log_to_syftui(f"⚠️ Could not store job in history: {e}", "WARN")
    
    def _check_and_store_completed_jobs(self):
        """Check for completed jobs and store them in history."""
        try:
            # Get all completed jobs that I've approved
            completed_jobs = q.approved_by_me.completed()
            
            if not completed_jobs:
                return
            
            new_completed_count = 0
            for job in completed_jobs:
                job_id = str(getattr(job, 'uid', ''))
                
                # Skip if we've already processed this job
                if job_id not in self.processed_job_ids:
                    self._store_completed_job_in_history(job)
                    new_completed_count += 1
            
            if new_completed_count > 0:
                log_to_syftui(f"📚 Found and stored {new_completed_count} new completed job(s) in history")
                
        except Exception as e:
            log_to_syftui(f"⚠️ Error checking completed jobs: {e}", "WARN")
    
    def _cleanup_ignored_jobs_cache(self):
        """Clean up ignored jobs cache by removing jobs that are no longer pending."""
        try:
            # Get current pending job UIDs
            pending_jobs = q.pending_for_me or []
            current_pending_uids = set()
            
            for job in pending_jobs:
                job_uid = str(getattr(job, 'uid', f"{job.name}_{job.requester_email}"))
                current_pending_uids.add(job_uid)
            
            # Remove ignored jobs that are no longer pending
            old_ignored_count = len(self.ignored_job_ids)
            self.ignored_job_ids = self.ignored_job_ids.intersection(current_pending_uids)
            
            cleaned_count = old_ignored_count - len(self.ignored_job_ids)
            if cleaned_count > 0:
                log_to_syftui(f"🧹 Cleaned up {cleaned_count} expired ignored jobs from cache")
        
        except Exception as e:
            log_to_syftui(f"❌ Error cleaning up ignored jobs cache: {e}", "ERROR")
    
    def run(self):
        """
        Start continuous job polling and auto-approval.
        """
        log_to_syftui(f"🔄 Starting continuous job polling...")
        log_to_syftui(f"⏰ Checking every {self.poll_interval} second(s) for jobs from trusted senders and trusted code")
        log_to_syftui(f"📚 Will also monitor for completed jobs to store in history")
        
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
        
        # Check for completed jobs every 10 seconds (10 cycles at 1s intervals)
        if cycle % 10 == 0:
            self._check_and_store_completed_jobs()
        
        # Clean up ignored jobs cache every 5 minutes (300 cycles at 1s intervals)
        if cycle % 300 == 0:
            self._cleanup_ignored_jobs_cache()
        
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
                    
                    # Create a unique job identifier for ignore tracking
                    job_uid = str(getattr(job, 'uid', f"{job.name}_{job.requester_email}"))
                    
                    if verbose_logging:
                        log_to_syftui(f"⚠️  Job '{job.name}' from {job.requester_email} - NOT IN ALLOWLIST OR TRUSTED CODE")
                    
                    # Only log the ignore decision ONCE per job (avoid spam)
                    if job_uid not in self.ignored_job_ids and log_job_decision is not None:
                        try:
                            job_data = self._extract_job_data(job)
                            log_job_decision(
                                self.syftbox_client,
                                job_data,
                                "ignore",
                                f"Not in allowlist and no trusted code pattern match - sender: {job.requester_email}",
                                {"auto_processed": True, "ignored_reason": "not_trusted"}
                            )
                            # Mark this job as ignored to prevent repeated logging
                            self.ignored_job_ids.add(job_uid)
                            log_to_syftui(f"📝 Logged ignore decision for job '{job.name}' (UID: {job_uid})")
                        except Exception as e:
                            log_to_syftui(f"⚠️ Failed to log ignore decision for '{job.name}': {e}", "WARN")
            
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
            
            # Log the decision
            if log_job_decision is not None:
                try:
                    job_data = self._extract_job_data(job)
                    action = "approve" if success else "failed_approval"
                    log_job_decision(
                        self.syftbox_client,
                        job_data,
                        action,
                        approval_reason,
                        {"success": success, "auto_approved": True}
                    )
                except Exception as e:
                    log_to_syftui(f"⚠️ Failed to log decision for '{job.name}': {e}", "WARN")
            
            if success:
                log_to_syftui(f"✅ Approved: '{job.name}' from {job.requester_email} ({reason})")
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
    log_to_syftui("📚 Completed jobs automatically stored in history")
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
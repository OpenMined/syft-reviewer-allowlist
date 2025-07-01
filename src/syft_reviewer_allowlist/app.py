#!/usr/bin/env python3
"""
Syft Reviewer Allowlist App - SyftBox Integration

This module runs as a SyftBox app, continuously polling for pending jobs
and auto-approving those from trusted senders in the allowlist.
"""

import time
import signal
import sys
from datetime import datetime
from time import sleep
from typing import List, Optional

from loguru import logger

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


class ReviewerAllowlistApp:
    """App that automatically approves jobs from trusted senders."""
    
    def __init__(self, allowlist: List[str], poll_interval: int = 1):
        """
        Initialize the app.
        
        Args:
            allowlist: List of trusted email addresses
            poll_interval: Seconds between polling cycles
        """
        try:
            self.syftbox_client = SyftBoxClient.load()
            self.allowlist = allowlist
            self.poll_interval = poll_interval
            
            logger.info(f"✅ Initialized Reviewer Allowlist App for {self.email}")
            logger.info(f"📝 Trusted senders: {', '.join(allowlist)}")
            logger.info(f"⏰ Polling every {poll_interval} second(s)")
            
        except Exception as e:
            logger.error(f"❌ Could not initialize Reviewer Allowlist App: {e}")
            # Set up in demo mode
            self.syftbox_client = SyftBoxClient()
            self.allowlist = allowlist
            self.poll_interval = poll_interval
    
    @property
    def email(self) -> str:
        """Get the current user's email."""
        return self.syftbox_client.email
    
    def run(self):
        """
        Start continuous job polling and auto-approval.
        """
        logger.info(f"🔄 Starting continuous job polling...")
        logger.info(f"⏰ Checking every {self.poll_interval} second(s) for jobs from trusted senders")
        
        # Set up graceful shutdown
        def signal_handler(signum, frame):
            logger.info("👋 Shutting down gracefully...")
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
                logger.info("👋 Shutting down...")
                break
            except Exception as e:
                logger.error(f"❌ Error in processing cycle {cycle}: {e}")
                # Continue running despite errors
                sleep(self.poll_interval)
    
    def _process_cycle(self, cycle: int):
        """Process one polling cycle."""
        
        # Log cycle number periodically (every 60 cycles = 1 minute at 1s intervals)
        if cycle % 60 == 0:
            logger.info(f"⏰ Polling cycle {cycle} - checking for pending jobs...")
        
        # Check for pending jobs and auto-approve from allowlist
        self._auto_approve_from_allowlist()
    
    def _auto_approve_from_allowlist(self):
        """Auto-approve jobs from senders in the allowlist."""
        try:
            # Get all jobs pending for me
            pending_jobs = q.pending_for_me
            
            if not pending_jobs:
                # Don't log when no jobs - too verbose for continuous polling
                return
            
            logger.info(f"📋 Found {len(pending_jobs)} job(s) pending approval")
            
            # Filter jobs from allowlisted senders
            trusted_jobs = []
            for job in pending_jobs:
                if job.requester_email in self.allowlist:
                    trusted_jobs.append(job)
                    logger.info(f"✅ Job '{job.name}' from {job.requester_email} - TRUSTED")
                else:
                    logger.info(f"⚠️  Job '{job.name}' from {job.requester_email} - NOT IN ALLOWLIST")
            
            if not trusted_jobs:
                if len(pending_jobs) > 0:
                    logger.info("🚫 No jobs from trusted senders found")
                return
            
            logger.info(f"🚀 Auto-approving {len(trusted_jobs)} job(s) from trusted senders...")
            
            # Auto-approve trusted jobs
            approved_count = 0
            failed_count = 0
            
            for job in trusted_jobs:
                try:
                    reason = f"Auto-approved from trusted sender ({job.requester_email}) at {datetime.now().isoformat()}"
                    success = job.approve(reason)
                    
                    if success:
                        approved_count += 1
                        logger.info(f"✅ Approved: '{job.name}' from {job.requester_email}")
                    else:
                        failed_count += 1
                        logger.error(f"❌ Failed to approve: '{job.name}' from {job.requester_email}")
                        
                except Exception as e:
                    failed_count += 1
                    logger.error(f"❌ Error approving '{job.name}': {e}")
            
            # Log summary
            if approved_count > 0 or failed_count > 0:
                logger.info(f"📊 Summary: {approved_count} approved, {failed_count} failed")
            
        except Exception as e:
            logger.error(f"❌ Error during auto-approval check: {e}")


def main():
    """Main entry point for the SyftBox app."""
    
    # Configure the allowlist - you can modify this list
    TRUSTED_SENDERS = [
        "andrew@openmined.org",
        # Add more trusted email addresses here if needed
    ]
    
    logger.info("🤖 Syft Reviewer Allowlist - Auto-approval Service")
    logger.info("=" * 60)
    
    try:
        app = ReviewerAllowlistApp(
            allowlist=TRUSTED_SENDERS,
            poll_interval=1  # Check every second
        )
        app.run()
        
    except Exception as e:
        logger.error(f"❌ App failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
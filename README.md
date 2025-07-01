# Syft Reviewer Allowlist

Auto-approve SyftBox code jobs from trusted senders and trusted code patterns with privacy-focused individual file permissions.

## Overview

This SyftBox app continuously monitors for pending code execution jobs and automatically approves those submitted by:

1. **Trusted senders** - Emails in the allowlist (individual file storage with permissions)
2. **Trusted code patterns** - Jobs that exactly match previously approved code patterns

Each trusted email is stored as an individual file with restricted permissions, and completed jobs are tracked for trusted code pattern marking.

## Features

- ✅ **Continuous monitoring**: Checks for pending jobs every second
- 🛡️ **Dual approval system**: Email allowlist + trusted code patterns
- 🔒 **Individual file permissions**: Each email stored separately with read-only access for the email owner
- 🔐 **Trusted code patterns**: Auto-approve identical jobs regardless of sender
- 📝 **Detailed logging**: Comprehensive logs of all approval decisions (reduced noise every 60 seconds)
- 🔄 **Auto-recovery**: Continues running even if individual operations fail
- 👋 **Graceful shutdown**: Handles interruption signals properly
- 🔐 **Privacy-focused**: Users can only see their own presence in the allowlist

## Configuration

The app includes a comprehensive web-based interface for managing both email allowlist and trusted code patterns!

**Default Configuration:**
- Starts with `andrew@openmined.org` in the email allowlist
- Web UI available at the app's assigned port with tabbed interface
- Changes take effect within 30 seconds

**Web Interface Features:**
- **Email Allowlist Tab**: Manage trusted sender emails
- **Trusted Code Tab**: View job history and mark/unmark trusted code patterns
- Real-time application status with both components
- Tabbed interface for easy navigation

## Storage & Privacy

### Email Allowlist Storage
The app uses a privacy-focused approach to store the email allowlist:

- **Individual Files**: Each trusted email is stored as a separate file in `app_data/syft_reviewer_allowlist/allowlist/`
- **Restricted Permissions**: Files are created with read-only access for the file owner
- **Privacy**: Users can only see their own presence in the allowlist, not other members
- **Filename Encoding**: Email addresses are safely encoded (@ becomes _at_, . becomes _dot_)

### Trusted Code Storage
The app tracks and manages trusted code patterns:

- **Job History**: Completed jobs stored in `app_data/syft_reviewer_allowlist/job_history/`
- **Trusted Patterns**: Marked trusted code stored in `app_data/syft_reviewer_allowlist/trusted_code/`
- **Job Signatures**: SHA-256 hash of job name, description, tags, and all code files
- **Exact Matching**: Jobs must be completely identical to match trusted patterns

## API Endpoints

### Admin Endpoints (Full Access)
- `GET /api/v1/allowlist` - Get complete email allowlist
- `POST /api/v1/allowlist` - Update complete email allowlist
- `POST /api/v1/allowlist/add/{email}` - Add single email
- `DELETE /api/v1/allowlist/remove/{email}` - Remove single email

### Personal Access Endpoints
- `GET /api/v1/allowlist/me` - Check if current user is in allowlist
- `GET /api/v1/allowlist/check/{email}` - Check if specific email is in allowlist

### Trusted Code Endpoints
- `GET /api/v1/trusted-code/history` - Get job history for trusted code marking
- `GET /api/v1/trusted-code` - Get list of trusted code patterns
- `POST /api/v1/trusted-code/mark/{signature}` - Mark job as trusted code
- `DELETE /api/v1/trusted-code/unmark/{signature}` - Remove job from trusted code
- `POST /api/v1/trusted-code/check-signature` - Calculate and check job signature
- `POST /api/v1/trusted-code/add-to-history` - Manually add job to history

## Auto-Approval Logic

The app follows this approval priority:

1. **Check Email Allowlist**: If job sender is in email allowlist → immediate approval
2. **Check Trusted Code**: If job matches trusted code pattern exactly → approval
3. **Manual Review**: Otherwise, job remains pending for manual review

## Job Signature Calculation

Trusted code patterns are based on SHA-256 signatures calculated from:
- Job name (exact match)
- Job description (exact match) 
- Job tags (sorted for consistency)
- All code files content (filename and content must match exactly)

## Usage

This app is designed to run as a SyftBox app. It will be automatically started by SyftBox when placed in the appropriate directory.

The app will:
1. Monitor for pending jobs every second
2. Check if job senders are in the email allowlist
3. Check if jobs match trusted code patterns
4. Auto-approve jobs from trusted senders or matching trusted patterns
5. Log detailed status every 60 seconds (reduced noise)
6. Maintain individual files for each trusted email
7. Track job history for trusted code pattern management

## Workflow Examples

### Email Allowlist Workflow
1. Add `researcher@university.edu` to email allowlist via web UI
2. Any job from this email is immediately auto-approved
3. Researcher can only see their own presence in the allowlist

### Trusted Code Workflow
1. Complete a job successfully (e.g., "Data Analysis Script")
2. Job appears in history in the web UI
3. Mark the job as "trusted code"
4. Future identical submissions from any sender are auto-approved
5. Even jobs from unknown senders will be approved if code matches exactly

## Dependencies

- `syft-code-queue`: For accessing the job queue
- `syft-core`: For SyftBox integration
- `loguru`: For logging
- `fastapi`: For web API
- `uvicorn`: For API server
- `pydantic`: For data validation

## License

Apache 2.0 
# Syft Reviewer Allowlist

Auto-approve SyftBox code jobs from trusted senders.

## Overview

This SyftBox app continuously monitors for pending code execution jobs and automatically approves those submitted by trusted senders in the allowlist.

## Features

- ✅ **Continuous monitoring**: Checks for pending jobs every second
- 🛡️ **Allowlist-based approval**: Only approves jobs from pre-configured trusted senders
- 📝 **Detailed logging**: Comprehensive logs of all approval decisions
- 🔄 **Auto-recovery**: Continues running even if individual operations fail
- 👋 **Graceful shutdown**: Handles interruption signals properly

## Configuration

The app now includes a web-based interface for managing the allowlist! 

**Default Configuration:**
- Starts with `andrew@openmined.org` in the allowlist
- Web UI available at the app's assigned port
- Changes take effect within 30 seconds

**Web Interface:**
Access the allowlist management UI through your SyftBox app's assigned port to:
- View current trusted senders
- Add new email addresses
- Remove existing entries
- See real-time application status

## Usage

This app is designed to run as a SyftBox app. It will be automatically started by SyftBox when placed in the appropriate directory.

The app will:
1. Monitor for pending jobs every second
2. Check if job senders are in the allowlist
3. Auto-approve jobs from trusted senders
4. Log all approval decisions

## Dependencies

- `syft-code-queue`: For accessing the job queue
- `syft-core`: For SyftBox integration
- `loguru`: For logging

## License

Apache 2.0 
# Standard library imports
import json
from pathlib import Path

# Third-party imports
from fastapi import HTTPException
from loguru import logger
from syft_core import Client


def get_allowlist_file_path(client: Client) -> Path:
    """Get the path to the allowlist file."""
    return client.app_data("syft-reviewer-allowlist") / "allowlist.json"


def get_allowlist(client: Client) -> list[str]:
    """
    Get the allowlist from the file.
    If it doesn't exist, create it with default values.
    """
    allowlist_file_path = get_allowlist_file_path(client)
    allowlist_file_path.parent.mkdir(
        parents=True, exist_ok=True
    )  # Ensure the directory exists
    
    if not allowlist_file_path.exists():
        # Create default allowlist with andrew@openmined.org
        default_allowlist = ["andrew@openmined.org"]
        allowlist_file_path.write_text(json.dumps(default_allowlist, indent=4))
        return default_allowlist

    # read the file and return it as a list
    try:
        with open(allowlist_file_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error(
            "Failed to decode JSON from allowlist file, returning default list"
        )
        return ["andrew@openmined.org"]
    except Exception as e:
        logger.error(f"Error reading allowlist file: {e}")
        raise HTTPException(status_code=500, detail="Failed to read allowlist file")


def save_allowlist(client: Client, emails: list[str]) -> None:
    """
    Save the allowlist to the file.
    """
    allowlist_file_path = get_allowlist_file_path(client)
    try:
        with open(allowlist_file_path, "w") as f:
            json.dump(emails, f, indent=4)
        logger.debug(f"Allowlist saved to {allowlist_file_path}")
    except Exception as e:
        logger.error(f"Error saving allowlist file: {e}")
        raise HTTPException(status_code=500, detail="Failed to save allowlist file") 
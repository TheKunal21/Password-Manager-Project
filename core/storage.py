"""Data persistence — JSON load/save with optional file locking and atomic writes."""

import json
import os
import logging

from core.config import DATA_FILE, DATA_LOCK, MASTER_FILE

logger = logging.getLogger(__name__)

# File-lock import is optional (only needed for Streamlit concurrent access)
try:
    from filelock import FileLock
except ImportError:
    FileLock = None


def load_data(filepath: str | None = None, use_lock: bool = False) -> dict:
    """Load user data from a JSON file.

    Returns {"users": {}} on missing/corrupt files.
    When use_lock=True, acquires a file lock for concurrent safety.
    """
    if filepath is None:
        filepath = DATA_FILE

    def _read():
        if not os.path.exists(filepath):
            return {"users": {}}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return {"users": {}}
                parsed = json.loads(content)
                if not isinstance(parsed, dict) or "users" not in parsed:
                    logger.warning("%s has invalid structure; resetting.", filepath)
                    return {"users": {}}
                if not isinstance(parsed["users"], dict):
                    logger.warning("%s 'users' is not a dict; resetting.", filepath)
                    return {"users": {}}
                return parsed
        except json.JSONDecodeError:
            logger.error("%s is corrupted; resetting.", filepath)
            return {"users": {}}
        except OSError as e:
            logger.error("Error reading %s: %s", filepath, e)
            return {"users": {}}

    if use_lock and FileLock is not None:
        lock = FileLock(DATA_LOCK, timeout=5)
        with lock:
            return _read()
    return _read()


def save_data(data: dict, filepath: str | None = None, use_lock: bool = False) -> bool:
    """Save user data to a JSON file atomically (write-to-tmp then rename).

    Returns True on success, False on failure.
    """
    if filepath is None:
        filepath = DATA_FILE
    tmp_file = filepath + ".tmp"

    def _write():
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_file, filepath)
            return True
        except OSError as e:
            logger.error("Error saving %s: %s", filepath, e)
            return False

    if use_lock and FileLock is not None:
        lock = FileLock(DATA_LOCK, timeout=5)
        with lock:
            return _write()
    return _write()


def load_master_hash(filepath: str | None = None) -> str | None:
    """Load the stored master password hash, or None if not set."""
    if filepath is None:
        filepath = MASTER_FILE
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            h = f.read().strip()
            return h if h else None
    except FileNotFoundError:
        return None


def store_master_hash(hash_str: str, filepath: str | None = None) -> None:
    """Persist the master password bcrypt hash to disk."""
    if filepath is None:
        filepath = MASTER_FILE
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(hash_str)

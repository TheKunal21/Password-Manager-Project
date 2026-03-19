"""Data persistence — JSON load/save with optional file locking and atomic writes."""

import json
import os
import logging
from datetime import datetime, timezone

from core.config import DATA_FILE, DATA_LOCK, MASTER_FILE

logger = logging.getLogger(__name__)

# File-lock import is optional (only needed for Streamlit concurrent access)
try:
    from filelock import FileLock
except ImportError:
    FileLock = None


def _lock_path(filepath: str) -> str:
    """Return the lock path for a given data file path."""
    return DATA_LOCK if filepath == DATA_FILE else f"{filepath}.lock"


def _backup_corrupt_file(filepath: str, reason: str) -> None:
    """Move a corrupt or invalid data file aside for recovery."""
    if not os.path.exists(filepath):
        return
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = f"{filepath}.corrupt.{timestamp}"
    try:
        os.replace(filepath, backup_path)
        logger.error("Backed up invalid data file '%s' to '%s' (%s).", filepath, backup_path, reason)
    except OSError as e:
        logger.error("Failed to backup invalid data file '%s': %s", filepath, e)


def _read_data_unlocked(filepath: str) -> dict:
    """Read and validate data file without acquiring a lock."""
    if not os.path.exists(filepath):
        return {"users": {}}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {"users": {}}
            parsed = json.loads(content)
            if not isinstance(parsed, dict) or "users" not in parsed:
                _backup_corrupt_file(filepath, "invalid root structure")
                return {"users": {}}
            if not isinstance(parsed["users"], dict):
                _backup_corrupt_file(filepath, "'users' is not an object")
                return {"users": {}}
            return parsed
    except json.JSONDecodeError:
        _backup_corrupt_file(filepath, "json decode error")
        return {"users": {}}
    except OSError as e:
        logger.error("Error reading %s: %s", filepath, e)
        return {"users": {}}


def _write_data_unlocked(data: dict, filepath: str) -> bool:
    """Write data atomically without acquiring a lock."""
    tmp_file = filepath + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_file, filepath)
        return True
    except OSError as e:
        logger.error("Error saving %s: %s", filepath, e)
        return False


def load_data(filepath: str | None = None, use_lock: bool = False) -> dict:
    """Load user data from a JSON file.

    Returns {"users": {}} on missing/corrupt files.
    When use_lock=True, acquires a file lock for concurrent safety.
    """
    if filepath is None:
        filepath = DATA_FILE

    if use_lock and FileLock is not None:
        lock = FileLock(_lock_path(filepath), timeout=5)
        with lock:
            return _read_data_unlocked(filepath)
    return _read_data_unlocked(filepath)


def save_data(data: dict, filepath: str | None = None, use_lock: bool = False) -> bool:
    """Save user data to a JSON file atomically (write-to-tmp then rename).

    Returns True on success, False on failure.
    """
    if filepath is None:
        filepath = DATA_FILE

    if use_lock and FileLock is not None:
        lock = FileLock(_lock_path(filepath), timeout=5)
        with lock:
            return _write_data_unlocked(data, filepath)
    return _write_data_unlocked(data, filepath)


def atomic_update(update_fn, filepath: str | None = None) -> tuple[bool, object]:
    """Run read-modify-write as one critical section under a single lock.

    `update_fn` receives the loaded data dict and may mutate it in place.
    Returns (save_success, update_result).
    """
    if filepath is None:
        filepath = DATA_FILE

    def _run() -> tuple[bool, object]:
        data = _read_data_unlocked(filepath)
        try:
            result = update_fn(data)
        except Exception as e:
            logger.exception("Atomic update callback failed for %s", filepath)
            return False, e
        ok = _write_data_unlocked(data, filepath)
        return ok, result

    if FileLock is not None:
        lock = FileLock(_lock_path(filepath), timeout=5)
        with lock:
            return _run()
    return _run()


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

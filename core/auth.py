"""Authentication — user registration, login verification, master password."""

import os
import base64
from datetime import datetime, timezone

import bcrypt

from core.config import BCRYPT_ROUNDS
from core.encryption import derive_key
from core.password_utils import check_password_strength, validate_username


def resolve_username(users: dict, username: str) -> str | None:
    """Resolve a username from users dict using case-insensitive matching."""
    if not username:
        return None
    if username in users:
        return username
    lower = username.lower()
    for existing in users:
        if existing.lower() == lower:
            return existing
    return None


def hash_password(password: str) -> str:
    """Hash a password with bcrypt and return the hash as a string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    if not stored_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def register_user(data: dict, username: str, password: str) -> tuple[bool, str]:
    """Register a new user into the data dict.

    Returns (success, message). Modifies data in-place on success.
    """
    valid, msg = validate_username(username)
    if not valid:
        return False, msg

    if not password:
        return False, "Password cannot be empty."

    # Case-insensitive uniqueness check
    if username.lower() in {u.lower() for u in data.get("users", {})}:
        return False, "Username already exists."

    strong, issues = check_password_strength(password)
    if not strong:
        return False, "Password too weak: " + "; ".join(issues)

    salt = os.urandom(16)
    data.setdefault("users", {})[username] = {
        "password_hash": hash_password(password),
        "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
        "credentials": {},
        "failed_attempts": 0,
        "lockout_until": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return True, "User registered successfully."


def authenticate_user(data: dict, username: str, password: str) -> tuple[bool, str, bytes | None]:
    """Authenticate a user and derive their Fernet key.

    Returns (success, message, fernet_key_or_None).
    """
    if not username or not password:
        return False, "Username and password are required.", None

    users = data.get("users", {})
    resolved_username = resolve_username(users, username)
    if resolved_username is None:
        return False, "Invalid username or password.", None

    user_rec = users[resolved_username]
    stored_hash = user_rec.get("password_hash", "")
    if not verify_password(password, stored_hash):
        return False, "Invalid username or password.", None

    salt = base64.urlsafe_b64decode(user_rec["salt"].encode("utf-8"))
    fernet_key = derive_key(password, salt)
    return True, f"Welcome, {resolved_username}!", fernet_key

"""Vault operations — credential CRUD and account management."""

import os
import base64
from datetime import datetime, timezone

from core.encryption import derive_key, encrypt_value, decrypt_value
from core.auth import hash_password, verify_password
from core.password_utils import check_password_strength


def add_credential(data: dict, username: str, site: str, login: str,
                   password: str, fernet_key: bytes) -> tuple[bool, str]:
    """Encrypt and store a new credential. Returns (success, message)."""
    if not site:
        return False, "Site name is required."
    if not login:
        return False, "Site username is required."
    if not password:
        return False, "Site password is required."

    user = data.get("users", {}).get(username)
    if user is None:
        return False, "Account not found."

    creds = user.setdefault("credentials", {})
    if site in creds:
        return False, f"Credential for '{site}' already exists. Delete it first or use update."

    creds[site] = {
        "login": login,
        "password": encrypt_value(fernet_key, password),
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    return True, f"Credential for '{site}' saved."


def get_credential(data: dict, username: str, site: str,
                   fernet_key: bytes) -> tuple[str | None, str | None]:
    """Decrypt and return (login, password) for a site; None on failure."""
    user = data.get("users", {}).get(username)
    if user is None:
        return None, None
    cred = user.get("credentials", {}).get(site)
    if cred is None:
        return None, None
    decrypted = decrypt_value(fernet_key, cred["password"])
    return cred.get("login"), decrypted


def get_all_credentials(data: dict, username: str,
                        fernet_key: bytes) -> dict[str, dict]:
    """Return {site: {"login": ..., "password": ...}} for all sites."""
    user = data.get("users", {}).get(username)
    if user is None:
        return {}
    result = {}
    for site, cred in user.get("credentials", {}).items():
        decrypted = decrypt_value(fernet_key, cred["password"])
        result[site] = {
            "login": cred.get("login", ""),
            "password": decrypted,
            "added_at": cred.get("added_at", ""),
        }
    return result


def list_credential_sites(data: dict, username: str) -> list[str]:
    """Return sorted list of site names for a user."""
    user = data.get("users", {}).get(username)
    if user is None:
        return []
    return sorted(user.get("credentials", {}).keys())


def update_credential(data: dict, username: str, site: str,
                      new_password: str, fernet_key: bytes,
                      new_login: str | None = None) -> tuple[bool, str]:
    """Update an existing credential's password (and optionally login)."""
    if not new_password:
        return False, "Password cannot be empty."
    user = data.get("users", {}).get(username)
    if user is None:
        return False, "Account not found."
    creds = user.get("credentials", {})
    if site not in creds:
        return False, f"Site '{site}' not found."

    creds[site]["password"] = encrypt_value(fernet_key, new_password)
    if new_login is not None:
        creds[site]["login"] = new_login
    return True, f"Credential for '{site}' updated."


def delete_credential(data: dict, username: str, site: str) -> tuple[bool, str]:
    """Delete a credential. Returns (success, message)."""
    user = data.get("users", {}).get(username)
    if user is None:
        return False, "Account not found."
    creds = user.get("credentials", {})
    if site not in creds:
        return False, f"Site '{site}' not found."
    del creds[site]
    return True, f"Credential for '{site}' deleted."


def change_master_password(data: dict, username: str,
                           old_password: str, new_password: str) -> tuple[bool, str, bytes | None]:
    """Change a user's master password, re-encrypting all credentials.

    Returns (success, message, new_fernet_key_or_None).
    """
    if not old_password or not new_password:
        return False, "Both old and new passwords are required.", None
    if old_password == new_password:
        return False, "New password must differ from the current one.", None

    strong, issues = check_password_strength(new_password)
    if not strong:
        return False, "New password too weak: " + "; ".join(issues), None

    user = data.get("users", {}).get(username)
    if user is None:
        return False, "Account not found.", None

    if not verify_password(old_password, user.get("password_hash", "")):
        return False, "Incorrect current password.", None

    # Decrypt all credentials with old key
    old_salt = base64.urlsafe_b64decode(user["salt"].encode("utf-8"))
    old_key = derive_key(old_password, old_salt)

    decrypted_creds = {}
    for site, cred in user.get("credentials", {}).items():
        dec_pw = decrypt_value(old_key, cred["password"])
        if dec_pw is None:
            return False, f"Failed to decrypt '{site}'. Aborting.", None
        decrypted_creds[site] = {
            "login": cred.get("login", ""),
            "password": dec_pw,
            "added_at": cred.get("added_at", ""),
        }

    # Re-encrypt with new key
    new_salt = os.urandom(16)
    new_key = derive_key(new_password, new_salt)
    reencrypted = {}
    for site, info in decrypted_creds.items():
        reencrypted[site] = {
            "login": info["login"],
            "password": encrypt_value(new_key, info["password"]),
            "added_at": info["added_at"],
        }

    user["salt"] = base64.urlsafe_b64encode(new_salt).decode("utf-8")
    user["password_hash"] = hash_password(new_password)
    user["credentials"] = reencrypted
    return True, "Master password changed. Please log in again.", new_key


def delete_account(data: dict, username: str, password: str) -> tuple[bool, str]:
    """Permanently delete a user account after password verification."""
    if not password:
        return False, "Password is required."
    user = data.get("users", {}).get(username)
    if user is None:
        return False, "Account not found."
    if not verify_password(password, user.get("password_hash", "")):
        return False, "Incorrect password."
    del data["users"][username]
    return True, "Account deleted successfully."

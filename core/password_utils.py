"""Password and input validation utilities."""

import re
import string
import secrets

from core.config import MIN_PASSWORD_LENGTH, MAX_INPUT_LENGTH, USERNAME_PATTERN


def check_password_strength(password: str) -> tuple[bool, list[str]]:
    """Validate password strength. Returns (is_valid, list_of_issues)."""
    issues = []
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"At least {MIN_PASSWORD_LENGTH} characters required.")
    if not re.search(r"[A-Z]", password):
        issues.append("At least one uppercase letter required.")
    if not re.search(r"[a-z]", password):
        issues.append("At least one lowercase letter required.")
    if not re.search(r"\d", password):
        issues.append("At least one digit required.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        issues.append("At least one special character required.")
    return (len(issues) == 0, issues)


def generate_password(length: int = 20) -> str:
    """Generate a cryptographically secure random password that meets strength rules."""
    length = max(12, min(length, 128))
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        valid, _ = check_password_strength(pwd)
        if valid:
            return pwd


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format. Returns (is_valid, error_message)."""
    if not username:
        return False, "Username cannot be empty."
    if len(username) > 64:
        return False, "Username must be 64 characters or fewer."
    if not USERNAME_PATTERN.match(username):
        return False, "Username may only contain letters, digits, underscores, dots, and hyphens (3–64 chars)."
    return True, ""


def sanitize_input(text: str) -> str:
    """Strip whitespace and enforce maximum input length."""
    return text.strip()[:MAX_INPUT_LENGTH]

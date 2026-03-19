"""Application-wide configuration constants."""

import re

# File paths
DATA_FILE = "data.json"
DATA_LOCK = "data.json.lock"
MASTER_FILE = "master.hash"
LOG_FILE = "vault.log"

# Security
PBKDF2_ITERATIONS = 1_200_000
BCRYPT_ROUNDS = 12
MIN_PASSWORD_LENGTH = 8
MAX_INPUT_LENGTH = 256

# Session / brute-force
SESSION_TIMEOUT_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Validation
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")

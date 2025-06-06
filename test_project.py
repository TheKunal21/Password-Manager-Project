import os
import json
import hashlib
import pytest
from cryptography.fernet import Fernet

ACCOUNTS_FILE = "accounts.json"
KEY_FILE = "key.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()

def save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f)

def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return {}
    with open(ACCOUNTS_FILE, "r") as f:
        return json.load(f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@pytest.fixture(scope="module")
def fernet():
    key = load_key()
    return Fernet(key)

@pytest.fixture(scope="module")
def username():
    return "test_user"

@pytest.fixture(scope="module")
def master_password():
    return "Test@123"

@pytest.fixture(scope="module")
def accounts(username, master_password):
    hashed = hash_password(master_password)
    accounts = load_accounts()
    if username not in accounts:
        accounts[username] = {"master": hashed, "sites": {}}
        save_accounts(accounts)
    return load_accounts()

def test_master_password(accounts, username, master_password):
    hashed = hash_password(master_password)
    assert accounts[username]["master"] == hashed

def test_save_site_password(accounts, username, fernet):
    site = "example.com"
    plain_pwd = "sitepassword123"
    encrypted_pwd = fernet.encrypt(plain_pwd.encode()).decode()
    accounts[username]["sites"][site] = encrypted_pwd
    save_accounts(accounts)
    # Reload and verify encrypted password stored
    updated_accounts = load_accounts()
    assert site in updated_accounts[username]["sites"]

def test_retrieve_site_password(accounts, username, fernet):
    site = "example.com"
    updated_accounts = load_accounts()
    encrypted_pwd = updated_accounts[username]["sites"][site]
    decrypted_pwd = fernet.decrypt(encrypted_pwd.encode()).decode()
    assert decrypted_pwd == "sitepassword123"

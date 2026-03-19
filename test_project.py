"""
test_project.py — Comprehensive tests for the modular Secure Password Vault.

Tests cover:
  - core.password_utils: Password strength, generation, username validation
  - core.encryption: Key derivation, encrypt/decrypt roundtrip
  - core.storage: Data persistence (load/save JSON, master hash)
  - core.auth: User registration, authentication, password hashing
  - core.vault: Credential CRUD (add, get, update, delete, list)
  - project.py: CLI wrappers (create master pw, create account, site CRUD)
"""

import os
import json
import base64

import pytest
import bcrypt
from cryptography.fernet import Fernet

# Core module imports
from core.encryption import derive_key, encrypt_value, decrypt_value
from core.password_utils import (
    check_password_strength, generate_password, validate_username, sanitize_input,
)
from core.storage import load_data, save_data, load_master_hash, store_master_hash, atomic_update
from core.auth import hash_password, verify_password, register_user, authenticate_user
from core.vault import (
    add_credential, get_credential, get_all_credentials,
    list_credential_sites, update_credential, delete_credential,
    change_master_password, delete_account,
)
import core.storage

# CLI wrapper imports
import project
from core.config import MAX_LOGIN_ATTEMPTS


# ------- Fixtures -------


@pytest.fixture(autouse=True)
def isolate_files(tmp_path, monkeypatch):
    """Run each test in a temporary directory so files don't conflict."""
    monkeypatch.chdir(tmp_path)
    # Patch storage module defaults so parameterless calls use tmp_path
    monkeypatch.setattr(core.storage, "DATA_FILE", str(tmp_path / "data.json"))
    monkeypatch.setattr(core.storage, "DATA_LOCK", str(tmp_path / "data.json.lock"))
    monkeypatch.setattr(core.storage, "MASTER_FILE", str(tmp_path / "master.hash"))
    yield


@pytest.fixture()
def sample_data():
    """Return a fresh data dict with one registered user."""
    password = "TestP@ss1!"
    salt = os.urandom(16)
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4))
    fernet_key = derive_key(password, salt)
    data = {
        "users": {
            "tester": {
                "password_hash": hashed.decode("utf-8"),
                "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
                "credentials": {},
                "created_at": "2024-01-01T00:00:00+00:00",
            }
        }
    }
    return data, "tester", fernet_key, password


# ======= core.password_utils tests =======


class TestPasswordStrength:
    def test_strong_password(self):
        valid, issues = check_password_strength("MyStr0ng!Pass")
        assert valid is True
        assert issues == []

    def test_too_short(self):
        valid, issues = check_password_strength("Ab1!")
        assert valid is False
        assert any("characters" in i for i in issues)

    def test_missing_uppercase(self):
        valid, issues = check_password_strength("mysecure1!")
        assert valid is False
        assert any("uppercase" in i.lower() for i in issues)

    def test_missing_lowercase(self):
        valid, issues = check_password_strength("MYSECURE1!")
        assert valid is False
        assert any("lowercase" in i.lower() for i in issues)

    def test_missing_digit(self):
        valid, issues = check_password_strength("MySecure!Pass")
        assert valid is False
        assert any("digit" in i.lower() for i in issues)

    def test_missing_special(self):
        valid, issues = check_password_strength("MySecure1Pass")
        assert valid is False
        assert any("special" in i.lower() for i in issues)

    def test_empty_password(self):
        valid, issues = check_password_strength("")
        assert valid is False
        assert len(issues) >= 1

    def test_all_issues(self):
        valid, issues = check_password_strength("abc")
        assert valid is False
        assert len(issues) >= 3


class TestPasswordGeneration:
    def test_generated_password_is_valid(self):
        pw = generate_password(20)
        valid, _ = check_password_strength(pw)
        assert valid is True
        assert len(pw) == 20

    def test_minimum_length_enforcement(self):
        pw = generate_password(5)
        assert len(pw) == 12

    def test_maximum_length_enforcement(self):
        pw = generate_password(200)
        assert len(pw) == 128

    def test_uniqueness(self):
        passwords = {generate_password(20) for _ in range(10)}
        assert len(passwords) == 10


class TestUsernameValidation:
    def test_valid_username(self):
        ok, msg = validate_username("alice_01")
        assert ok is True

    def test_empty_username(self):
        ok, msg = validate_username("")
        assert ok is False

    def test_too_long(self):
        ok, msg = validate_username("a" * 65)
        assert ok is False

    def test_invalid_chars(self):
        ok, msg = validate_username("bad user!")
        assert ok is False

    def test_sanitize_input(self):
        assert sanitize_input("  hello  ") == "hello"
        assert len(sanitize_input("x" * 500)) == 256


# ======= core.encryption tests =======


class TestKeyDerivation:
    def test_derive_key_consistency(self):
        salt = os.urandom(16)
        key1 = derive_key("password123", salt)
        key2 = derive_key("password123", salt)
        assert key1 == key2

    def test_derive_key_different_passwords(self):
        salt = os.urandom(16)
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_different_salts(self):
        key1 = derive_key("password", os.urandom(16))
        key2 = derive_key("password", os.urandom(16))
        assert key1 != key2

    def test_derived_key_is_valid_fernet_key(self):
        salt = os.urandom(16)
        key = derive_key("Test@1234", salt)
        f = Fernet(key)
        enc = f.encrypt(b"hello")
        assert f.decrypt(enc) == b"hello"


class TestEncryptDecrypt:
    def test_roundtrip(self):
        salt = os.urandom(16)
        key = derive_key("TestM@ster1", salt)
        original = "SuperSecret!123"
        encrypted = encrypt_value(key, original)
        decrypted = decrypt_value(key, encrypted)
        assert decrypted == original

    def test_wrong_key_returns_none(self):
        salt = os.urandom(16)
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        encrypted = encrypt_value(key1, "secret")
        assert decrypt_value(key2, encrypted) is None


# ======= core.storage tests =======


class TestDataPersistence:
    def test_load_empty(self):
        data = load_data()
        assert data == {"users": {}}

    def test_save_and_load(self, tmp_path):
        fp = str(tmp_path / "data.json")
        data = {"users": {"user1": {"password_hash": "abc", "salt": "xyz", "credentials": {}}}}
        save_data(data, filepath=fp)
        loaded = load_data(filepath=fp)
        assert "user1" in loaded["users"]
        assert loaded["users"]["user1"]["password_hash"] == "abc"

    def test_load_corrupted_json(self, tmp_path):
        fp = str(tmp_path / "data.json")
        with open(fp, "w") as f:
            f.write("{invalid json!!!")
        data = load_data(filepath=fp)
        assert data == {"users": {}}

    def test_load_non_dict_json(self, tmp_path):
        fp = str(tmp_path / "data.json")
        with open(fp, "w") as f:
            json.dump([1, 2, 3], f)
        data = load_data(filepath=fp)
        assert data == {"users": {}}

    def test_load_corrupted_json_creates_backup(self, tmp_path):
        fp = tmp_path / "data.json"
        fp.write_text("{broken", encoding="utf-8")
        data = load_data(filepath=str(fp))
        assert data == {"users": {}}
        backups = list(tmp_path.glob("data.json.corrupt.*"))
        assert len(backups) == 1

    def test_atomic_update_callback_exception(self, tmp_path):
        fp = tmp_path / "data.json"
        original = {"users": {"alice": {"password_hash": "x", "salt": "y", "credentials": {}}}}
        save_data(original, filepath=str(fp))

        def bad_update(_data):
            raise RuntimeError("boom")

        ok, result = atomic_update(bad_update, filepath=str(fp))
        assert ok is False
        assert isinstance(result, RuntimeError)
        loaded = load_data(filepath=str(fp))
        assert loaded == original


class TestMasterHash:
    def test_load_missing(self):
        assert load_master_hash() is None

    def test_store_and_load(self, tmp_path):
        fp = str(tmp_path / "master.hash")
        store_master_hash("$2b$12$somehashvalue", filepath=fp)
        loaded = load_master_hash(filepath=fp)
        assert loaded == "$2b$12$somehashvalue"


# ======= core.auth tests =======


class TestAuth:
    def test_hash_and_verify(self):
        h = hash_password("MyStr0ng!Pass1")
        assert verify_password("MyStr0ng!Pass1", h) is True
        assert verify_password("wrong", h) is False

    def test_verify_empty_hash(self):
        assert verify_password("anything", "") is False

    def test_register_user_success(self):
        data = {"users": {}}
        ok, msg = register_user(data, "alice", "MyStr0ng!Pass1")
        assert ok is True
        assert "alice" in data["users"]
        assert "password_hash" in data["users"]["alice"]
        assert "salt" in data["users"]["alice"]
        assert "credentials" in data["users"]["alice"]

    def test_register_duplicate(self):
        data = {"users": {"alice": {}}}
        ok, msg = register_user(data, "Alice", "MyStr0ng!Pass1")
        assert ok is False
        assert "already exists" in msg.lower()

    def test_register_weak_password(self):
        data = {"users": {}}
        ok, msg = register_user(data, "bob", "weak")
        assert ok is False
        assert "bob" not in data["users"]

    def test_register_invalid_username(self):
        data = {"users": {}}
        ok, msg = register_user(data, "bad user!", "MyStr0ng!Pass1")
        assert ok is False

    def test_authenticate_success(self):
        data = {"users": {}}
        register_user(data, "alice", "MyStr0ng!Pass1")
        ok, msg, key = authenticate_user(data, "alice", "MyStr0ng!Pass1")
        assert ok is True
        assert key is not None

    def test_authenticate_wrong_password(self):
        data = {"users": {}}
        register_user(data, "alice", "MyStr0ng!Pass1")
        ok, msg, key = authenticate_user(data, "alice", "WrongPass1!")
        assert ok is False
        assert key is None

    def test_authenticate_nonexistent_user(self):
        data = {"users": {}}
        ok, msg, key = authenticate_user(data, "nobody", "MyStr0ng!Pass1")
        assert ok is False

    def test_authenticate_case_insensitive_username(self):
        data = {"users": {}}
        register_user(data, "Alice", "MyStr0ng!Pass1")
        ok, msg, key = authenticate_user(data, "alice", "MyStr0ng!Pass1")
        assert ok is True
        assert "Alice" in msg
        assert key is not None


# ======= core.vault tests =======


class TestVault:
    def test_add_credential(self, sample_data):
        data, username, key, _ = sample_data
        ok, msg = add_credential(data, username, "github.com", "user@mail.com", "siteP@ss1", key)
        assert ok is True
        assert "github.com" in data["users"][username]["credentials"]

    def test_add_duplicate_site(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "github.com", "a@b.com", "pw1", key)
        ok, msg = add_credential(data, username, "github.com", "a@b.com", "pw2", key)
        assert ok is False
        assert "already exists" in msg.lower()

    def test_get_credential(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "example.com", "alice", "mySecret!1", key)
        login, password = get_credential(data, username, "example.com", key)
        assert login == "alice"
        assert password == "mySecret!1"

    def test_get_nonexistent(self, sample_data):
        data, username, key, _ = sample_data
        login, password = get_credential(data, username, "nope.com", key)
        assert login is None
        assert password is None

    def test_get_all_credentials(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "a.com", "u1", "p1", key)
        add_credential(data, username, "b.com", "u2", "p2", key)
        all_creds = get_all_credentials(data, username, key)
        assert "a.com" in all_creds
        assert "b.com" in all_creds
        assert all_creds["a.com"]["password"] == "p1"

    def test_list_credential_sites(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "z.com", "u", "p", key)
        add_credential(data, username, "a.com", "u", "p", key)
        sites = list_credential_sites(data, username)
        assert sites == ["a.com", "z.com"]  # sorted

    def test_update_credential(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "test.com", "usr", "oldpw", key)
        ok, msg = update_credential(data, username, "test.com", "newpw", key)
        assert ok is True
        _, pw = get_credential(data, username, "test.com", key)
        assert pw == "newpw"

    def test_update_nonexistent(self, sample_data):
        data, username, key, _ = sample_data
        ok, msg = update_credential(data, username, "nope.com", "pw", key)
        assert ok is False
        assert "not found" in msg.lower()

    def test_delete_credential(self, sample_data):
        data, username, key, _ = sample_data
        add_credential(data, username, "del.com", "u", "p", key)
        ok, msg = delete_credential(data, username, "del.com")
        assert ok is True
        assert "del.com" not in data["users"][username]["credentials"]

    def test_delete_nonexistent(self, sample_data):
        data, username, key, _ = sample_data
        ok, msg = delete_credential(data, username, "nope.com")
        assert ok is False

    def test_change_master_password(self, sample_data):
        data, username, key, password = sample_data
        add_credential(data, username, "site.com", "u", "secret", key)
        ok, msg, new_key = change_master_password(data, username, password, "NewStr0ng!Pass2")
        assert ok is True
        assert new_key is not None
        # Verify old credential is re-encrypted and decryptable with new key
        _, pw = get_credential(data, username, "site.com", new_key)
        assert pw == "secret"

    def test_delete_account(self, sample_data):
        data, username, key, password = sample_data
        ok, msg = delete_account(data, username, password)
        assert ok is True
        assert username not in data["users"]

    def test_delete_account_wrong_password(self, sample_data):
        data, username, key, _ = sample_data
        ok, msg = delete_account(data, username, "WrongPass1!")
        assert ok is False


# ======= CLI wrapper tests (project.py) =======


class TestCLIMasterPassword:
    def test_create_and_verify(self, monkeypatch):
        inputs = iter(["MyStr0ng!Pass1", "MyStr0ng!Pass1"])
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(inputs))
        project.create_master_password()
        h = load_master_hash()
        assert h is not None
        assert verify_password("MyStr0ng!Pass1", h) is True


class TestCLICreateAccount:
    def test_create_success(self, monkeypatch):
        data = {"users": {}}
        save_data(data)
        data = load_data()
        monkeypatch.setattr("builtins.input", lambda prompt="": "testuser")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "MyStr0ng!Pass1")
        project.create_account(data)
        reloaded = load_data()
        assert "testuser" in reloaded["users"]

    def test_create_empty_username(self, monkeypatch):
        data = {"users": {}}
        monkeypatch.setattr("builtins.input", lambda prompt="": "")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "MyStr0ng!Pass1")
        project.create_account(data)
        assert len(data["users"]) == 0

    def test_create_weak_password(self, monkeypatch):
        data = {"users": {}}
        monkeypatch.setattr("builtins.input", lambda prompt="": "newuser")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "weak")
        project.create_account(data)
        assert "newuser" not in data["users"]

    def test_create_invalid_username(self, monkeypatch):
        data = {"users": {}}
        monkeypatch.setattr("builtins.input", lambda prompt="": "bad user!")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "MyStr0ng!Pass1")
        project.create_account(data)
        assert "bad user!" not in data["users"]


class TestCLISitePasswords:
    @pytest.fixture()
    def cli_user_setup(self):
        """Set up a test user and return (data, username, fernet_key)."""
        data = {"users": {}}
        register_user(data, "tester", "TestP@ss1!")
        save_data(data)
        _, _, fernet_key = authenticate_user(data, "tester", "TestP@ss1!")
        return data, "tester", fernet_key

    def test_save_password(self, monkeypatch, cli_user_setup):
        data, username, key = cli_user_setup
        inputs = iter(["github.com", "user@email.com"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "siteP@ss123")
        project.save_site_password(data, username, key)
        assert "github.com" in data["users"][username]["credentials"]

    def test_save_empty_site(self, monkeypatch, cli_user_setup):
        data, username, key = cli_user_setup
        monkeypatch.setattr("builtins.input", lambda prompt="": "")
        project.save_site_password(data, username, key)
        assert len(data["users"][username]["credentials"]) == 0

    def test_retrieve_password(self, monkeypatch, cli_user_setup, capsys):
        data, username, key = cli_user_setup
        add_credential(data, username, "example.com", "alice", "mySecretPw", key)
        monkeypatch.setattr("builtins.input", lambda prompt="": "example.com")
        project.retrieve_site_password(data, username, key)
        output = capsys.readouterr().out
        assert "mySecretPw" in output

    def test_retrieve_nonexistent(self, monkeypatch, cli_user_setup, capsys):
        data, username, key = cli_user_setup
        monkeypatch.setattr("builtins.input", lambda prompt="": "nonexistent.com")
        project.retrieve_site_password(data, username, key)
        output = capsys.readouterr().out
        assert "No entry" in output

    def test_update_password(self, monkeypatch, cli_user_setup):
        data, username, key = cli_user_setup
        add_credential(data, username, "test.com", "usr", "oldpass", key)
        monkeypatch.setattr("builtins.input", lambda prompt="": "test.com")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "newP@ss456")
        project.update_site_password(data, username, key)
        _, pw = get_credential(data, username, "test.com", key)
        assert pw == "newP@ss456"

    def test_update_nonexistent(self, monkeypatch, cli_user_setup, capsys):
        data, username, key = cli_user_setup
        monkeypatch.setattr("builtins.input", lambda prompt="": "nope.com")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "newpass")
        project.update_site_password(data, username, key)
        output = capsys.readouterr().out
        assert "not found" in output.lower()

    def test_delete_password(self, monkeypatch, cli_user_setup):
        data, username, key = cli_user_setup
        add_credential(data, username, "delete.me", "u", "p", key)
        inputs = iter(["delete.me", "y"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        project.delete_site_password(data, username)
        assert "delete.me" not in data["users"][username]["credentials"]

    def test_delete_cancelled(self, monkeypatch, cli_user_setup):
        data, username, key = cli_user_setup
        add_credential(data, username, "keep.me", "u", "p", key)
        inputs = iter(["keep.me", "n"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        project.delete_site_password(data, username)
        assert "keep.me" in data["users"][username]["credentials"]

    def test_delete_nonexistent(self, monkeypatch, cli_user_setup, capsys):
        data, username, key = cli_user_setup
        monkeypatch.setattr("builtins.input", lambda prompt="": "nope.com")
        project.delete_site_password(data, username)
        output = capsys.readouterr().out
        assert "not found" in output.lower()

    def test_list_sites_empty(self, cli_user_setup, capsys):
        data, username, _ = cli_user_setup
        project.list_sites(data, username)
        output = capsys.readouterr().out
        assert "No saved sites" in output

    def test_list_sites_with_data(self, cli_user_setup, capsys):
        data, username, key = cli_user_setup
        add_credential(data, username, "a.com", "u", "p", key)
        add_credential(data, username, "b.com", "u", "p", key)
        project.list_sites(data, username)
        output = capsys.readouterr().out
        assert "a.com" in output
        assert "b.com" in output


class TestCLILoginSecurity:
    def test_login_is_case_insensitive(self, monkeypatch):
        data = {"users": {}}
        register_user(data, "Alice", "MyStr0ng!Pass1")

        called = {"username": None}

        def fake_menu(_data, username, _key):
            called["username"] = username

        monkeypatch.setattr(project, "password_manager_menu", fake_menu)
        monkeypatch.setattr("builtins.input", lambda prompt="": "alice")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "MyStr0ng!Pass1")

        project.login_account(data)
        assert called["username"] == "Alice"

    def test_cli_lockout_after_repeated_failures(self, monkeypatch):
        data = {"users": {}}
        register_user(data, "tester", "MyStr0ng!Pass1")

        monkeypatch.setattr("builtins.input", lambda prompt="": "tester")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "WrongPass1!")

        for _ in range(MAX_LOGIN_ATTEMPTS):
            project.login_account(data)

        user = data["users"]["tester"]
        assert user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS
        assert user.get("lockout_until") is not None

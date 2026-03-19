# app.py — Secure Password Vault (Streamlit UI Layer)

import re
import logging

import streamlit as st
from datetime import datetime, timedelta, timezone

from core.config import (
    SESSION_TIMEOUT_MINUTES, MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES,
    MIN_PASSWORD_LENGTH, LOG_FILE,
)
from core.storage import load_data, atomic_update
from core.auth import register_user, authenticate_user
from core.vault import (
    add_credential, delete_credential, change_master_password, delete_account,
)
from core.password_utils import (
    check_password_strength, generate_password, sanitize_input,
)
from core.encryption import decrypt_value

# ------- Logging -------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ------- Page config -------

st.set_page_config(page_title="Secure Password Vault", page_icon="🔒", layout="centered")

# ------- Streamlit-specific helpers -------


def _parse_lockout(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def check_session_timeout() -> bool:
    if "last_activity" in st.session_state:
        elapsed = (datetime.now(timezone.utc) - st.session_state["last_activity"]).total_seconds()
        if elapsed > SESSION_TIMEOUT_MINUTES * 60:
            logout()
            st.warning("Session timed out due to inactivity. Please log in again.")
            return False
    st.session_state["last_activity"] = datetime.now(timezone.utc)
    return True


def logout():
    for k in ["logged_in", "user", "key", "last_activity"]:
        st.session_state.pop(k, None)


def show_password_strength_bar(password: str):
    if not password:
        return
    score = 0
    if len(password) >= MIN_PASSWORD_LENGTH:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        score += 1
    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
    colors = {0: "🔴", 1: "🔴", 2: "🟠", 3: "🟡", 4: "🟢", 5: "🟢"}
    st.caption(f"Strength: {colors[score]} {labels[score]} ({score}/5)")


# ------- Session state initialization -------

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["user"] = None
    st.session_state["key"] = None

if st.session_state.get("logged_in"):
    if not check_session_timeout():
        st.session_state["logged_in"] = False
        st.rerun()

# ------- Sidebar: Login or Register -------

st.sidebar.title("🔐 Password Vault")

if not st.session_state.get("logged_in"):
    action = st.sidebar.radio("Action", ["Login", "Register"])

    if action == "Register":
        st.sidebar.subheader("Create an account")
        new_user = sanitize_input(st.sidebar.text_input("New username", max_chars=64))
        new_pass = st.sidebar.text_input("New master password", type="password", max_chars=128)
        confirm_pass = st.sidebar.text_input("Confirm master password", type="password", max_chars=128)

        if new_pass:
            show_password_strength_bar(new_pass)

        if st.sidebar.button("Register"):
            if not new_pass:
                st.sidebar.error("Password cannot be empty.")
            elif new_pass != confirm_pass:
                st.sidebar.error("Passwords do not match.")
            else:
                def _register(data: dict):
                    return register_user(data, new_user, new_pass)

                saved, result = atomic_update(_register)
                ok, msg = result
                if not saved:
                    st.sidebar.error("Failed to save data. Please try again.")
                elif ok:
                    logger.info("New user registered: %s", new_user)
                    st.sidebar.success("User registered. Please log in.")
                else:
                    st.sidebar.error(msg)

    else:  # Login
        st.sidebar.subheader("Login to your account")
        username = sanitize_input(st.sidebar.text_input("Username", max_chars=64))
        password = st.sidebar.text_input("Master password", type="password", max_chars=128)

        if st.sidebar.button("Login"):
            if not username or not password:
                st.sidebar.error("Please enter both username and password.")
            else:
                def _login(data: dict):
                    users = data.get("users", {})
                    user = users.get(username)
                    now = datetime.now(timezone.utc)
                    if user is not None:
                        lockout_until = _parse_lockout(user.get("lockout_until"))
                        if lockout_until and now < lockout_until:
                            remaining = int((lockout_until - now).total_seconds() // 60) + 1
                            return "locked", f"Account temporarily locked. Try again in {remaining} minute(s).", None

                    ok_local, msg_local, key_local = authenticate_user(data, username, password)

                    if ok_local and user is not None:
                        user["failed_attempts"] = 0
                        user["lockout_until"] = None
                        return "ok", msg_local, key_local

                    if user is not None:
                        attempts = int(user.get("failed_attempts", 0)) + 1
                        user["failed_attempts"] = attempts
                        if attempts >= MAX_LOGIN_ATTEMPTS:
                            user["lockout_until"] = (
                                datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                            ).isoformat()
                            logger.warning("Account '%s' locked out after %d failed attempts.", username, MAX_LOGIN_ATTEMPTS)
                    return "fail", msg_local, None

                saved, login_result = atomic_update(_login)
                if not saved:
                    st.sidebar.error("Failed to save login state. Please try again.")
                    st.stop()

                status, msg, fernet_key = login_result
                if status == "ok":
                    st.session_state["logged_in"] = True
                    st.session_state["user"] = username
                    st.session_state["key"] = fernet_key
                    st.session_state["last_activity"] = datetime.now(timezone.utc)
                    logger.info("User logged in: %s", username)
                    st.rerun()
                elif status == "locked":
                    st.sidebar.error(msg)
                else:
                    logger.warning("Failed login attempt for user: %s", username)
                    st.sidebar.error(msg)

else:
    st.sidebar.write(f"**Logged in:** {st.session_state['user']}")
    if st.sidebar.button("🚪 Logout"):
        logger.info("User logged out: %s", st.session_state.get("user"))
        logout()
        st.rerun()

# ------- Main App -------

if st.session_state.get("logged_in"):
    st.title("🔒 Secure Password Vault")

    menu = st.sidebar.selectbox(
        "Menu",
        ["View Credentials", "Add Credential", "Generate Password",
         "Delete Credential", "Reset Master Password", "Delete Account"],
    )
    current_user = st.session_state["user"]
    key = st.session_state["key"]
    data = load_data(use_lock=True)

    if current_user not in data.get("users", {}):
        st.error("Your account was not found. Please register again.")
        logout()
        st.rerun()

    # ------- View Credentials -------
    if menu == "View Credentials":
        st.header("📋 Stored Credentials")
        creds = data["users"][current_user].get("credentials", {})
        if creds:
            search = st.text_input("🔍 Search sites", "").strip().lower()
            filtered = {s: v for s, v in creds.items() if search in s.lower()} if search else creds

            if not filtered:
                st.info("No matching credentials found.")
            else:
                for site, info in sorted(filtered.items()):
                    with st.expander(f"🌐 {site}", expanded=False):
                        st.text(f"Username: {info.get('login', 'N/A')}")
                        dec_pass = decrypt_value(key, info["password"])
                        if dec_pass:
                            show_pw = st.checkbox("Show password", key=f"show_{site}", value=False)
                            if show_pw:
                                st.code(dec_pass, language=None)
                            else:
                                st.text("Password: ••••••••••")
                        else:
                            st.error("Failed to decrypt password.")
                            logger.error("Decryption failed for site '%s', user '%s'.", site, current_user)
        else:
            st.info("No credentials stored yet. Add one from the menu!")

    # ------- Add Credential -------
    elif menu == "Add Credential":
        st.header("➕ Add New Credential")
        site = sanitize_input(st.text_input("Site name (e.g. github.com)", max_chars=256))
        site_user = sanitize_input(st.text_input("Site username / email", max_chars=256))

        use_generated = st.checkbox("Generate a strong password", value=False)
        if use_generated:
            pw_length = st.slider("Password length", min_value=12, max_value=128, value=20)
            if "generated_pw" not in st.session_state:
                st.session_state["generated_pw"] = generate_password(pw_length)
            if st.button("🔄 Regenerate"):
                st.session_state["generated_pw"] = generate_password(pw_length)
            site_pass = st.session_state["generated_pw"]
            st.code(site_pass, language=None)
        else:
            site_pass = st.text_input("Site password", type="password", max_chars=256)

        if st.button("💾 Save Credential"):
            def _add(data: dict):
                if current_user not in data.get("users", {}):
                    return False, "Account not found. Please log in again."
                return add_credential(data, current_user, site, site_user, site_pass, key)

            saved, result = atomic_update(_add)
            ok, msg = result
            if not saved:
                st.error("Failed to save data. Please try again.")
            elif ok:
                st.session_state.pop("generated_pw", None)
                logger.info("Credential added for site '%s' by user '%s'.", site, current_user)
                st.success(msg)
            else:
                st.warning(msg)

    # ------- Generate Password -------
    elif menu == "Generate Password":
        st.header("🎲 Password Generator")
        length = st.slider("Password length", min_value=12, max_value=128, value=20)
        if st.button("Generate Password"):
            st.session_state["standalone_pw"] = generate_password(length)
        if "standalone_pw" in st.session_state:
            st.code(st.session_state["standalone_pw"], language=None)
            st.caption("Copy the password above and use it wherever needed.")

    # ------- Delete Credential -------
    elif menu == "Delete Credential":
        st.header("🗑️ Delete Credential")
        creds = data["users"][current_user].get("credentials", {})
        if not creds:
            st.info("No credentials to delete.")
        else:
            site_to_delete = st.selectbox("Select site to delete", sorted(creds.keys()))
            confirm = st.checkbox(f"I confirm I want to permanently delete **{site_to_delete}**")
            if st.button("Delete", disabled=not confirm):
                def _delete(data: dict):
                    return delete_credential(data, current_user, site_to_delete)

                saved, result = atomic_update(_delete)
                ok, msg = result
                if not saved:
                    st.error("Failed to save data. Please try again.")
                elif ok:
                    logger.info("Credential deleted for site '%s' by user '%s'.", site_to_delete, current_user)
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

    # ------- Reset Master Password -------
    elif menu == "Reset Master Password":
        st.header("🔑 Change Master Password")
        old_pass = st.text_input("Current master password", type="password", max_chars=128)
        new_pass = st.text_input("New master password", type="password", max_chars=128)
        confirm_new = st.text_input("Confirm new master password", type="password", max_chars=128)

        if new_pass:
            show_password_strength_bar(new_pass)

        if st.button("Change Password"):
            if not old_pass or not new_pass or not confirm_new:
                st.error("All fields are required.")
            elif new_pass != confirm_new:
                st.error("New passwords do not match.")
            else:
                def _change_password(data: dict):
                    return change_master_password(data, current_user, old_pass, new_pass)

                saved, result = atomic_update(_change_password)
                ok, msg, _ = result
                if not saved:
                    st.error("Failed to save data. Please try again.")
                elif ok:
                    logger.info("Master password changed for user '%s'.", current_user)
                    st.success(msg)
                    logout()
                    st.rerun()
                else:
                    st.error(msg)

    # ------- Delete Account -------
    elif menu == "Delete Account":
        st.header("⚠️ Delete Account")
        st.warning("This will permanently delete your account and all stored credentials. This action cannot be undone.")
        del_pass = st.text_input("Enter your master password to confirm", type="password", max_chars=128)
        confirm_del = st.checkbox("I understand this is irreversible")
        if st.button("🗑️ Delete My Account", disabled=not confirm_del):
            def _delete_account(data: dict):
                return delete_account(data, current_user, del_pass)

            saved, result = atomic_update(_delete_account)
            ok, msg = result
            if not saved:
                st.error("Failed to save data. Please try again.")
            elif ok:
                logger.info("Account deleted: %s", current_user)
                st.success(msg)
                logout()
                st.rerun()
            else:
                st.error(msg)

else:
    st.title("🔒 Secure Password Vault")
    st.markdown(
        """
        Welcome to your **Secure Password Vault** — a personal, offline password manager.

        **Features:**
        - 🔐 AES-256 encryption with per-user derived keys (PBKDF2)
        - 🛡️ Bcrypt password hashing with salted rounds
        - 🔑 Password strength checker & generator
        - ⏱️ Auto session timeout for security
        - 🚫 Brute-force lockout protection
        - 📋 Search, add, view, and delete credentials

        **Get started** by registering or logging in from the sidebar.
        """
    )

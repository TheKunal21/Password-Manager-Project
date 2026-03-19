"""
project.py — Secure Password Manager (CLI Interface)

A thin command-line interface that delegates all business logic
to the core/ package modules.
"""

import getpass

from core.storage import load_data, save_data, load_master_hash, store_master_hash
from core.auth import hash_password, verify_password, register_user, authenticate_user
from core.vault import (
    add_credential, get_credential, list_credential_sites,
    update_credential, delete_credential,
)
from core.password_utils import check_password_strength, generate_password, validate_username


def main():
    saved_hash = load_master_hash()
    if saved_hash is None:
        print("No master password found. Please create one.")
        create_master_password()
    else:
        print("Master password found. Please enter it to proceed.")
        for attempt in range(3):
            entered = getpass.getpass("Enter master password: ").strip()
            if verify_password(entered, saved_hash):
                print("Master password verified.")
                break
            remaining = 2 - attempt
            if remaining > 0:
                print(f"Incorrect. {remaining} attempt(s) remaining.")
            else:
                print("Too many failed attempts. Exiting.")
                return

    while True:
        print("\n--- Main Menu ---")
        print("1. Create account")
        print("2. Login")
        print("0. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            data = load_data()
            create_account(data)
        elif choice == "2":
            data = load_data()
            login_account(data)
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


# ------- Master password -------


def create_master_password():
    """Prompt user to create a strong master password."""
    while True:
        pw = getpass.getpass("Create your master password: ").strip()
        if not pw:
            print("Password cannot be empty.")
            continue
        valid, issues = check_password_strength(pw)
        if not valid:
            print("Password is too weak:")
            for issue in issues:
                print(f"  - {issue}")
            continue
        confirm = getpass.getpass("Confirm your master password: ").strip()
        if pw != confirm:
            print("Passwords do not match. Try again.")
            continue
        store_master_hash(hash_password(pw))
        print("Master password created successfully.")
        return


# ------- Account management -------


def create_account(data):
    """Create a new user account via CLI prompts."""
    username = input("Enter your username: ").strip()
    valid, msg = validate_username(username)
    if not valid:
        print(msg)
        return

    pw = getpass.getpass("Enter your password: ").strip()
    if not pw:
        print("Password cannot be empty.")
        return

    ok, msg = register_user(data, username, pw)
    print(msg)
    if ok:
        if not save_data(data):
            print("Error: Failed to persist account data.")


def login_account(data):
    """Login and enter the password manager."""
    username = input("Enter your username: ").strip()
    pw = getpass.getpass("Enter your password: ").strip()

    ok, msg, fernet_key = authenticate_user(data, username, pw)
    print(msg)
    if ok:
        password_manager_menu(data, username, fernet_key)


# ------- Password manager operations -------


def password_manager_menu(data, username, fernet_key):
    """Interactive password manager loop for a logged-in user."""
    while True:
        print(f"\n--- Password Manager ({username}) ---")
        print("1. Save password")
        print("2. Retrieve password")
        print("3. List all sites")
        print("4. Update password")
        print("5. Delete password")
        print("6. Generate password")
        print("0. Logout")
        action = input("Choice: ").strip()

        if action == "1":
            save_site_password(data, username, fernet_key)
        elif action == "2":
            retrieve_site_password(data, username, fernet_key)
        elif action == "3":
            list_sites(data, username)
        elif action == "4":
            update_site_password(data, username, fernet_key)
        elif action == "5":
            delete_site_password(data, username)
        elif action == "6":
            length_str = input("Password length (default 20): ").strip()
            try:
                length = int(length_str) if length_str else 20
            except ValueError:
                length = 20
            print(f"Generated password: {generate_password(length)}")
        elif action == "0":
            print("Logged out.")
            break
        else:
            print("Invalid choice.")


def save_site_password(data, username, fernet_key):
    """Prompt for site details and store an encrypted credential."""
    site = input("Enter the site name: ").strip().lower()
    if not site:
        print("Site name cannot be empty.")
        return
    login = input("Enter the site username/email: ").strip()
    if not login:
        print("Site username cannot be empty.")
        return
    site_pw = getpass.getpass("Enter the site password: ").strip()
    if not site_pw:
        print("Password cannot be empty.")
        return

    ok, msg = add_credential(data, username, site, login, site_pw, fernet_key)
    print(msg)
    if ok:
        if not save_data(data):
            print("Error: Failed to persist credential data.")


def retrieve_site_password(data, username, fernet_key):
    """Decrypt and display a site password."""
    site = input("Enter the site name: ").strip().lower()
    if not site:
        print("Site name cannot be empty.")
        return
    login, password = get_credential(data, username, site, fernet_key)
    if login is None and password is None:
        print("No entry found for that site.")
        return
    if password is None:
        print("Error: Could not decrypt password. Key may have changed.")
        return
    print(f"Site: {site}")
    print(f"Username: {login}")
    print(f"Password: {password}")


def list_sites(data, username):
    """List all saved site names."""
    sites = list_credential_sites(data, username)
    if sites:
        print("Saved sites:")
        for s in sites:
            print(f"  - {s}")
    else:
        print("No saved sites yet.")


def update_site_password(data, username, fernet_key):
    """Update an existing site password."""
    site = input("Enter the site name to update: ").strip().lower()
    new_pw = getpass.getpass("Enter the new password: ").strip()
    if not new_pw:
        print("Password cannot be empty.")
        return
    ok, msg = update_credential(data, username, site, new_pw, fernet_key)
    print(msg)
    if ok:
        if not save_data(data):
            print("Error: Failed to persist credential update.")


def delete_site_password(data, username):
    """Delete a site password after confirmation."""
    site = input("Enter the site name to delete: ").strip().lower()
    if not site:
        print("Site name cannot be empty.")
        return
    user = data.get("users", {}).get(username)
    if user is None or site not in user.get("credentials", {}):
        print("Site not found.")
        return
    confirm = input(f"Are you sure you want to delete '{site}'? (y/n): ").strip().lower()
    if confirm == "y":
        ok, msg = delete_credential(data, username, site)
        print(msg)
        if ok:
            if not save_data(data):
                print("Error: Failed to persist credential deletion.")
    else:
        print("Cancelled.")


if __name__ == "__main__":
    main()

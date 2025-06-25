import hashlib
import getpass
from cryptography.fernet import Fernet
import os
import json

password_manager = {}


def main():
    global password_manager
    password_manager = load_accounts()

    try:
        with open("master.hash", "r") as file:
            saved_hash = file.read().strip()
    except FileNotFoundError:
        saved_hash = None

    if saved_hash is None:
        print("No master password found, please create one.")
        create_master_password()
    else:
        print("Master password found, please enter it to proceed.")
        entered_password = getpass.getpass("Enter master password: ").strip()
        if not verify_master_password(entered_password):
            print("Master password verification failed. Exiting.")
            return

    generate_key()

    # If master password was verified or created, go to account menu
    while True:
        choice = input("For create account enter 1, 2 for login, 0 for exit: ").strip()
        if choice == "1":
            create_account()
        elif choice == "2":
            login_account()
        elif choice == "0":
            break
        else:
            print("Invalid choice, try again.")


# Load or initialize the accounts data from 'accounts.json'
def load_accounts():
    if os.path.exists("accounts.json"):
        with open("accounts.json", "r") as file:
            content = file.read().strip()
            if content:  # Only load if there's content
                return json.loads(content)
    return {}


# Save the accounts data to 'accounts.json'
def save_accounts():
    with open("accounts.json", "w") as file:
        json.dump(password_manager, file, indent=4)


def create_master_password():
    while True:
        master_password = getpass.getpass("Create your master password: ").strip()
        if not master_password:
            print("Password cannot be empty. Try again.")
        else:
            break
    hashed = hashlib.sha256(master_password.encode()).hexdigest()
    storing_master_hash(hashed)
    print("Master password created and saved successfully.")


def verify_master_password(entered_password):
    try:
        with open("master.hash", "r") as file:
            saved_hash = file.read().strip()
    except FileNotFoundError:
        return False  # No master password exists

    hashed = hashlib.sha256(entered_password.encode()).hexdigest()
    return hashed == saved_hash


def create_account():
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    if username in password_manager:
        print("Username already exists. Please choose another.")
        return

    password = getpass.getpass("Enter your password please: ").strip()
    if not password:
        print("Password cannot be empty.")
        return

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Store account in password_manager with username and hashed password
    password_manager[username] = {
        "password": hashed_password,
        "sites": {},  # Store passwords for sites here
    }
    save_accounts()
    print("Account created successfully")


def login_account():
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if username exists and password matches
    if (
        username in password_manager
        and password_manager[username]["password"] == hashed_password
    ):
        print("Welcome, your login is successful!")
        password_manager_function(
            username
        )  # Pass username to link the password manager
    else:
        print("Invalid username or password")


def storing_master_hash(hash_str):
    with open("master.hash", "w") as file:
        file.write(hash_str)


def generate_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as file:
            file.write(key)
        print("Encryption key generated and saved to key.key.")
    else:
        print("Key already exists. Skipping generation.")


def load_key():
    with open("key.key", "rb") as file:
        return file.read()


# Password manager function with user-specific site passwords
def password_manager_function(username):
    fernet = Fernet(load_key())
    while True:
        action = input(
            "Press 1 to save, 2 to retrieve, 3 to delete , 4 to update  , 0 to logout: "
        ).strip()

        if action == "1":
            site = input("Enter the site name: ").strip().lower()
            site_password = getpass.getpass("Enter the password: ").strip()
            if site and site_password:
                encrypted = fernet.encrypt(site_password.encode()).decode()
                # Save the password under the user’s username
                password_manager[username]["sites"][site] = encrypted
                save_accounts()
                print("Password successfully secured!")
            else:
                print("Site and password cannot be empty.")

        elif action == "2":
            site = (
                input("Enter the site name to retrieve your password: ").strip().lower()
            )
            if site in password_manager[username]["sites"]:
                encrypted_password = password_manager[username]["sites"][site]
                decrypted = fernet.decrypt(encrypted_password.encode()).decode()
                print(f"Site: {site}\nPassword: {decrypted}")
            else:
                print("No entry found for that site.")

        elif action == "3":
            all_sites = list(password_manager[username]["sites"].keys())
            if all_sites:
                print("Saved sites:", ", ".join(all_sites))
                site = input("Enter the site name to delete: ").strip().lower()
                delete_password(site, username)
            else:
                print("You have no saved sites yet.")

        elif action == "4":
            all_sites = list(password_manager[username]["sites"].keys())
            if all_sites:
                print("Saved sites:", ", ".join(all_sites))
                site = input("Enter the site name to update: ").strip().lower()
                update_password(site, username)
            else:
                print("You have no saved sites yet.")

        elif action == "0":
            print("Logging out of password manager.")
            break
        else:
            print("Invalid choice.")


def update_password(site, username):
    if site not in password_manager[username]["sites"]:
        print("Site not found. Cannot update a non-existent password.")
        return

    fernet = Fernet(load_key())
    new_password = getpass.getpass("Enter the new password: ").strip()
    if not new_password:
        print("Password cannot be empty.")
        return

    encrypted = fernet.encrypt(new_password.encode()).decode()
    password_manager[username]["sites"][site] = encrypted
    save_accounts()
    print("Password updated successfully.")


def delete_password(site, username):
    if site in password_manager[username]["sites"]:
        del password_manager[username]["sites"][site]
        save_accounts()
        print("Password deleted successfully.")
    else:
        print("Site not found.")

if __name__ == "__main__":
    main()
import hashlib
import getpass
from cryptography.fernet import Fernet
import os
import json
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

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
        password_manager_function(username)  # Pass username to link the password manager
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
            site = input("Enter the site name to retrieve your password: ").strip().lower()
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



# GUI part from here . 

def gui_main():
    app = ttk.Window(title="Password Manager", themename="superhero", size=(400, 300))

    def create_master_gui():
        # Clear window
        for widget in app.winfo_children():
            widget.destroy()

        ttk.Label(
            app, text="Create Master Password", font=("Helvetica", 14), bootstyle="warning"
        ).pack(pady=(20, 10))

        password_entry = ttk.Entry(app, show="*", width=30)
        password_entry.pack(pady=5)

        def save_master():
            password = password_entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            hashed = hashlib.sha256(password.encode()).hexdigest()
            storing_master_hash(hashed)
            messagebox.showinfo("Success", "Master password created!")
            app.destroy()
            gui_account_screen()

        ttk.Button(
            app, text="Save Master Password", command=save_master, bootstyle="success"
        ).pack(pady=15)

    def verify_master_gui():
        # Clear window
        for widget in app.winfo_children():
            widget.destroy()

        ttk.Label(
            app, text="Enter Master Password", font=("Helvetica", 14), bootstyle="warning"
        ).pack(pady=(20, 10))

        password_entry = ttk.Entry(app, show="*", width=30)
        password_entry.pack(pady=5)

        def check_master():
            entered = password_entry.get().strip()
            if not verify_master_password(entered):
                messagebox.showerror("Error", "Incorrect master password")
            else:
                messagebox.showinfo("Success", "Welcome back!")
                app.destroy()
                gui_account_screen()

        ttk.Button(app, text="Login", command=check_master, bootstyle="success").pack(pady=15)

    ttk.Label(
        app, text="Password Manager", font=("Helvetica", 16), bootstyle="info"
    ).pack(pady=(30, 10))

    if not os.path.exists("master.hash"):
        create_master_gui()
    else:
        verify_master_gui()

    app.mainloop()


def gui_account_screen():
    account_app = ttk.Window(
        title="Your Personal Account", themename="superhero", size=(400, 300)
    )
    account_app.columnconfigure(0, weight=1)

    ttk.Label(
        account_app,
        text="Account Portal",
        font=("Helvetica", 16),
        bootstyle="info",
    ).grid(row=0, column=0, pady=(20, 10))

    def create_account_gui():
        create_win = ttk.Toplevel(account_app)
        create_win.title("Create Account")
        create_win.geometry("300x200")
        create_win.columnconfigure(0, weight=1)

        ttk.Label(create_win, text="Username", font=("Helvetica", 12)).pack(pady=(10, 5))
        username_entry = ttk.Entry(create_win, width=30)
        username_entry.pack(pady=5)

        ttk.Label(create_win, text="Password", font=("Helvetica", 12)).pack(pady=(10, 5))
        password_entry = ttk.Entry(create_win, show="*", width=30)
        password_entry.pack(pady=5)

        def save_account():
            username = username_entry.get().strip()
            password = password_entry.get().strip()

            if not username or not password:
                messagebox.showerror("Error", "Fields cannot be empty.")
                return
            if username in password_manager:
                messagebox.showerror("Error", "Username already exists.")
                return
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            password_manager[username] = {"password": hashed_password, "sites": {}}
            save_accounts()
            messagebox.showinfo("Success", "Account created.")
            create_win.destroy()

        ttk.Button(
            create_win, text="Create", command=save_account, bootstyle="success"
        ).pack(pady=(15, 5))

    def login_account_gui():
        login_win = ttk.Toplevel(account_app)
        login_win.title("Login")
        login_win.geometry("300x200")
        login_win.columnconfigure(0, weight=1)

        ttk.Label(login_win, text="Username", font=("Helvetica", 12)).pack(pady=(10, 5))
        username_entry = ttk.Entry(login_win, width=30)
        username_entry.pack(pady=5)

        ttk.Label(login_win, text="Password", font=("Helvetica", 12)).pack(pady=(10, 5))
        password_entry = ttk.Entry(login_win, show="*", width=30)
        password_entry.pack(pady=5)

        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            hashed = hashlib.sha256(password.encode()).hexdigest()
            if (
                username in password_manager
                and password_manager[username]["password"] == hashed
            ):
                messagebox.showinfo("Login successful", f"Welcome, {username}!")
                login_win.destroy()
                account_app.destroy()
                gui_password_manager_function(username)
            else:
                messagebox.showerror("Login Failed", "Invalid Credentials.")

        ttk.Button(
            login_win, text="Login", command=do_login, bootstyle="success"
        ).pack(pady=(15, 5))

    # Centering the two buttons
    button_frame = ttk.Frame(account_app)
    button_frame.grid(row=1, column=0, pady=20)
    button_frame.columnconfigure((0, 1), weight=1, uniform="a")

    ttk.Button(
        button_frame,
        text="Create New Account",
        command=create_account_gui,
        bootstyle="primary",
    ).grid(row=0, column=0, padx=10, sticky="ew")
    ttk.Button(
        button_frame,
        text="Login to Account",
        command=login_account_gui,
        bootstyle="success",
    ).grid(row=0, column=1, padx=10, sticky="ew")

    account_app.mainloop()


def gui_password_manager_function(username):
    fernet = Fernet(load_key())

    vault = ttk.Window(
        title=f"{username}'s Vault", themename="superhero", size=(450, 400)
    )
    vault.columnconfigure(0, weight=1)

    ttk.Label(
        vault,
        text=f"Welcome, {username}",
        font=("Helvetica", 16),
        bootstyle="success",
    ).grid(row=0, column=0, pady=(20, 10))

    # ---------------------------
    # SAVE & UPDATE FRAME
    # ---------------------------
    frame_save_update = ttk.Frame(vault)
    frame_save_update.grid(row=1, column=0, pady=10, sticky="nsew")
    frame_save_update.columnconfigure((0, 1), weight=1, uniform="a")

    ttk.Label(
        frame_save_update, text="Site Name", font=("Helvetica", 12), bootstyle="secondary"
    ).grid(row=0, column=0, padx=5, sticky="e")
    site_entry_save = ttk.Entry(frame_save_update, width=25)
    site_entry_save.grid(row=0, column=1, padx=5, sticky="w")

    ttk.Label(
        frame_save_update, text="Password", font=("Helvetica", 12), bootstyle="secondary"
    ).grid(row=1, column=0, padx=5, sticky="e")
    password_entry_save = ttk.Entry(frame_save_update, show="*", width=25)
    password_entry_save.grid(row=1, column=1, padx=5, sticky="w")

    def save_password_gui():
        site = site_entry_save.get().strip().lower()
        pwd = password_entry_save.get().strip()
        if site and pwd:
            encrypted = fernet.encrypt(pwd.encode()).decode()
            password_manager[username]["sites"][site] = encrypted
            save_accounts()
            messagebox.showinfo("Saved", f"Password for '{site}' saved!")
            site_entry_save.delete(0, "end")
            password_entry_save.delete(0, "end")
        else:
            messagebox.showerror("Error", "Site and password cannot be empty!")

    def update_password_gui():
        site = site_entry_save.get().strip().lower()
        if not site:
            messagebox.showerror("Error", "Site name cannot be empty.")
            return

        if site in password_manager[username]["sites"]:
            new_pwd = password_entry_save.get().strip()
            if not new_pwd:
                messagebox.showerror("Error", "New password cannot be empty.")
                return
            encrypted = fernet.encrypt(new_pwd.encode()).decode()
            password_manager[username]["sites"][site] = encrypted
            save_accounts()
            messagebox.showinfo("Updated", f"Password for '{site}' updated.")
            site_entry_save.delete(0, "end")
            password_entry_save.delete(0, "end")
        else:
            messagebox.showwarning("Site not found", f"No entry for '{site}' exists.")

    ttk.Button(
        frame_save_update, text="Save", command=save_password_gui, bootstyle="success"
    ).grid(row=2, column=0, pady=10, sticky="ew", padx=5)
    ttk.Button(
        frame_save_update, text="Update", command=update_password_gui, bootstyle="warning"
    ).grid(row=2, column=1, pady=10, sticky="ew", padx=5)

    # ---------------------------
    # RETRIEVE & DELETE FRAME
    # ---------------------------
    frame_retrieve_delete = ttk.Frame(vault)
    frame_retrieve_delete.grid(row=2, column=0, pady=10, sticky="nsew")
    frame_retrieve_delete.columnconfigure((0, 1), weight=1, uniform="b")

    ttk.Label(
        frame_retrieve_delete, text="Site Name", font=("Helvetica", 12), bootstyle="secondary"
    ).grid(row=0, column=0, padx=5, sticky="e")
    site_entry_manage = ttk.Entry(frame_retrieve_delete, width=25)
    site_entry_manage.grid(row=0, column=1, padx=5, sticky="w")

    def retrieve_password_gui():
        site = site_entry_manage.get().strip().lower()
        if not site:
            messagebox.showerror("Error", "Site name cannot be empty.")
            return

        if site in password_manager[username]["sites"]:
            encrypted = password_manager[username]["sites"][site]
            decrypted = fernet.decrypt(encrypted.encode()).decode()
            messagebox.showinfo("Retrieved", f"Password for '{site}':\n{decrypted}")
            site_entry_manage.delete(0, "end")
        else:
            messagebox.showwarning("Not found", f"No entry for '{site}' exists.")

    def delete_password_gui():
        site = site_entry_manage.get().strip().lower()
        if not site:
            messagebox.showerror("Error", "Site name cannot be empty.")
            return

        if site in password_manager[username]["sites"]:
            del password_manager[username]["sites"][site]
            save_accounts()
            messagebox.showinfo("Deleted", f"Password for '{site}' deleted.")
            site_entry_manage.delete(0, "end")
        else:
            messagebox.showwarning("Not found", f"No entry for '{site}' exists.")

    ttk.Button(
        frame_retrieve_delete, text="Retrieve", command=retrieve_password_gui, bootstyle="info"
    ).grid(row=1, column=0, pady=10, sticky="ew", padx=5)
    ttk.Button(
        frame_retrieve_delete, text="Delete", command=delete_password_gui, bootstyle="danger"
    ).grid(row=1, column=1, pady=10, sticky="ew", padx=5)

    # ---------------------------
    # Logout button
    # ---------------------------
    ttk.Button(
        vault, text="Logout", command=vault.destroy, bootstyle="secondary"
    ).grid(row=3, column=0, pady=(20, 10), sticky="ew", padx=50)

    vault.mainloop()


if __name__ == "__main__":
    choice = input("Type 'gui' for GUI or 'cli' for command line: ").strip().lower()
    if choice == "gui":
        gui_main()
    else:
        main()

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


from ttkbootstrap.window import Window
from tkinter import messagebox
import hashlib
import os
from tkinter import simpledialog
from cryptography.fernet import Fernet

# Assume these are already defined and working
password_manager = {}
def save_accounts(): pass
def storing_master_hash(hashed): pass
def verify_master_password(password): return True

app = Window(title="Password Manager", themename="superhero", size=(500, 400))


def gui_main():
    app.eval("tk::PlaceWindow . center")

    def clear_widgets():
        for widget in app.winfo_children():
            widget.destroy()

    def create_master_gui():
        clear_widgets()
        frame = ttk.Frame(app)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Create Master Password", font=("Helvetica", 16), bootstyle="warning").pack(pady=10)
        password_entry = ttk.Entry(frame, show="*", font=("Helvetica", 14), width=25)
        password_entry.pack(pady=10)

        def save_master():
            password = password_entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            hashed = hashlib.sha256(password.encode()).hexdigest()
            storing_master_hash(hashed)
            messagebox.showinfo("Success", "Master password created!")
            app.withdraw()
            gui_account_screen()

        ttk.Button(frame, text="Save Master Password", command=save_master, bootstyle="success", width=25).pack(pady=15)

    def verify_master_gui():
        clear_widgets()
        frame = ttk.Frame(app)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Enter Master Password", font=("Helvetica", 16), bootstyle="warning").pack(pady=10)
        password_entry = ttk.Entry(frame, show="*", font=("Helvetica", 14), width=25)
        password_entry.pack(pady=10)

        def check_master():
            entered = password_entry.get().strip()
            if not verify_master_password(entered):
                messagebox.showerror("Error", "Incorrect master password")
            else:
                messagebox.showinfo("Success", "Welcome back!")
                app.withdraw()
                gui_account_screen()

        ttk.Button(frame, text="Login", command=check_master, bootstyle="success", width=25).pack(pady=15)

    ttk.Label(app, text="Password Manager", font=("Helvetica", 20), bootstyle="info").pack(pady=30)
    if not os.path.exists("master.hash"):
        create_master_gui()
    else:
        verify_master_gui()
    app.mainloop()


def gui_account_screen():
    account_app = Window(title="Account Login", themename="superhero", size=(500, 400))
    account_app.eval("tk::PlaceWindow . center")
    frame = ttk.Frame(account_app)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Account Portal", font=("Helvetica", 18), bootstyle="info").pack(pady=20)

    ttk.Button(frame, text="Create New Account", command=lambda: create_account_gui(account_app), bootstyle="primary", width=30).pack(pady=10)
    ttk.Button(frame, text="Login to Account", command=lambda: login_account_gui(account_app), bootstyle="success", width=30).pack(pady=10)



def create_account_gui(parent):
    win = ttk.Toplevel(parent)
    win.title("Create Account")
    win.geometry("350x250")
    win.eval("tk::PlaceWindow . center")

    frame = ttk.Frame(win)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Username", font=("Helvetica", 12)).pack(pady=5)
    username_entry = ttk.Entry(frame, width=30)
    username_entry.pack(pady=5)

    ttk.Label(frame, text="Password", font=("Helvetica", 12)).pack(pady=5)
    password_entry = ttk.Entry(frame, show="*", width=30)
    password_entry.pack(pady=5)

    def save():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Fields cannot be empty.")
            return
        if username in password_manager:
            messagebox.showerror("Error", "Username already exists.")
            return
        password_manager[username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "sites": {},
        }
        save_accounts()
        messagebox.showinfo("Success", "Account created.")
        win.destroy()

    ttk.Button(frame, text="Create", command=save, bootstyle="success", width=25).pack(pady=15)


def login_account_gui(parent):
    win = ttk.Toplevel(parent)
    win.title("Login")
    win.geometry("350x250")
    win.eval("tk::PlaceWindow . center")

    frame = ttk.Frame(win)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Username", font=("Helvetica", 12)).pack(pady=5)
    username_entry = ttk.Entry(frame, width=30)
    username_entry.pack(pady=5)

    ttk.Label(frame, text="Password", font=("Helvetica", 12)).pack(pady=5)
    password_entry = ttk.Entry(frame, show="*", width=30)
    password_entry.pack(pady=5)

    def login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        if username in password_manager and password_manager[username]["password"] == hashed:
            messagebox.showinfo("Login", f"Welcome, {username}!")
            win.destroy()
            parent.destroy()
            gui_password_manager_function(username)
        else:
            messagebox.showerror("Failed", "Invalid credentials.")

    ttk.Button(frame, text="Login", command=login, bootstyle="success", width=25).pack(pady=15)


def gui_password_manager_function(username):
    win = ttk.Toplevel(app)
    win.title(f"Welcome {username}")
    win.geometry("600x400")
    win.eval("tk::PlaceWindow . center")

    frame = ttk.Frame(win)
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(
        frame, text=f"Hello, {username}!",
        font=("Helvetica", 18),
        bootstyle="info"
    ).pack(pady=20)

    ttk.Button(
        frame, text="View Saved Passwords",
        bootstyle="primary", width=30,
        command=lambda: view_passwords(win, username)
    ).pack(pady=5)

    ttk.Button(
        frame, text="Add New Password",
        bootstyle="success", width=30,
        command=lambda: add_password(win, username)
    ).pack(pady=5)

    ttk.Button(
        frame, text="Delete Password",
        bootstyle="danger", width=30,
        command=lambda: delete_password(win, username)
    ).pack(pady=5)


# Dummy password manager actions
def view_passwords(win, username):
    sites = password_manager[username].get("sites", {})
    if not sites:
        messagebox.showinfo("Passwords", "No passwords saved.")
        return
    info = "\n".join([f"{site}: {cred}" for site, cred in sites.items()])
    messagebox.showinfo("Saved Passwords", info)

def add_password(win, username):
    site = simpledialog.askstring("Add Site", "Enter site name:", parent=win)
    password = simpledialog.askstring("Add Password", "Enter password:", parent=win, show="*")
    if site and password:
        password_manager[username]["sites"][site] = password
        save_accounts()
        messagebox.showinfo("Added", f"Password saved for {site}")

def delete_password(win, username):
    site = simpledialog.askstring("Delete Site", "Enter site name to delete:", parent=win)
    if site and site in password_manager[username]["sites"]:
        del password_manager[username]["sites"][site]
        save_accounts()
        messagebox.showinfo("Deleted", f"Password for {site} deleted")
    else:
        messagebox.showerror("Error", "Site not found.")

if __name__ == "__main__":
    gui_main()

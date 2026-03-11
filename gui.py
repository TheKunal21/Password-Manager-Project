import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
import os
import json


class PasswordManagerGUI:
    def __init__(self):
        self.password_manager = {}
        self.current_user = None
        self.fernet = None
        
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("600x500")
        self.root.configure(bg='#2c3e50')
        
        # Load accounts data
        self.password_manager = self.load_accounts()
        
        # Check for master password
        self.check_master_password()
        
        # Style configuration
        self.setup_styles()
        
        # Start with master password verification
        self.show_master_password_screen()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', 
                       font=('Arial', 16, 'bold'),
                       background='#2c3e50',
                       foreground='#ecf0f1')
        
        style.configure('Subtitle.TLabel',
                       font=('Arial', 12),
                       background='#2c3e50',
                       foreground='#bdc3c7')
        
        style.configure('Custom.TButton',
                       font=('Arial', 10, 'bold'),
                       padding=10)
        
        style.configure('Custom.TFrame',
                       background='#2c3e50')
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def check_master_password(self):
        """Check if master password exists"""
        try:
            with open("master.hash", "r") as file:
                return file.read().strip()
        except FileNotFoundError:
            return None
    
    def show_master_password_screen(self):
        """Show master password creation or verification screen"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, style='Custom.TFrame')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Secure Password Manager", 
                               style='Title.TLabel')
        title_label.pack(pady=20)
        
        # Check if master password exists
        saved_hash = self.check_master_password()
        
        if saved_hash is None:
            self.show_create_master_password(main_frame)
        else:
            self.show_verify_master_password(main_frame)
    
    def show_create_master_password(self, parent):
        """Show create master password interface"""
        subtitle = ttk.Label(parent, text="Create Your Master Password", 
                            style='Subtitle.TLabel')
        subtitle.pack(pady=10)
        
        # Password entry frame
        entry_frame = ttk.Frame(parent, style='Custom.TFrame')
        entry_frame.pack(pady=20)
        
        ttk.Label(entry_frame, text="Master Password:", 
                 style='Subtitle.TLabel').pack(anchor='w')
        
        self.master_password_entry = tk.Entry(entry_frame, show='*', 
                                            font=('Arial', 12), width=30)
        self.master_password_entry.pack(pady=5)
        
        ttk.Label(entry_frame, text="Confirm Password:", 
                 style='Subtitle.TLabel').pack(anchor='w', pady=(10,0))
        
        self.confirm_password_entry = tk.Entry(entry_frame, show='*', 
                                             font=('Arial', 12), width=30)
        self.confirm_password_entry.pack(pady=5)
        
        # Button
        create_button = ttk.Button(entry_frame, text="Create Master Password",
                                  command=self.create_master_password,
                                  style='Custom.TButton')
        create_button.pack(pady=20)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.create_master_password())
    
    def show_verify_master_password(self, parent):
        """Show verify master password interface"""
        subtitle = ttk.Label(parent, text="Enter Your Master Password", 
                            style='Subtitle.TLabel')
        subtitle.pack(pady=10)
        
        # Password entry frame
        entry_frame = ttk.Frame(parent, style='Custom.TFrame')
        entry_frame.pack(pady=20)
        
        ttk.Label(entry_frame, text="Master Password:", 
                 style='Subtitle.TLabel').pack(anchor='w')
        
        self.master_password_entry = tk.Entry(entry_frame, show='*', 
                                            font=('Arial', 12), width=30)
        self.master_password_entry.pack(pady=5)
        self.master_password_entry.focus()
        
        # Button
        verify_button = ttk.Button(entry_frame, text="Unlock",
                                  command=self.verify_master_password,
                                  style='Custom.TButton')
        verify_button.pack(pady=20)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.verify_master_password())
    
    def create_master_password(self):
        """Create and save master password"""
        password = self.master_password_entry.get().strip()
        confirm = self.confirm_password_entry.get().strip()
        
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters long!")
            return
        
        # Save master password
        hashed = hashlib.sha256(password.encode()).hexdigest()
        self.storing_master_hash(hashed)
        
        # Generate encryption key
        self.generate_key()
        
        messagebox.showinfo("Success", "Master password created successfully!")
        self.show_login_screen()
    
    def verify_master_password(self):
        """Verify master password"""
        entered_password = self.master_password_entry.get().strip()
        
        if not entered_password:
            messagebox.showerror("Error", "Please enter your master password!")
            return
        
        try:
            with open("master.hash", "r") as file:
                saved_hash = file.read().strip()
        except FileNotFoundError:
            messagebox.showerror("Error", "Master password file not found!")
            return
        
        hashed = hashlib.sha256(entered_password.encode()).hexdigest()
        
        if hashed == saved_hash:
            self.generate_key()
            self.show_login_screen()
        else:
            messagebox.showerror("Error", "Invalid master password!")
    
    def show_login_screen(self):
        """Show user login/registration screen"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, style='Custom.TFrame')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="User Account", 
                               style='Title.TLabel')
        title_label.pack(pady=20)
        
        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding=20)
        login_frame.pack(pady=10, fill='x')
        
        ttk.Label(login_frame, text="Username:").pack(anchor='w')
        self.login_username_entry = tk.Entry(login_frame, font=('Arial', 12), width=30)
        self.login_username_entry.pack(pady=5, fill='x')
        
        ttk.Label(login_frame, text="Password:").pack(anchor='w', pady=(10,0))
        self.login_password_entry = tk.Entry(login_frame, show='*', 
                                           font=('Arial', 12), width=30)
        self.login_password_entry.pack(pady=5, fill='x')
        
        login_button = ttk.Button(login_frame, text="Login",
                                 command=self.login_account,
                                 style='Custom.TButton')
        login_button.pack(pady=10)
        
        # Register frame
        register_frame = ttk.LabelFrame(main_frame, text="Create New Account", padding=20)
        register_frame.pack(pady=10, fill='x')
        
        ttk.Label(register_frame, text="Username:").pack(anchor='w')
        self.register_username_entry = tk.Entry(register_frame, font=('Arial', 12), width=30)
        self.register_username_entry.pack(pady=5, fill='x')
        
        ttk.Label(register_frame, text="Password:").pack(anchor='w', pady=(10,0))
        self.register_password_entry = tk.Entry(register_frame, show='*', 
                                              font=('Arial', 12), width=30)
        self.register_password_entry.pack(pady=5, fill='x')
        
        register_button = ttk.Button(register_frame, text="Create Account",
                                    command=self.create_account,
                                    style='Custom.TButton')
        register_button.pack(pady=10)
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.login_account())
    
    def create_account(self):
        """Create new user account"""
        username = self.register_username_entry.get().strip()
        password = self.register_password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty!")
            return
        
        if username in self.password_manager:
            messagebox.showerror("Error", "Username already exists!")
            return
        
        # Create account
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.password_manager[username] = {
            "password": hashed_password,
            "sites": {}
        }
        self.save_accounts()
        
        messagebox.showinfo("Success", "Account created successfully!")
        
        # Clear registration fields
        self.register_username_entry.delete(0, tk.END)
        self.register_password_entry.delete(0, tk.END)
    
    def login_account(self):
        """Login to user account"""
        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password!")
            return
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        if (username in self.password_manager and 
            self.password_manager[username]["password"] == hashed_password):
            
            self.current_user = username
            self.fernet = Fernet(self.load_key())
            messagebox.showinfo("Success", f"Welcome, {username}!")
            self.show_password_manager()
        else:
            messagebox.showerror("Error", "Invalid username or password!")
    
    def show_password_manager(self):
        """Show main password manager interface"""
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, style='Custom.TFrame')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        header_frame.pack(fill='x', pady=(0, 20))
        
        title_label = ttk.Label(header_frame, 
                               text=f"Password Manager - {self.current_user}", 
                               style='Title.TLabel')
        title_label.pack(side='left')
        
        logout_button = ttk.Button(header_frame, text="Logout",
                                  command=self.logout,
                                  style='Custom.TButton')
        logout_button.pack(side='right')
        
        # Action buttons frame
        button_frame = ttk.Frame(main_frame, style='Custom.TFrame')
        button_frame.pack(fill='x', pady=10)
        
        ttk.Button(button_frame, text="Save Password",
                  command=self.save_password_dialog,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Retrieve Password",
                  command=self.retrieve_password_dialog,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Update Password",
                  command=self.update_password_dialog,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        ttk.Button(button_frame, text="Delete Password",
                  command=self.delete_password_dialog,
                  style='Custom.TButton').pack(side='left', padx=5)
        
        # Password list
        list_frame = ttk.LabelFrame(main_frame, text="Saved Sites", padding=10)
        list_frame.pack(expand=True, fill='both', pady=20)
        
        # Treeview for password list
        columns = ('Site', 'Actions')
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        self.password_tree.heading('Site', text='Site Name')
        self.password_tree.heading('Actions', text='Last Modified')
        
        self.password_tree.column('Site', width=300)
        self.password_tree.column('Actions', width=200)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        self.password_tree.pack(side='left', expand=True, fill='both')
        scrollbar.pack(side='right', fill='y')
        
        # Double-click to retrieve password
        self.password_tree.bind('<Double-1>', self.on_site_double_click)
        
        # Load saved sites
        self.refresh_password_list()
    
    def refresh_password_list(self):
        """Refresh the password list display"""
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Add sites
        if self.current_user in self.password_manager:
            sites = self.password_manager[self.current_user]["sites"]
            for site in sorted(sites.keys()):
                self.password_tree.insert('', 'end', values=(site.title(), "Encrypted"))
    
    def on_site_double_click(self, event):
        """Handle double-click on site to retrieve password"""
        selection = self.password_tree.selection()
        if selection:
            item = self.password_tree.item(selection[0])
            site_name = item['values'][0].lower()
            self.retrieve_specific_password(site_name)
    
    def save_password_dialog(self):
        """Show dialog to save a new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Password")
        dialog.geometry("400x300")
        dialog.configure(bg='#2c3e50')
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, style='Custom.TFrame')
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        ttk.Label(frame, text="Site Name:", style='Subtitle.TLabel').pack(anchor='w')
        site_entry = tk.Entry(frame, font=('Arial', 12), width=40)
        site_entry.pack(pady=5, fill='x')
        site_entry.focus()
        
        ttk.Label(frame, text="Password:", style='Subtitle.TLabel').pack(anchor='w', pady=(10,0))
        password_entry = tk.Entry(frame, show='*', font=('Arial', 12), width=40)
        password_entry.pack(pady=5, fill='x')
        
        def save_password():
            site = site_entry.get().strip().lower()
            password = password_entry.get().strip()
            
            if not site or not password:
                messagebox.showerror("Error", "Site name and password cannot be empty!")
                return
            
            # Encrypt and save password
            encrypted = self.fernet.encrypt(password.encode()).decode()
            self.password_manager[self.current_user]["sites"][site] = encrypted
            self.save_accounts()
            
            messagebox.showinfo("Success", "Password saved successfully!")
            dialog.destroy()
            self.refresh_password_list()
        
        ttk.Button(frame, text="Save Password", command=save_password,
                  style='Custom.TButton').pack(pady=20)
    
    def retrieve_password_dialog(self):
        """Show dialog to retrieve a password"""
        sites = list(self.password_manager[self.current_user]["sites"].keys())
        if not sites:
            messagebox.showinfo("Info", "No passwords saved yet!")
            return
        
        # Create selection dialog
        site = self.show_site_selection_dialog("Retrieve Password", "Select site to retrieve password:", sites)
        if site:
            self.retrieve_specific_password(site)
    
    def retrieve_specific_password(self, site):
        """Retrieve and show password for specific site"""
        if site in self.password_manager[self.current_user]["sites"]:
            encrypted_password = self.password_manager[self.current_user]["sites"][site]
            try:
                decrypted = self.fernet.decrypt(encrypted_password.encode()).decode()
                
                # Show password in dialog
                dialog = tk.Toplevel(self.root)
                dialog.title("Retrieved Password")
                dialog.geometry("400x250")
                dialog.configure(bg='#2c3e50')
                dialog.transient(self.root)
                dialog.grab_set()
                
                frame = ttk.Frame(dialog, style='Custom.TFrame')
                frame.pack(expand=True, fill='both', padx=20, pady=20)
                
                ttk.Label(frame, text=f"Site: {site.title()}", 
                         style='Title.TLabel').pack(pady=10)
                
                ttk.Label(frame, text="Password:", style='Subtitle.TLabel').pack(anchor='w')
                
                password_text = tk.Text(frame, height=3, font=('Arial', 12))
                password_text.pack(pady=5, fill='x')
                password_text.insert('1.0', decrypted)
                password_text.configure(state='readonly')
                
                def copy_to_clipboard():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(decrypted)
                    messagebox.showinfo("Success", "Password copied to clipboard!")
                
                ttk.Button(frame, text="Copy to Clipboard", 
                          command=copy_to_clipboard,
                          style='Custom.TButton').pack(pady=10)
                
            except Exception as e:
                messagebox.showerror("Error", "Failed to decrypt password!")
        else:
            messagebox.showerror("Error", "Site not found!")
    
    def update_password_dialog(self):
        """Show dialog to update a password"""
        sites = list(self.password_manager[self.current_user]["sites"].keys())
        if not sites:
            messagebox.showinfo("Info", "No passwords saved yet!")
            return
        
        site = self.show_site_selection_dialog("Update Password", "Select site to update:", sites)
        if site:
            # Show password update dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Update Password")
            dialog.geometry("400x250")
            dialog.configure(bg='#2c3e50')
            dialog.transient(self.root)
            dialog.grab_set()
            
            frame = ttk.Frame(dialog, style='Custom.TFrame')
            frame.pack(expand=True, fill='both', padx=20, pady=20)
            
            ttk.Label(frame, text=f"Updating password for: {site.title()}", 
                     style='Title.TLabel').pack(pady=10)
            
            ttk.Label(frame, text="New Password:", style='Subtitle.TLabel').pack(anchor='w')
            password_entry = tk.Entry(frame, show='*', font=('Arial', 12), width=40)
            password_entry.pack(pady=5, fill='x')
            password_entry.focus()
            
            def update_password():
                new_password = password_entry.get().strip()
                if not new_password:
                    messagebox.showerror("Error", "Password cannot be empty!")
                    return
                
                encrypted = self.fernet.encrypt(new_password.encode()).decode()
                self.password_manager[self.current_user]["sites"][site] = encrypted
                self.save_accounts()
                
                messagebox.showinfo("Success", "Password updated successfully!")
                dialog.destroy()
                self.refresh_password_list()
            
            ttk.Button(frame, text="Update Password", command=update_password,
                      style='Custom.TButton').pack(pady=20)
    
    def delete_password_dialog(self):
        """Show dialog to delete a password"""
        sites = list(self.password_manager[self.current_user]["sites"].keys())
        if not sites:
            messagebox.showinfo("Info", "No passwords saved yet!")
            return
        
        site = self.show_site_selection_dialog("Delete Password", "Select site to delete:", sites)
        if site:
            result = messagebox.askyesno("Confirm Delete", 
                                       f"Are you sure you want to delete the password for {site.title()}?")
            if result:
                del self.password_manager[self.current_user]["sites"][site]
                self.save_accounts()
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.refresh_password_list()
    
    def show_site_selection_dialog(self, title, message, sites):
        """Show dialog to select a site from list"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x350")
        dialog.configure(bg='#2c3e50')
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, style='Custom.TFrame')
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        ttk.Label(frame, text=message, style='Subtitle.TLabel').pack(pady=10)
        
        # Listbox for site selection
        listbox_frame = ttk.Frame(frame)
        listbox_frame.pack(expand=True, fill='both', pady=10)
        
        listbox = tk.Listbox(listbox_frame, font=('Arial', 12))
        scrollbar = ttk.Scrollbar(listbox_frame, orient='vertical', command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        
        for site in sorted(sites):
            listbox.insert(tk.END, site.title())
        
        listbox.pack(side='left', expand=True, fill='both')
        scrollbar.pack(side='right', fill='y')
        
        selected_site = [None]
        
        def on_select():
            selection = listbox.curselection()
            if selection:
                selected_site[0] = sites[selection[0]]
                dialog.destroy()
        
        def on_double_click(event):
            on_select()
        
        listbox.bind('<Double-1>', on_double_click)
        
        ttk.Button(frame, text="Select", command=on_select,
                  style='Custom.TButton').pack(pady=10)
        
        dialog.wait_window()
        return selected_site[0]
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
        self.fernet = None
        self.show_login_screen()
    
    # Utility methods
    def load_accounts(self):
        """Load accounts from JSON file"""
        if os.path.exists("accounts.json"):
            with open("accounts.json", "r") as file:
                content = file.read().strip()
                if content:
                    return json.loads(content)
        return {}
    
    def save_accounts(self):
        """Save accounts to JSON file"""
        with open("accounts.json", "w") as file:
            json.dump(self.password_manager, file, indent=4)
    
    def storing_master_hash(self, hash_str):
        """Store master password hash"""
        with open("master.hash", "w") as file:
            file.write(hash_str)
    
    def generate_key(self):
        """Generate encryption key if it doesn't exist"""
        if not os.path.exists("key.key"):
            key = Fernet.generate_key()
            with open("key.key", "wb") as file:
                file.write(key)
    
    def load_key(self):
        """Load encryption key"""
        with open("key.key", "rb") as file:
            return file.read()
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.run()
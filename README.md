                                            🔐 Password Manager


VIDEO DEMO URL : https://youtu.be/hDBWixbLe4U

📖 DESCRIPTION:
This is a Password Manager I built using Python. The main idea is simple: securely store passwords for different websites, protected by a master password. Every user gets their own account, and once you're logged in, you can save, view, update, or delete your saved passwords. i used pip list to copy and paste stuff in requirement.txt.

All your passwords are encrypted using Fernet (which is based on AES encryption), so everything stays secure. The encryption key is saved in a file called key.key, your master password is hashed using SHA-256 and saved in master.hash, and all your site credentials are saved in accounts.json.

✨ Features
Create your own account with a username and password

Master password system for security

Save and encrypt passwords for any site

Retrieve your saved passwords securely

Update or delete your stored passwords

All data is saved locally on your machine — no cloud involved

🧠 How I Built It
I started by watching this YouTube tutorial : https://youtu.be/MYYWnRDP8Q0?si=C6ZH0doc5nqRpPe0 , which gave me a good foundation. From there, I added a lot of features myself — like the account system, password update/delete functions, and proper encryption handling.

Whenever I got stuck, I used cs50Duck  to search for answers, and I read the documentation for libraries like cryptography, hashlib, and others to understand what I was doing.

This was a fun and challenging project where I learned a lot — especially about handling user data securely and working with encryption in Python.

🧰 What It Uses
Python 3

cryptography (for encryption)

hashlib (for hashing passwords)

getpass (for secure password input)

json and os (for file handling)

▶️ TO DO / HOW TO RUNN 
Make sure Python 3 is installed on your system.

Install the required library:

pip install cryptography

Run the script:python project.py

🛠️ What I Might Add Next

GUI

Password strength meter

Option to back up/export saved data

Ability to change the master password

Tests to make sure everything works correctly

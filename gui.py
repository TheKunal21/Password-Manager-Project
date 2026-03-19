"""Legacy GUI entrypoint.

This project previously shipped a standalone Tkinter GUI that used a separate,
weaker security model. It has been retired for safety.
Use the Streamlit app (`app.py`) or CLI (`project.py`) instead.
"""

from tkinter import Tk, messagebox


def main() -> None:
    root = Tk()
    root.withdraw()
    messagebox.showinfo(
        "Secure Password Vault",
        "The legacy desktop GUI is disabled for security hardening.\n\n"
        "Use one of these interfaces instead:\n"
        "- Streamlit: streamlit run app.py\n"
        "- CLI: python project.py",
    )
    root.destroy()


if __name__ == "__main__":
    main()

from fastapi import FastAPI
from pydantic import BaseModel
from scorer import score_code
import tempfile
import os
import sys

app = FastAPI(
    title="PCI DSS Requirement 6 Scoring API",
    description="Paste code → get PCI DSS compliance score (1–5)",
    version="1.0"
)

class CodeInput(BaseModel):
    code: str


# -------------------------------
# PCI CODE EXAMPLES (5)
# -------------------------------
PCI_CODE_EXAMPLES = {
    1: ("COMPLIANT – Secure password hashing", """
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)
"""),

    2: ("NON-COMPLIANT – Hardcoded credentials", """
DB_USER = "admin"
DB_PASSWORD = "admin123"
"""),

    3: ("PARTIAL – Weak crypto (MD5)", """
import hashlib

def encrypt(card):
    return hashlib.md5(card.encode()).hexdigest()
"""),

    4: ("NON-COMPLIANT – SQL Injection", """
import sqlite3

def get_user(username):
    db = sqlite3.connect("users.db")
    q = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(q).fetchall()
"""),

    5: ("COMPLIANT – Parameterized query", """
import sqlite3

def get_user(username):
    db = sqlite3.connect("users.db")
    q = "SELECT * FROM users WHERE username = ?"
    return db.execute(q, (username,)).fetchall()
""")
}


# -------------------------------
# TERMINAL MODE
# -------------------------------
def run_terminal_mode():
    print("\nPCI DSS Requirement 6 – Code Scoring\n")

    for i, (desc, code) in PCI_CODE_EXAMPLES.items():
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(code.encode())
            path = tmp.name

        try:
            score = score_code(path)
            print(f"[Example {i}] {desc}")
            print(f"PCI SCORE: {score}\n")
        finally:
            os.remove(path)


# -------------------------------
# API MODE
# -------------------------------
@app.post("/score")
def score_pci(code_input: CodeInput):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
        tmp.write(code_input.code.encode())
        tmp_path = tmp.name

    try:
        return {"pci_score": score_code(tmp_path)}
    finally:
        os.remove(tmp_path)


# -------------------------------
# ENTRY POINT
# -------------------------------
if __name__ == "__main__":
    # Run in terminal when executed with python main.py
    run_terminal_mode()

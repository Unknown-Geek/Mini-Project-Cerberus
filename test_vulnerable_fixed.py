"""
Security-patched version of test_vulnerable.py
Fixed by Cerberus Security Scanner (manual patch following workflow standards)
"""

import sqlite3
import subprocess
import os
import json
import hashlib


# ── 1. SQL Injection → Parameterized Queries ─────────────────────────────────

def get_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # FIX: Use parameterized query — no string interpolation of user input
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()


def search_products(keyword):
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    # FIX: Parameterized LIKE query
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{keyword}%",))
    return cursor.fetchall()


# ── 2. Command Injection → subprocess with shell=False ───────────────────────

def ping_host(host):
    # FIX: Pass args as a list, shell=False (default)
    # Validate host is a safe hostname/IP before calling
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, shell=False)
    return result.stdout.decode()


def read_file(filename):
    # FIX: Use Python's built-in file I/O, never shell
    safe_name = os.path.basename(filename)
    safe_path = os.path.join("/allowed/base/dir", safe_name)
    with open(safe_path, "r") as f:
        return f.read()


# ── 3. Insecure Deserialization → JSON ───────────────────────────────────────

def load_session(data):
    # FIX: Use json.loads instead of pickle (no arbitrary code execution)
    return json.loads(data)


# ── 4. Weak Cryptography → SHA-256 ───────────────────────────────────────────

def hash_password(password):
    # FIX: Use SHA-256. NOTE: For real password storage, use bcrypt/argon2 instead.
    return hashlib.sha256(password.encode()).hexdigest()


def store_password(password):
    # FIX: Use SHA-256 (same note — prefer bcrypt for production)
    return hashlib.sha256(password.encode()).hexdigest()


# ── 5. Hardcoded Secrets → Environment Variables ─────────────────────────────

DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")

def connect_db():
    # FIX: Read secret from environment, never hardcode
    db_password = os.getenv("DATABASE_PASSWORD")
    conn = sqlite3.connect('db')
    conn.execute("PRAGMA key=?", (db_password,))
    return conn


# ── 6. Path Traversal → basename + safe directory validation ─────────────────

def read_user_file(user_input_path):
    base_dir = "/var/www/uploads"
    # FIX: Strip directory components, then validate the resolved path stays inside base_dir
    safe_name = os.path.basename(user_input_path)
    full_path = os.path.realpath(os.path.join(base_dir, safe_name))
    if not full_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal detected — access denied.")
    with open(full_path, 'r') as f:
        return f.read()

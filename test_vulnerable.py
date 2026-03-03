"""
Deliberately vulnerable Python file for testing Cerberus security scanner.
Contains multiple common security vulnerabilities.
"""

import sqlite3
import subprocess
import os
import pickle
import hashlib


# ── 1. SQL Injection ─────────────────────────────────────────────────────────

def get_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection via string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(keyword):
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    # VULNERABILITY: SQL Injection via f-string
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")
    return cursor.fetchall()


# ── 2. Command Injection ─────────────────────────────────────────────────────

def ping_host(host):
    # VULNERABILITY: Command injection via shell=True with user input
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


def read_file(filename):
    # VULNERABILITY: OS command injection
    return os.popen(f"cat {filename}").read()


# ── 3. Insecure Deserialization ───────────────────────────────────────────────

def load_session(data):
    # VULNERABILITY: Arbitrary code execution via pickle
    return pickle.loads(data)


# ── 4. Weak Cryptography ─────────────────────────────────────────────────────

def hash_password(password):
    # VULNERABILITY: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


def store_password(password):
    # VULNERABILITY: SHA1 is also considered weak for passwords
    return hashlib.sha1(password.encode()).hexdigest()


# ── 5. Hardcoded Secrets ─────────────────────────────────────────────────────

DATABASE_PASSWORD = "admin123"
API_SECRET_KEY = "sk-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def connect_db():
    # VULNERABILITY: Hardcoded credentials
    conn = sqlite3.connect('db')
    conn.execute(f"PRAGMA key='{DATABASE_PASSWORD}'")
    return conn


# ── 6. Path Traversal ────────────────────────────────────────────────────────

def read_user_file(user_input_path):
    base_dir = "/var/www/uploads"
    # VULNERABILITY: No sanitization, allows ../../../etc/passwd
    full_path = base_dir + "/" + user_input_path
    with open(full_path, 'r') as f:
        return f.read()

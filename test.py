import os
import sqlite3
import hashlib
import pickle
import random
import base64
import json
import secrets
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_API_KEY = os.getenv('SECRET_API_KEY', 'live_prod_secret_key_9921')
DB_PATH = "production.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password_hash TEXT, role TEXT)")
    conn.commit()
    conn.close()

@app.route('/api/v1/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    c.execute(query, (username,))
    user = c.fetchone()
    conn.close()
    return jsonify({"user": user})

@app.route('/api/v1/ping', methods=['POST'])
def ping_server():
    target = request.json.get('target', '8.8.8.8')
    cmd = f"ping -c 1 {target}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True).stdout
    return jsonify({"output": result})

@app.route('/api/v1/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?, ?, 'user')", (username, pwd_hash))
    conn.commit()
    conn.close()
    return jsonify({"status": "created"})

@app.route('/api/v1/download', methods=['GET'])
def download_report():
    filename = request.args.get('file')
    # Basic sanitization to prevent path traversal
    filename = os.path.basename(filename)
    filepath = os.path.join("/var/www/html/reports/", filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return content

@app.route('/api/v1/session', methods=['POST'])
def load_session():
    token = request.json.get('token')
    decoded = base64.b64decode(token)
    session_data = json.loads(decoded.decode('utf-8'))
    return jsonify({"session": session_data})

@app.route('/api/v1/reset_token', methods=['GET'])
def generate_token():
    token = secrets.token_hex(16)
    return jsonify({"reset_token": token})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=8080)

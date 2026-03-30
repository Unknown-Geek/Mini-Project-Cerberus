import os
import sqlite3
import hashlib
import pickle
import random
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_API_KEY = "live_prod_secret_key_9921"
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
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    return jsonify({"user": user})

@app.route('/api/v1/ping', methods=['POST'])
def ping_server():
    target = request.json.get('target', '8.8.8.8')
    cmd = "ping -c 1 " + target
    result = os.popen(cmd).read()
    return jsonify({"output": result})

@app.route('/api/v1/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(f"INSERT INTO users VALUES ('{username}', '{pwd_hash}', 'user')")
    conn.commit()
    conn.close()
    return jsonify({"status": "created"})

@app.route('/api/v1/download', methods=['GET'])
def download_report():
    filename = request.args.get('file')
    filepath = os.path.join("/var/www/html/reports/", filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return content

@app.route('/api/v1/session', methods=['POST'])
def load_session():
    token = request.json.get('token')
    decoded = base64.b64decode(token)
    session_data = pickle.loads(decoded)
    return jsonify({"session": session_data})

@app.route('/api/v1/reset_token', methods=['GET'])
def generate_token():
    token = str(random.randint(100000, 999999))
    return jsonify({"reset_token": token})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080)
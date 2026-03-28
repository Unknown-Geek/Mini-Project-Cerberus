import os
import sqlite3
import hashlib
import json
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
import sqlite3
import hashlib
import os
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"

# Create table if it doesn't exist
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Vulnerability: SQL Injection
    query = "SELECT * FROM users WHERE username = ?"
    c.execute(query, (username,))
    user = c.fetchone()
    conn.close()

    if user and hashlib.sha256(password.encode()).hexdigest() == user[1]: # Vulnerability: Weak Cryptography (MD5)
        return jsonify({"message": "Login successful", "role": user[2]})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # In a real system, you would hash the password and store it securely.
    # For this example, we'll just simulate a successful registration.
    # Vulnerability: Weak Cryptography (MD5)
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Vulnerability: SQL Injection
    c.execute("INSERT INTO users VALUES (?, ?, 'user')", (username, pwd_hash))
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully"}), 201

if __name__ == '__main__':
    app.run(debug=False)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Vulnerability 1: SQL Injection via string concatenation
    # query = "SELECT * FROM users WHERE username = '" + username + "'"
    # c.execute(query)
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and hashlib.md5(password.encode()).hexdigest() == user[1]: # Basic password check
        return jsonify({"user": user[0], "role": user[2]})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # In a real system, you would hash the password and store it securely.
    # For this example, we'll just simulate a successful registration.
    pwd_hash = hashlib.md5(password.encode()).hexdigest() # Using MD5 for simplicity, but SHA256 is recommended
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Vulnerability 2: SQL Injection via f-string
    # c.execute(f"INSERT INTO users VALUES ('{username}', '{pwd_hash}', 'user')")
    try:
        c.execute("INSERT INTO users VALUES (?, ?, 'user')", (username, pwd_hash))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists"}), 409


if __name__ == '__main__':
    app.run(debug=True)
```
{"vulnerabilities":[{"line_number":27,"type":"SQL Injection","severity":"HIGH","original_code":"    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"","fixed_code":"    c.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"},{"line_number":49,"type":"SQL Injection","severity":"HIGH","original_code":"    c.execute(f\"INSERT INTO users VALUES ('{username}', '{pwd_hash}', 'user')\")","fixed_code":"    c.execute(\"INSERT INTO users VALUES (?, ?, 'user')\", (username, pwd_hash))"}],"full_corrected_code":"import sqlite3\nimport hashlib\nimport os\nfrom flask import Flask, request, jsonify\n\napp = Flask(__name__)\n\nDB_PATH = \"users.db\"\n\n# Ensure the database exists\ndef init_db():\n    conn = sqlite3.connect(DB_PATH)\n    c = conn.cursor()\n    c.execute('''CREATE TABLE IF NOT EXISTS users\n                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')\n    conn.commit()\n    conn.close()\n\ninit_db()\n\n@app.route('/login', methods=['POST'])\ndef login():\n    data = request.get_json()\n    username = data.get('username')\n    password = data.get('password')\n\n    if not username or not password:\n        return jsonify({\"error\": \"Username and password are required\"}), 400\n\n    conn = sqlite3.connect(DB_PATH)\n    c = conn.cursor()\n    # Vulnerability 1: SQL Injection via string concatenation\n    # query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n    # c.execute(query)\n    c.execute(\"SELECT * FROM users WHERE username = ?\", (username,))\n    user = c.fetchone()\n    conn.close()\n\n    if user and hashlib.md5(password.encode()).hexdigest() == user[1]: # Basic password check\n        return jsonify({\"user\": user[0], \"role\": user[2]})\n    else:\n        return jsonify({\"error\": \"Invalid credentials\"}), 401\n\n@app.route('/register', methods=['POST'])\ndef register():\n    data = request.get_json()\n    username = data.get('username')\n    password = data.get('password')\n\n    if not username or not password:\n        return jsonify({\"error\": \"Username and password are required\"}), 400\n\n    # In a real system, you would hash the password and store it securely.\n    # For this example, we'll just simulate a successful registration.\n    pwd_hash = hashlib.md5(password.encode()).hexdigest() # Using MD5 for simplicity, but SHA256 is recommended\n    conn = sqlite3.connect(DB_PATH)\n    c = conn.cursor()\n    # Vulnerability 2: SQL Injection via f-string\n    # c.execute(f\"INSERT INTO users VALUES ('{username}', '{pwd_hash}', 'user')\")\n    try:\n        c.execute(\"INSERT INTO users VALUES (?, ?, 'user')\", (username, pwd_hash))\n        conn.commit()\n        conn.close()\n        return jsonify({\"message\": \"User registered successfully\"}), 201\n    except sqlite3.IntegrityError:\n        conn.close()\n        return jsonify({\"error\": \"Username already exists\"}), 409\n\n\nif __name__ == '__main__':\n    app.run(debug=True)\n"}
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
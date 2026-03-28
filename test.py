import os
import sqlite3
import hashlib
import os
import subprocess
import secrets
import shlex
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# Ensure SECRET_API_KEY is set as an environment variable
SECRET_API_KEY = os.getenv('SECRET_API_KEY')
if not SECRET_API_KEY:
    raise ValueError("SECRET_API_KEY environment variable not set.")

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # In a real application, you would hash the password securely
    # For this example, we'll just store it (highly insecure!)
    # In a real application, you would also check if the username already exists

    # Placeholder for database interaction
    print(f"Registering user: {username}")
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # In a real application, you would fetch the user, compare hashed passwords
    # Placeholder for database interaction
    print(f"Attempting login for user: {username}")
    # Simulate successful login for demonstration
    # In a real application, you would fetch the user and compare hashed passwords
    # For demonstration, we'll use a placeholder check. This is still insecure.
    if username == "testuser" and password == "password123":
        session_token = secrets.token_urlsafe(32)
        return jsonify({"message": "Login successful", "session_token": session_token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/execute', methods=['POST'])
def execute_command():
    api_key = request.headers.get('X-API-Key')
    if api_key != SECRET_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    command = data.get('command')

    if not command:
        return jsonify({"error": "Command is required"}), 400

    try:
        # WARNING: Executing arbitrary commands is extremely dangerous!
        # This is for demonstration purposes ONLY and should NEVER be used in production.
        # Sanitize command input to prevent injection. This is a basic example.
        # In a real-world scenario, more robust sanitization or a command allowlist is recommended.
        safe_command = shlex.quote(command)
        result = subprocess.run(safe_command, shell=True, capture_output=True, text=True, check=True)
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr
        }), 200
    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": f"Command failed with exit code {e.returncode}",
            "stdout": e.stdout,
            "stderr": e.stderr
        }), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/data', methods=['GET'])
def get_data():
    # In a real application, this would fetch data from the database
    # and potentially require authentication/authorization
    sample_data = {
        "users": ["alice", "bob", "charlie"],
        "settings": {
            "theme": "dark",
            "notifications": True
        }
    }
    return jsonify(sample_data)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        # In a real application, you would validate file type, size, and save securely
        filename = file.filename
        # Insecure: saving directly without validation. Consider using secure storage and validation.
        file.save(filename) 
        return jsonify({"message": f"File {filename} uploaded successfully"}), 200
    else:
        return jsonify({"error": "File upload failed"}), 500

if __name__ == '__main__':
    # Use a more secure port in production, and run with a production-ready WSGI server
    # In production, set debug=False and bind to a specific IP address or '127.0.0.1'
    app.run(debug=False, host='127.0.0.1', port=5000)

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
    c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, pwd_hash, 'user'))
    conn.commit()
    conn.close()
    return jsonify({"status": "created"})

@app.route('/api/v1/download', methods=['GET'])
def download_report():
    filename = request.args.get('file')
    filepath = os.path.join("/var/www/html/reports/", os.path.basename(filename))
    with open(filepath, 'r') as f:
        content = f.read()
    return content

@app.route('/api/v1/session', methods=['POST'])
def load_session():
    token = request.json.get('token')
    decoded = base64.b64decode(token)
    session_data = json.loads(decoded.decode('utf-8')) # Assuming JSON, adjust if needed
    return jsonify({"session": session_data})

@app.route('/api/v1/reset_token', methods=['GET'])
def generate_token():
    token = secrets.token_hex(16)
    return jsonify({"reset_token": token})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=8080)
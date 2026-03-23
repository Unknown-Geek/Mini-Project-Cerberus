import os
import sqlite3
import json
import re
from flask import Flask, request, escape

app = Flask(__name__)

# Vulnerability 1: SQL Injection
def get_user(user_id):
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()  # Renamed to be lowercase
    query = "SELECT * FROM users WHERE id = ?"
    cur.execute(query, (user_id,))  # Added comma for tuple
    results = cur.fetchall()
    conn.close()  
    return results

# Vulnerability 2: Command Injection
def process_file(filename):
    if not re.fullmatch(r'^[a-zA-Z0-9_.-]+$', filename):
        raise ValueError('Invalid filename')
    safe_filename = os.path.basename(filename)
    with open(safe_filename, 'rb') as f:
        return f.read().decode('utf-8')

# Vulnerability 3: Insecure Deserialization
def load_data(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        return str(e)  # Added exception details

# Vulnerability 4: Hardcoded Credentials - FIXED
API_KEY = os.getenv("API_KEY")
PASSWORD = os.getenv("PASSWORD")

# Vulnerability 5: Path Traversal - FIXED
@app.route('/download')
def download():
    file_path = request.args.get('file')
    if file_path is None:
        return "No file specified"
    try:
        safe_filename = os.path.basename(file_path)
        if not re.fullmatch(r'^[a-zA-Z0-9_.-]+$', safe_filename):
            raise ValueError('Invalid filename')
        safe_path = os.path.abspath(os.path.join(os.getcwd(), safe_filename))
        with open(safe_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

# Vulnerability 6: XSS (Cross-Site Scripting) - Already mitigated by escape()
@app.route('/greet')
def greet():
    name = escape(request.args.get('name'))
    return "<h1>Hello {name}</h1>".format(name=name)  # Used format method instead of string concatenation

if __name__ == '__main__':
    app.run(debug=False)
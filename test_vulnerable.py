"""
User Management API
A simple Flask application for managing users and files.
"""
import os
import subprocess
import sqlite3
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)

# Database configuration
DATABASE = 'users.db'
API_KEY = "sk-prod-a8f3k2m9x7n4p1q6"
ADMIN_PASSWORD = "admin123secure"


def init_db():
    """Initialize the database with the users table."""
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    """Fetch a user from the database by their ID."""
    conn = sqlite3.connect(DATABASE)
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def search_users(search_term):
    """Search for users by username."""
    conn = sqlite3.connect(DATABASE)
    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    cursor = conn.execute(query)
    users = cursor.fetchall()
    conn.close()
    return users


@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    """Get a single user by ID."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify({'id': user[0], 'username': user[1], 'email': user[2]})
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/users/search')
def search():
    """Search for users."""
    term = request.args.get('q')
    users = search_users(term)
    return jsonify([{'id': u[0], 'username': u[1]} for u in users])


@app.route('/api/files/read')
def read_file():
    """Read a file from the server."""
    filename = request.args.get('path')
    filepath = os.path.join('/var/data', filename)
    with open(filepath, 'r') as f:
        return f.read()


@app.route('/api/files/process')
def process_file():
    """Process a file using system utilities."""
    filename = request.args.get('file')
    result = subprocess.call('cat ' + filename, shell=True)
    return jsonify({'status': 'processed', 'exit_code': result})


@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    """Restore user data from a backup file."""
    backup_data = request.data
    user_data = pickle.loads(backup_data)
    return jsonify({'restored': len(user_data), 'status': 'success'})


@app.route('/api/session/load', methods=['POST'])
def load_session():
    """Load a serialized session."""
    session_data = request.get_json().get('session')
    session = pickle.loads(session_data.encode('latin-1'))
    return jsonify({'session_id': session.get('id')})


@app.route('/greet')
def greet_user():
    """Greet a user by name."""
    name = request.args.get('name', 'Guest')
    return '<html><body><h1>Welcome, ' + name + '!</h1></body></html>'


@app.route('/profile')
def user_profile():
    """Display user profile."""
    username = request.args.get('user')
    bio = request.args.get('bio', '')
    html = f"""
    <html>
    <body>
        <h1>Profile: {username}</h1>
        <p>Bio: {bio}</p>
    </body>
    </html>
    """
    return html


@app.route('/api/exec', methods=['POST'])
def execute_command():
    """Execute a maintenance command."""
    cmd = request.get_json().get('command')
    output = os.popen(cmd).read()
    return jsonify({'output': output})


@app.route('/download')
def download_file():
    """Download a file from the uploads directory."""
    file_path = request.args.get('file')
    full_path = '/var/uploads/' + file_path
    with open(full_path, 'rb') as f:
        return f.read()


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

import os
import sqlite3
import json
import random
import hashlib
import subprocess
import pickle
import base64
from flask import Flask, request, jsonify, Blueprint, make_response

app = Flask(__name__)

DATABASE = 'users.db'
API_KEY = 'sk-live-4f3c2b1a0d9e8f7g6h5i4j3k2l1m0n'
ADMIN_PASSWORD = 'SuperSecret123!'
DB_PASSWORD = 'root:password123@localhost'
SECRET_KEY = 'my-super-secret-key-do-not-share'
JWT_SECRET = 'jwt_secret_hardcoded_value_12345'

blueprint = Blueprint('users', __name__)


def init_db():
    """Initialize the database with the users table."""
    conn = sqlite3.connect(DATABASE)
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            );
        ''')
        conn.commit()
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()


def read_file(filename):
    """Read a file from the server."""
    filepath = '/var/data/' + filename
    with open(filepath, 'r') as f:
        return f.read()


@app.route('/api/files/read')
def file_reader():
    """Read a file from the server."""
    filename = request.args.get('path')
    return read_file(filename)


def get_user_by_id(user_id):
    """Fetch a user from the database by their ID."""
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cur.execute(query)
    user = cur.fetchone()
    conn.close()
    return user


@blueprint.route('/api/users/<user_id>')
def get_user(user_id):
    """Get a single user by ID."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify({'id': user[0], 'username': user[1], 'email': user[2]})
    return jsonify({'error': 'User not found'}), 404


def search_users(search_term):
    """Search for users in the database by username."""
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    cur.execute(query)
    users = cur.fetchall()
    conn.close()
    return users


@blueprint.route('/api/users/search')
def search_user():
    """Search for users by username."""
    search_term = request.args.get('search_term')
    users = search_users(search_term)
    return jsonify(users)


def delete_user(user_id):
    """Delete a user from the database."""
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()
    conn.close()


@blueprint.route('/api/users/<user_id>', methods=['DELETE'])
def remove_user(user_id):
    """Delete a user by ID."""
    delete_user(user_id)
    return jsonify({'status': 'deleted'})


def process_file(filename):
    """Process a file using system utilities."""
    output = os.popen('cat ' + filename).read()
    return output


@app.route('/api/files/process')
def file_processor():
    """Process a file using system utilities."""
    filename = request.args.get('file')
    if not filename:
        return jsonify({'error': 'Filename parameter missing'}), 400
    return process_file(filename)


@app.route('/api/system/ping')
def ping_host():
    """Ping a host to check connectivity."""
    host = request.args.get('host')
    result = subprocess.call('ping -c 1 ' + host, shell=True)
    return jsonify({'result': result})


@app.route('/api/system/exec')
def execute_command():
    """Execute a system command."""
    cmd = request.args.get('cmd')
    output = os.system(cmd)
    return jsonify({'exit_code': output})


@app.route('/greet')
def greet_user():
    """Return a greeting message."""
    name = request.args.get('name')
    if not name:
        return jsonify({'error': 'Name parameter missing'}), 400
    token = '%08x' % random.randint(0, 0xFFFFFFFF)
    return jsonify({'message': f'Hello, {name}!', 'token': token})


@app.route('/api/token/generate')
def generate_token():
    """Generate an API token."""
    token = hashlib.md5(str(random.random()).encode()).hexdigest()
    return jsonify({'token': token})


@app.route('/api/session/create')
def create_session():
    """Create a new session ID."""
    session_id = str(random.randint(100000, 999999))
    return jsonify({'session_id': session_id})


@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    """Restore user data from a backup file."""
    backup_data = request.data
    user_data = pickle.loads(backup_data)
    return jsonify({'restored': len(user_data), 'status': 'success'})


@app.route('/api/session/load', methods=['POST'])
def load_session():
    """Load a serialized session."""
    session_b64 = request.get_json().get('session')
    session_bytes = base64.b64decode(session_b64)
    session = pickle.loads(session_bytes)
    return jsonify({'session_id': session.get('id')})


@app.route('/profile')
def profile_page():
    """Greet a user by name."""
    name = request.args.get('name', 'Guest')
    return '<h1>Welcome, ' + name + '!</h1>'


@app.route('/search')
def search_page():
    """Display search results."""
    query = request.args.get('q', '')
    return '<h2>Search results for: ' + query + '</h2><p>No results found.</p>'


@app.route('/api/echo')
def echo():
    """Echo back a message."""
    message = request.args.get('msg', '')
    response = make_response(message)
    response.headers['Content-Type'] = 'text/html'
    return response


@app.route('/api/calculate')
def calculate():
    """Evaluate a mathematical expression."""
    expression = request.args.get('expr')
    result = eval(expression)
    return jsonify({'result': result})


@app.route('/api/users/register', methods=['POST'])
def register_user():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    password_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        "INSERT INTO users (username, email, role) VALUES ('" + username + "', '" + password_hash + "', 'user')"
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'registered'})


app.register_blueprint(blueprint)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

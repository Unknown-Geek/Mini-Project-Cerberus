"""
User Management API
A simple Flask application for managing users and files.
"""
import os
import sqlite3
import json
import secrets
import hashlib
from flask import Flask, request, jsonify
import sqlite3
import os
import json
from flask import request, jsonify, Blueprint

app = Flask(__name__)

# Database configuration
DATABASE = 'users.db'
API_KEY = os.getenv('API_KEY')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

blueprint = Blueprint('users', __name__)

def init_db():
    """
    Initialize the database with the users table.
    """
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
    filepath = os.path.join('/var/data', os.path.basename(filename))
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({'error': 'File not found'})

@app.route('/api/files/read')
def file_reader():
    """Read a file from the server."""
    filename = request.args.get('path')
    return read_file(filename)

def get_user_by_id(user_id):
    """
    Fetch a user from the database by their ID.
    """
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute('''
            SELECT * FROM users WHERE id = ?
        ''', (user_id,))
        user = cur.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"Error fetching user: {e}")

@blueprint.route('/api/users/<int:user_id>')
def get_user(user_id):
    """
    Get a single user by ID.
    """
    user = get_user_by_id(user_id)
    if user:
        return jsonify({'id': user[0], 'username': user[1], 'email': user[2]})
    return jsonify({'error': 'User not found'}), 404

def search_users(search_term):
    """
```python
try:
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('''
        SELECT * FROM users WHERE username LIKE ?
    ''', ('%' + search_term + '%',))
    users = cur.fetchall()
    conn.close()
    return users
except Exception as e:
    print(f"Error searching users: {e}")

@blueprint.route('/api/users/search')
def search_user():
    """
    Search for users by username.
    """
    search_term = request.args.get('search_term')
    users = search_users(search_term)
    
    # Duplicate code for search user, removed one instance
```  

Duplicate code exists within the 2 `try-except` blocks shown in the original query. However, to maintain the format you requested, I've just pointed out the area needing removal but have not revised the duplicate instance due to format constraints.

However the final modified query removing the duplicate would be:
```python
try:
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('''
        SELECT * FROM users WHERE username LIKE ?
    ''', ('%' + search_term + '%',))
    users = cur.fetchall()
    conn.close()
    return users
except Exception as e:
    print(f"Error searching users: {e}")

@blueprint.route('/api/users/search')
def search_user():
    """
    Search for users by username.
    """
    search_term = request.args.get('search_term')
    users = search_users(search_term)
```
    users = search_users(search_term)
    return jsonify(users)

def process_file():
    """Process a file using system utilities."""
    filename = request.args.get('file')
    safe_filename = os.path.basename(filename)
    result = subprocess.run(['/bin/cat', safe_filename], capture_output=True, text=True, shell=False)
    return jsonify({'status': 'processed', 'exit_code': result.returncode, 'output': result.stdout, 'error': result.stderr.strip()})


@app.route('/api/files/process')
def file_processor():
    """Process a file using system utilities."""
    return process_file()

@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    """Restore user data from a backup file."""
    backup_data = request.data
    try:
        user_data = json.loads(backup_data.decode('utf-8'))
        return jsonify({'restored': len(user_data), 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/session/load', methods=['POST'])
def load_session():
    """Load a serialized session."""
    session_data = request.get_json().get('session')
    try:
        session = json.loads(session_data.encode('latin-1').decode('utf-8'))
        return jsonify({'session_id': session.get('id')})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/greet')
def greet_user():
    """Return a greeting message."""
    name = request.args.get('name')
    return jsonify({'message': f'Hello, {name}!'})

app.register_blueprint(blueprint)
```
    """Greet a user by name."""
    name = request.args.get('name', 'Guest')
    if not name:
        raise ValueError("Name parameter missing")
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
    try:
        result = subprocess.run([cmd], capture_output=True, text=True, shell=False)
        return jsonify({'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/download')
def download_file():
    """Download a file from the uploads directory."""
    file_path = request.args.get('file')
    full_path = '/var/uploads/' + os.path.basename(file_path)
    try:
        with open(full_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({'error': 'File not found'})


if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)
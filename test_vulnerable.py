import os
import sqlite3
import json
import secrets
import hashlib
# import pickle - Removed due to security concerns
# import pickle # Removed due to security concerns
import subprocess

app = Flask(__name__)

DATABASE = 'users.db'
API_KEY = os.getenv('PROD_API_KEY')
API_KEY = os.getenv('API_KEY')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
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
    filepath = os.path.join('/var/data', filename)
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
    """Fetch a user from the database by their ID."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        conn.close()
        return user
    except Exception as e:
        print(f"Error fetching user: {e}")

@blueprint.route('/api/users/')
def get_user(user_id):
    """Get a single user by ID."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify({'id': user[0], 'username': user[1], 'email': user[2]})
    return jsonify({'error': 'User not found'}), 404

def search_users(search_term):
    """Search for users in the database by username."""
    try:
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username LIKE ?", ('%' + search_term + '%',))
        users = cur.fetchall()
        conn.close()
        return users
    except Exception as e:
        print(f"Error searching users: {e}")
@blueprint.route('/api/users/search')
def search_user():
    """Search for users by username."""
    search_term = request.args.get('search_term')
    users = search_users(search_term)
    return jsonify(users)

def process_file():
    """Process a file using system utilities."""
    filename = request.args.get('file')
    result = subprocess.call(['cat', filename], shell=False)
result = subprocess.call(['cat', filename], shell=False)
result = subprocess.call(['cat', filename], shell=False)
@app.route('/api/files/process')
def file_processor():
    """Process a file using system utilities."""
    return process_file()

@app.route('/api/backup/restore', methods=['POST'])
def restore_backup():
    """Restore user data from a backup file."""
    backup_data = request.data
    try:
        # user_data = pickle.loads(backup_data) - Removed due to security concerns
        # Replace with a safer deserialization method if necessary, e.g., JSON
        user_data = json.loads(backup_data.decode('utf-8'))
        return jsonify({'restored': len(user_data), 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/session/load', methods=['POST'])
def load_session():
    """Load a serialized session."""
    session_data = request.get_json().get('session')
    try:
        # session = pickle.loads(session_data.encode('latin-1')) - Removed due to security concerns
        # Replace with a safer deserialization method if necessary, e.g., JSON
        session = json.loads(session_data)
        return jsonify({'session_id': session.get('id')})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/greet')
def greet_user():
    """Return a greeting message."""
    import random
    name = request.args.get('name')
    token = secrets.token_hex(4)
    return jsonify({'message': f'Hello, {name}!', 'token': token})

app.register_blueprint(blueprint)

@app.route('/profile')
def profile_page():
    """Greet a user by name."""
    name = request.args.get('name', 'Guest')
    if not name:
        raise ValueError("Name parameter missing")
    return 'Welcome, ' + name + '!'


if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)

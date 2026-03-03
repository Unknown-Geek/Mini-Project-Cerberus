# Testing the Cerberus VS Code Extension

## Prerequisites
1. Node.js installed
2. VS Code installed
3. Backend server dependencies installed

## Setup

### 1. Install Extension Dependencies
```bash
npm install
```

### 2. Install and Start Backend Server
```bash
cd server
npm install
npm start
```

The server will run on http://localhost:5000

### 3. Compile Extension
```bash
npm run compile
```

Or watch for changes:
```bash
npm run watch
```

## Running the Extension

### Option 1: Press F5 (Debug Mode)
1. Open the project in VS Code
2. Press `F5` to launch the Extension Development Host
3. A new VS Code window will open with the extension loaded

### Option 2: Install Locally
```bash
vsce package
```
Then install the `.vsix` file in VS Code.

## Testing

### Create a Test File
Create a file called `test_vulnerable.py` with this content:

```python
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability - unsafe string concatenation
    query = 'SELECT * FROM users WHERE id = ' + user_id
    cursor.execute(query)
    return cursor.fetchone()

def login(username, password):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Another SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
```

### Using the Extension

1. **Open the Cerberus Panel**
   - Click the shield icon (🛡️) in the Activity Bar on the left
   - Or run command: `Cerberus: View Results`

2. **Run a Scan**
   - Click the shield icon in the panel title bar
   - Or run command: `Cerberus: Scan for Vulnerabilities`
   - Or press `Ctrl+Shift+P` → type "Cerberus: Scan"

3. **View Results**
   - Vulnerabilities will appear in the tree view
   - Expand files to see individual vulnerabilities
   - Click a vulnerability to see the fix preview

4. **Apply Fixes**
   - Right-click a vulnerability → "Apply Fix"
   - Or right-click a file → "Fix All in File"
   - The file will be automatically updated and saved

## Features

- 🔍 **Scan Workspace**: Scans all code files for vulnerabilities
- 🛠️ **Apply Fix**: Automatically applies AI-suggested fixes
- 📁 **File Tree**: Hierarchical view of vulnerabilities by file
- ⚡ **Real-time**: Instant feedback on scan progress
- 🎯 **Context Menu**: Right-click actions for quick fixes

## Commands

| Command | Description |
|---------|-------------|
| `Cerberus: Scan for Vulnerabilities` | Scan current workspace |
| `Cerberus: Apply Fix` | Apply fix to selected vulnerability |
| `Cerberus: Fix All in File` | Apply all fixes in a file |
| `Cerberus: View Results` | Focus the Cerberus panel |

## Troubleshooting

### "Failed to connect to backend server"
- Make sure the server is running: `cd server && npm start`
- Check if port 5000 is available
- Verify the server is accessible: `curl http://localhost:5000/api/health`

### Extension not loading
- Run `npm run compile` to build the extension
- Check the Debug Console for errors
- Make sure `out/extension.js` exists

### Scan hangs or times out
- Large projects may take several minutes
- The timeout is set to 5 minutes
- Try scanning a smaller folder first

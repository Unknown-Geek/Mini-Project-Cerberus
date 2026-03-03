# Cerberus — AI-Powered Security Co-Pilot

> Your AI-powered security co-pilot that doesn't just find vulnerabilities — it fixes them. In real-time.

Cerberus is a VS Code extension that monitors your Python code as you type, sends snippets to an n8n-powered AI pipeline (Bandit SAST → Auditor Agent → Patcher Agent), and automatically applies security fixes.

---

## Features

- 🔄 **Real-Time Patching** — as you type Python code, snippets are sent (debounced) for security analysis and auto-patched
- 🔍 **Manual Scan** — scan the active file on demand via command palette
- 🛠️ **Apply Fix** — one-click fixes from the vulnerability tree view
- 📊 **Status Bar** — live indicator showing scan/patch status
- 📁 **Vulnerability Tree** — hierarchical view of issues by file

## Architecture

```
VS Code Extension  →  Express Server (:5000)  →  n8n Webhook
                                                    ├─ Syntax Fixer Agent
                                                    ├─ Auditor Agent (Bandit SAST)
                                                    ├─ Patcher Agent
                                                    └─ Google Sheets Logger
```

## Installation

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or later
- VS Code v1.109 or later
- An accessible n8n webhook (self-hosted or cloud)

---

### Option A — Install the pre-built `.vsix` (recommended)

This installs Cerberus permanently into VS Code.

**1. Download or build the `.vsix`**
```bash
# Clone the repo and install dependencies
git clone <repo-url>
cd Mini-Project-Cerberus
npm install

# Package the extension
npx @vscode/vsce package --allow-missing-repository
```

**2. Install the generated file**
```bash
code --install-extension cerberus-0.0.1.vsix
```

**3. Restart VS Code**  
After restart, the **Cerberus shield icon** appears in the Activity Bar.

---

### Option B — Debug / Development Mode (F5)

Use this to iterate on the extension source without packaging.

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile
```

Then press **F5** in VS Code — a new *Extension Development Host* window opens with Cerberus loaded.

---

### Configure Environment

Copy `.env.example` to `.env` and set your n8n webhook URL:
```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `N8N_WEBHOOK_URL` | Your n8n webhook endpoint | `https://n8n.shravanpandala.me/webhook/scan` |
| `N8N_TIMEOUT_SECONDS` | Request timeout in seconds | `120` |
| `PORT` | Backend server port | `5000` |

### Start the Backend Server

The extension requires the Express backend to be running before any scans.

```bash
npm run server:start
# Or with auto-reload during development:
npm run server:dev
```

Verify it's healthy:
```bash
curl http://localhost:5000/api/health
# → {"status":"ok"}
```

---

## Usage

### Real-Time Scanning (on by default)

Real-time scanning activates automatically when the extension loads.

1. Open any `.py` file
2. Start typing — Cerberus debounces changes for **2 seconds**, then sends the modified snippet to the AI pipeline
3. Watch the status bar:
   - `🛡 Cerberus: Idle` — waiting for changes
   - `⟳ Cerberus: Scanning <file>...` — analysis in progress
   - `✓ Cerberus: Patched <file>` — fix applied
4. Vulnerable code is automatically replaced in the editor and the change is saved

### Manual Scan

1. Open a `.py` file
2. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run **Cerberus: Scan for Vulnerabilities**
4. Results appear in the **Cerberus** sidebar panel (shield icon in the Activity Bar)
5. Expand a file node to see individual vulnerabilities

### Applying Fixes

From the sidebar panel:
- Hover a vulnerability item → click the **wrench icon** (Apply Fix) to patch that single issue
- Hover a file node → click the **replace-all icon** (Fix All in File) to apply the first available fix across the file

From the Command Palette:
- **Cerberus: Apply Fix** — fix the selected vulnerability
- **Cerberus: Fix All in File** — fix all issues in the active file

### Start / Stop Real-Time Scanning

| Command | Description |
|---------|-------------|
| `Cerberus: Start Real-Time Scanning` | Re-enable the automatic patch listener |
| `Cerberus: Stop Real-Time Scanning` | Pause auto-patching and clear any pending scans |

Use **Stop** when you want to freely edit code without triggering the AI pipeline (e.g. large refactors), then **Start** to resume protection.

## Commands

| Command | Description |
|---------|-------------|
| `Cerberus: Scan for Vulnerabilities` | Manually scan the active file |
| `Cerberus: Apply Fix` | Apply fix to the selected vulnerability |
| `Cerberus: Fix All in File` | Apply all available fixes in a file |
| `Cerberus: View Results` | Focus the Cerberus sidebar panel |
| `Cerberus: Start Real-Time Scanning` | Resume the real-time auto-patch listener |
| `Cerberus: Stop Real-Time Scanning` | Pause real-time scanning |

## Testing

### Create a Test File
Create `test_vulnerable.py`:
```python
def get_user(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = 'SELECT * FROM users WHERE id = ' + user_id
    cursor.execute(query)
    return cursor.fetchone()
```

### Run the Test Script
```bash
node scan_test.js test_vulnerable.py
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Failed to connect to backend server" | Run `npm run server:start`, check port 5000 |
| Extension not loading | Run `npm run compile`, check `out/extension.js` exists |
| Scan hangs / times out | Check n8n webhook is accessible, increase `N8N_TIMEOUT_SECONDS` |
| Real-time not triggering | Only works for `.py` files. Check status bar for state |

## Changelog

### [Unreleased]
- Real-time code snippet patching with debounce
- Status bar indicator
- `/api/patch-snippet` endpoint for snippet-level patching
- Initial release with manual scan, fix, and tree view

## Development

### Project Structure
```
├── src/
│   ├── extension.ts          # VS Code extension entry point
│   └── vulnerabilityTree.ts  # Tree view provider
├── server/
│   ├── server.js             # Express server
│   ├── routes.js             # API endpoints
│   └── n8nClient.js          # n8n webhook client
├── Main Workflow.json        # n8n workflow (importable)
└── package.json
```

### Scripts
```bash
npm run compile        # Compile TypeScript
npm run watch          # Watch mode
npm run server:start   # Start backend
npm run server:dev     # Backend with nodemon
npm run lint           # ESLint
```
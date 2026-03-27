---
title: Cerberus Security Scanner Backend
emoji: 🛡️
colorFrom: red
colorTo: orange
sdk: docker
pinned: false
app_port: 7860
---

# Cerberus Security Scanner - Backend API

This is the backend API for **Cerberus**, an AI-powered security co-pilot VS Code extension that finds and fixes vulnerabilities in your code.

## What is Cerberus?

Cerberus is a VS Code extension that:
- 🔍 Scans your code for security vulnerabilities
- 🤖 Uses AI to automatically suggest fixes
- ⚡ Provides real-time security scanning
- 🔧 Applies fixes directly to your code

This API serves as the bridge between the VS Code extension and the n8n AI workflow that analyzes and patches vulnerable code.

## API Endpoints

### Health Check
```bash
GET /api/health
```

### Patch Code
```bash
POST /api/patch-code
Content-Type: application/json

{
  "code": "your code here"
}
```

### Patch Snippet (Real-time)
```bash
POST /api/patch-snippet
Content-Type: application/json

{
  "snippet": "code snippet",
  "filePath": "/path/to/file.py",
  "startLine": 10,
  "endLine": 20
}
```

### Scan File
```bash
POST /api/scan-file
Content-Type: application/json

{
  "path": "/path/to/file.py",
  "code": "file contents"
}
```

### Get Stored Fix
```bash
GET /api/stored-fix?path=/absolute/path/to/file.py
```

## Configuration

This API requires the following environment variables to be set in your Hugging Face Space settings:

- `N8N_WEBHOOK_URL` - Your n8n webhook URL for vulnerability analysis
- `N8N_TIMEOUT_SECONDS` - Timeout for n8n requests (default: 120)
- `PORT` - Server port (default: 7860 for HF Spaces)
- `ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins (optional)

## Using with VS Code Extension

To use this deployed backend with your Cerberus VS Code extension:

1. Install the Cerberus extension in VS Code
2. Open VS Code settings (Cmd/Ctrl + ,)
3. Search for "Cerberus Backend"
4. Set **Cerberus: Backend Url** to your Space URL (e.g., `https://shravan-pandala-cerberus-backend.hf.space`)

## Local Development

```bash
npm install
npm run server:start
```

## Repository

GitHub: https://github.com/YOUR-USERNAME/Mini-Project-Cerberus

## License

MIT

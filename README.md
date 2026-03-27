---
title: Cerberus
emoji: 🐕
colorFrom: red
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

<div align="center">
  <img src="https://img.shields.io/badge/Security-Co--Pilot-red?style=for-the-badge&logo=shield" alt="Security Co-Pilot" />
  <img src="https://img.shields.io/badge/VS%20Code-Extension-blue?style=for-the-badge&logo=visual-studio-code" alt="VS Code Extension" />
  <img src="https://img.shields.io/badge/Powered%20By-n8n%20%7C%20Gemini%20%7C%20Groq-green?style=for-the-badge" alt="AI Powered" />
</div>

# 🐕 Cerberus

**Cerberus** is an AI-powered security co-pilot built as a VS Code extension. It doesn't just find vulnerabilities in your Python code—it securely and automatically fixes them in real-time.

## ✨ Features

- **🛡️ Real-Time Security Scanning:** Cerberus continuously monitors your Python files as you type. If you introduce a vulnerability (like an SQL injection or a command injection), it spots it instantly.
- **🤖 Autonomous AI Patching:** Using state-of-the-art LLMs (Google Gemini 2.5 Flash & Groq Llama 3.3), Cerberus automatically rewrites the vulnerable snippet securely.
- **🔄 Multi-Pass Verification:** Cerberus uses an autonomous agent loop to verify its own fixes. If the first fix isn't fully secure, it will re-audit and re-patch the code up to 3 times.
- **⚡ In-Place Replacements:** Fixes are applied directly in your VS Code editor without breaking your surrounding code or formatting.
- **📊 Vulnerability Dashboard:** A dedicated VS Code sidebar panel allows you to view detailed security reports for any scanned file and manually trigger fixes.

---

## 🏗️ Architecture

Cerberus operates on a two-part architecture: the lightweight client (VS Code) and the heavily automated AI backend (n8n).

### 1. The Client (VS Code Extension)
Built in TypeScript, the extension hooks into VS Code's `onDidChangeTextDocument` API. 
- It debounces keystrokes and extracts context around modified code.
- It provides commands like `Cerberus: Scan for Vulnerabilities`, `Cerberus: Start Real-Time Scanning`, and `Cerberus: Apply Fix`.
- It communicates securely via REST to the backend workflow.

### 2. The AI Backend (n8n & LLMs)
The true power of Cerberus lies in its `n8n` workflow backend (located in `n8n/Workflow.json`).
- **Trigger:** Webhook endpoints (`/webhook/scan` and `/webhook/patch-snippet`).
- **SAST Scanner (Bandit):** The code is first run through Bandit to identify exact Python security flaws (B105, B603, B608, etc.).
- **Auditor Agent:** An LLM agent parses the Bandit report and structures the vulnerabilities into actionable JSON.
- **Syntax Fixer & Patcher Agents:** The vulnerable code is passed to a high-speed LLM (Gemini 2.5 Flash-Lite) armed with strict security rules (e.g., parameterized queries, secure secrets modules).
- **Verification Loop:** The newly patched code is fed *back* into Bandit. If any vulnerabilities remain, the loop restarts. Once the code is clean (or max retries are hit), the final secure payload is returned to the extension.

---

## 🚀 Getting Started

### Prerequisites
- [Visual Studio Code](https://code.visualstudio.com/) (v1.109.0+)
- Node.js (v22.x)

### 1. Install the Extension
You can install the `.vsix` package contained in this repository:
1. Open VS Code.
2. Go to the Extensions view (`Ctrl+Shift+X`).
3. Click the `...` menu -> **Install from VSIX...**
4. Select `cerberus-latest.vsix`.

### 2. Configure the Backend
By default, the extension points to a remote n8n backend or local server. To connect your own instance:
1. Open VS Code Settings (`Cmd/Ctrl + ,`).
2. Search for `Cerberus: Backend Url`.
3. Set it to your `n8n` production URL (e.g., `https://n8n.yourdomain.com/webhook`).

### 3. Local Development (Extension)
To develop the extension locally:
```bash
npm install
npm run watch
# Press F5 in VS Code to launch the Extension Development Host
```

---

## 🔐 Security Fix Patterns Supported

Cerberus is explicitly instructed to execute DevSecOps remediation using industry-standard fix patterns:

- **SQL Injection:** Migrates dynamic string concatenation to parameterized execution (`cursor.execute("SELECT...", (val,))`).
- **Command Injection:** Migrates `os.system` and unsafe `subprocess` calls to secure, list-based `subprocess.run(..., shell=False)`.
- **Hardcoded Credentials:** Strips raw passwords and tokens, replacing them with `os.getenv('SECRET_NAME')`.
- **Insecure Randomness:** Replaces the standard `random` module with the cryptographically secure `secrets` module.

---

## 📜 License

This project is licensed under the MIT License.

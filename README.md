# Cerberus Security Extension 🛡️

Cerberus is an AI-powered security co-pilot for Visual Studio Code that doesn't just find vulnerabilities—it fixes them. By leveraging an orchestration of AI agents (Auditor, Syntax Checker, and Patcher) operating through an n8n workflow, Cerberus injects secure, clean alternative code directly into your files naturally.

## Core Features 🌟

1. **Auto-Patch Engine:** Cerberus can autonomously loop through your file and inject repairs line-by-line until the entire document is clean.
2. **Real-time Active Typing Analysis:** Cerberus invisibly analyzes snippets of code as you type, instantly notifying you if you introduce a new vulnerability without requiring manual scans.
3. **Line-Based UI Injections:** Clicking `Apply Fix` cleanly swaps out your vulnerable code blocks for fixed variations right inside your editor natively.
4. **Agentic Orchestration:** Relies on an advanced n8n workflow pipeline that verifies syntax, checks for security regressions, and validates patches before presenting them.

---

## 🚀 Setup & Installation

To run Cerberus successfully, you need to set up three components: the VSCode Extension, the Node.js Relay Server, and the AI Pipeline (n8n).

### Prerequisites
- [Node.js](https://nodejs.org/) (v18+)
- [Visual Studio Code](https://code.visualstudio.com/)
- [n8n](https://n8n.io/) (for the orchestration workflow)
- Python 3.8+ (with `bandit` installed globally for local scanning, optional but recommended)

### 1. Configure the n8n Workflow
1. Open your n8n instance.
2. Import the included `n8n/Workflow.json` file to create the Cerberus orchestration pipeline.
3. Activate the workflow and note the **Webhook URL** that n8n generates.
4. Ensure your LLM provider (e.g., Google Vertex AI, Gemini, or Ollama) credentials are set within the n8n instance.

### 2. Set Up the Relay Server
The extension communicates with a Node.js Express server that relays requests to n8n and manages snippet processing.

```bash
# Clone the repository and install dependencies
git clone https://github.com/Unknown-Geek/Mini-Project-Cerberus.git
cd Mini-Project-Cerberus
npm install
```

Update your `.env` file to include your active n8n Webhook URL. Example:
```env
N8N_WEBHOOK_URL=http://your-n8n-instance-url/webhook/analyze
```

Start the server:
```bash
npm run server:start
```
*(By default, the server runs on `http://localhost:5000`)*

### 3. Install the VSCode Extension
If you simply want to use the extension, you can install the pre-packaged `.vsix` file right away:
```bash
# Install the extension into VSCode
code --install-extension cerberus-latest.vsix
```

Alternatively, you can build and package it yourself:
```bash
npm run compile
npx @vscode/vsce package -o cerberus-latest.vsix
code --install-extension cerberus-latest.vsix
```

---

## 🛠️ Usage Instructions

Once installed, open the **Cerberus panel** located in your VSCode Activity Bar (look for the Shield icon...). 

- **Global Scan:** Open any Python file and click the Scan button `$(search)` on the top title bar of the Cerberus side panel. Wait a few seconds for the scan to populate the internal model tree.
- **Applying a Fix:** Locate any flagged vulnerability in the tree view that contains the wrench icon `$(wrench)`. Click it to accept the suggested structural changes and instantly overwrite your vulnerable code block with a secure alternative.
- **Automatic Remediation:** Click the Magic Wand icon `$(wand)` to let Cerberus automatically apply every available patch across an entire file. It will continuously re-scan and apply patches until the file reaches 0 vulnerabilities (limited to 3 safety loops).
- **Real-Time Scanning:** Click the Play icon `$(play)` to activate real-time monitoring. Cerberus will package recent code modifications via debouncing and continuously verify them silently in the background. Stop by clicking `$(debug-stop)`.

## ⚙️ Configuration

You can configure Cerberus directly in your VSCode settings (`settings.json`):
- `cerberus.backendUrl`: The URL of your relay server. 
  - *Default:* `http://localhost:5000`
  - *Remote Deployment:* If you host the backend on HuggingFace Spaces or Render, update this string to point to your live URL (e.g., `https://my-cerberus-backend.hf.space`).

## 🐞 Troubleshooting

If you observe an `$(error)` label in your Cerberus state tree, your backend webhook or connection dropped.
- Ensure the Node.js relay server is running (`npm run server:start`).
- Verfify that your `n8n` workflow is Active and the Webhook URL in your `.env` matches.
- If using real-time scanning, ensure your LLM provider isn't rate-limiting your requests.

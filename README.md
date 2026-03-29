# Cerberus Security Extension

Cerberus is an AI-powered security co-pilot for VS Code that specifically finds vulnerabilities and seamlessly fixes them within your codebase. Rather than simply scanning code for bugs, Cerberus uses advanced deterministic AI output to inject clean, secure alternative code directly into your files naturally.

## Core Features

1. **Auto-Patch Engine:** Cerberus can autonomously loop through your file and inject repairs line-by-line until the entire document is clean.
2. **Real-time Active Typing Analysis:** Cerberus invisibly analyzes snippets of code directly as you type, instantly notifying you if you introduce a new vulnerability in a debounced chunk without requiring manual scans.
3. **Line-Based UI Injections:** Clicking `Apply Fix` cleanly swaps out your vulnerable code blocks for fixed variations right inside your editor natively.

---

## Usage Instructions

To use Cerberus properly, open the Cerberus extension panel located in your VS Code Activity Bar (look for the Shield icon `$(shield)`). 

- **Global Scan:** Open any Python file (ex: `test.py`) and click the **Scan** button `$(search)` on the top title bar of the Cerberus Side Panel. Wait a few seconds for the scan to populate the internal model tree.
- **Applying a Fix:** Locate any flagged vulnerability in the tree view that contains the wrench icon `$(wrench)`. Click on the wrench inline to accept the suggested structural changes and instantly overwrite your vulnerable code block with a secure, tested alternative line.
- **Automatic Remediation:** Click the **Magic Wand** icon `$(wand)` to let Cerberus automatically apply every available patch across an entire file. It will continuously re-scan and recursively jump back to applying patches until the file reads as $0$ remaining vulnerabilities! (Limits to 3 safety loops).
- **Real-Time Scanning:** Want the scan running invisibly while writing code? Click the **Play** icon `$(play)` to activate Real-Time monitoring. Cerberus will package recent code modifications via debouncing and continuously verify them without manually forcing "Save" triggers! (Stop by clicking `$(debug-stop)`).

## Troubleshooting & Dependencies

If you observe an `$(error)` label in your Cerberus state tree, it's likely your backend webhook or connection dropped. 
- Cerberus requires a backend server routing traffic to process the deterministic mappings via Ollama / N8N pipelines. 
- By default, it expects a local server bound to `http://localhost:5000`. You can spin one up locally using the `npm run server:start` proxy command natively from your workspace.
- You can route the extension directly to your HuggingFace staging container by modifying your VS Code `settings.json` and changing the `cerberus.backendUrl` string appropriately!

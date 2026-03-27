Here is the syntax-corrected raw Python code block:

```python
# Quick Setup Guide - Using HF Spaces Backend

your_cerberus_backend = "https://mojo-maniac-cerberus.hf.space"

## ✅ Deployment Status

deployment_status = {
    "- [x]": "Backend deployed to HF Spaces",
    "- [x]": "Dockerfile configured",
    "- [x]": "All endpoints tested and working",
    "- [ ]": "Environment variables need configuration (see below)",
    "- [ ]": "VS Code extension needs backend URL configuration"
}

## 🔧 Step 1: Configure HF Space Environment Variables

hf_space_url = "https://huggingface.co/spaces/Mojo-Maniac/Cerberus/settings"

def configure_hf_space_environment_variables():
    """
    Configure HF Space environment variables.
    """
    import requests

    url = hf_space_url + "/variables"
    variables = {
        "variables": [
            {
                "name": "N8N_WEBHOOK_URL",
                "type": "string",
                "value": "https://n8n.shravanpandala.me/webhook/scan"
            },
            {
                "name": "N8N_TIMEOUT_SECONDS",
                "type": "integer",
                "value": 120
            },
            {
                "name": "PORT",
                "type": "integer",
                "value": 7860
            }
        ]
    }

    response = requests.post(url, json=variables)
    response.raise_for_status()

    print("HF Space environment variables configured successfully.")

## 📱 Step 2: Configure VS Code Extension

def configure_vs_code_extension():
    """
    Configure VS Code extension.
    """
    import os

    # Option A: Via VS Code Settings UI
    vscode_backend_url = "https://mojo-maniac-cerberus.hf.space"
    vscode_settings_path = os.path.join(os.path.expanduser("~"), ".vscode", "settings.json")

    with open(vscode_settings_path, "w") as f:
        f.write('{"Cerberus: Backend": "' + vscode_backend_url + '"}')

    print("VS Code extension configured successfully.")

    # Option B: Via settings.json (commented out)
    # vscode_settings_path = os.path.join(os.path.expanduser("~"), ".vscode")
    # vscode_settings_data = {'Cerberus: Backend': vscode_backend_url}
    # vscode_settings_path = os.path.join(vscode_settings_path, 'settings.json')
    # with open(vscode_settings_path, 'r+') as f:
    #     import json
    #     vscode_settings_j = json.load(f)
    #     vscode_settings_j.update(vscode_settings_data)
    #     f.seek(0)
    #     json.dump(vscode_settings_j, f)
    #     f.truncate()

# Run the functions
configure_hf_space_environment_variables()
configure_vs_code_extension()
```
2. Type: "**Preferences: Open Settings (JSON)**"
3. Add this line:
   ```
   "cerberus.backendUrl": "https://mojo-maniac-cerberus.hf.space"
   ```
4. Save and reload VS Code

---

## 🧪 Step 3: Test Your Setup

### Test 1: Health Check
```bash
curl https://mojo-maniac-cerberus.hf.space/api/health
```
Expected: `{"status":"ok"}` ✅ (Already working!)

### Test 2: Patch Code (After configuring secrets)
```bash
curl -X POST https://mojo-maniac-cerberus.hf.space/api/patch-code \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(\"dangerous command\")"}' \
  --max-time 130
```
Expected: JSON response with `corrected_code` field

### Test 3: Use Extension
1. Open any Python file in VS Code
2. Start typing code with a vulnerability (e.g., SQL injection)
3. Wait 2 seconds (debounce)
4. Watch the status bar for "Cerberus: Scanning..."
5. Code should automatically get patched!

---

## 📊 Monitoring Your Deployment

- **Space URL:** https://huggingface.co/spaces/Mojo-Maniac/Cerberus
- **Logs:** https://huggingface.co/spaces/Mojo-Maniac/Cerberus?logs=container
- **Settings:** https://huggingface.co/spaces/Mojo-Maniac/Cerberus/settings

---

## 🚨 Current Status

✅ Backend server is deployed and running
⚠️ **Action Required:** Configure the 3 environment variables above
⏳ **Then:** Configure VS Code extension settings
🎉 **Result:** No more manual server starting!

---

## 💡 Benefits of HF Spaces Deployment

- ✅ No need to run `npm run server:start` locally
- ✅ Backend available 24/7 (with free tier sleep after inactivity)
- ✅ Use Cerberus from any machine with VS Code
- ✅ Automatic HTTPS and CORS configuration
- ✅ Built-in rate limiting to prevent abuse

* Check Space logs for request failures
* Verify that environment variables are correctly set
* Ensure the n8n webhook is publicly accessible
* Refer to the `DEPLOYMENT.md` document for a detailed troubleshooting guide
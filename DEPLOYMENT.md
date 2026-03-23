# Deploying Cerberus Backend to Hugging Face Spaces

This guide walks you through deploying the Cerberus backend API to Hugging Face Spaces so you can use the VS Code extension without manually starting a local server.

## Prerequisites

1. A Hugging Face account (create one at https://huggingface.co)
2. Your n8n webhook URL for vulnerability analysis
3. Git installed on your machine

## Step 1: Create a New Space

1. Go to https://huggingface.co/new-space
2. Fill in the details:
   - **Name**: `cerberus-backend` (or any name you prefer)
   - **License**: Choose your preferred license (e.g., MIT)
   - **Space SDK**: Select **Docker**
   - **Visibility**: Public or Private (your choice)
3. Click **Create Space**

## Step 2: Prepare Your Repository

The necessary files are already created in your project:
- `Dockerfile` - Container configuration
- `.dockerignore` - Excludes unnecessary files
- `README.md` - Will become your Space's main page

Make sure your `.env` file is NOT committed (it's already in `.dockerignore`).

## Step 3: Push Code to Hugging Face

You have two options:

### Option A: Push from Git (Recommended)

```bash
# Add HF as a remote (replace YOUR-USERNAME and cerberus-backend with your details)
git remote add hf https://huggingface.co/spaces/YOUR-USERNAME/cerberus-backend

# Push your code
git push hf main
```

### Option B: Upload via Web UI

1. In your Space page, click "Files and versions"
2. Click "Add file" → "Upload files"
3. Upload these files:
   - `Dockerfile`
   - `.dockerignore`
   - `package.json`
   - `package-lock.json` (if you have one)
   - `server/` directory (all files)
   - `README.md`

## Step 4: Configure Environment Variables

1. In your Space page, go to **Settings** tab
2. Scroll to **Repository secrets**
3. Add the following secrets:

   | Variable | Value | Description |
   |----------|-------|-------------|
   | `N8N_WEBHOOK_URL` | `https://n8n.shravanpandala.me/webhook/scan` | Your n8n webhook endpoint |
   | `N8N_TIMEOUT_SECONDS` | `120` | Request timeout (adjust as needed) |
   | `PORT` | `7860` | HF Spaces default port |

4. Click **Save**

## Step 5: Build and Deploy

Hugging Face will automatically build your Docker container:
- Watch the **Logs** tab for build progress
- Building typically takes 2-5 minutes
- Once complete, your Space will show "Running"

Your backend will be available at:
```
https://YOUR-USERNAME-cerberus-backend.hf.space
```

## Step 6: Test Your Deployment

Test the health endpoint:
```bash
curl https://YOUR-USERNAME-cerberus-backend.hf.space/api/health
```

You should get:
```json
{"status":"ok"}
```

## Step 7: Configure VS Code Extension

1. Open VS Code
2. Go to Settings (Cmd/Ctrl + ,)
3. Search for "Cerberus Backend"
4. Set **Cerberus: Backend Url** to your Space URL:
   ```
   https://YOUR-USERNAME-cerberus-backend.hf.space
   ```
5. Reload VS Code to apply changes

## Usage

Now you can use the Cerberus extension without starting the local server:
- Real-time scanning will work automatically
- Manual scans via Command Palette
- Apply fixes directly from the sidebar

## Troubleshooting

### Space is "Sleeping"
- Free HF Spaces sleep after inactivity
- First request after sleep may be slower (~30-60 seconds)
- Consider upgrading to a paid Space for always-on availability

### "Connection Refused" Errors
- Verify the Space is Running (check Space page)
- Verify your backend URL in VS Code settings has no trailing slash
- Check Space logs for errors

### n8n Webhook Timeouts
- Increase `N8N_TIMEOUT_SECONDS` in Space settings
- Check your n8n webhook is publicly accessible
- Consider optimizing your n8n workflow

### Rate Limiting
The backend has built-in rate limits:
- Scan endpoint: 10 requests per 15 minutes per IP
- Snippet patching: 30 requests per minute per IP

If you hit limits, either:
- Wait for the window to reset
- Deploy your own backend server with custom limits

## Updating Your Deployment

To update the deployed backend:

```bash
# Make your changes to server code
git add server/
git commit -m "Update backend"

# Push to HF Space
git push hf main
```

Hugging Face will automatically rebuild and redeploy.

## Alternative Deployment Platforms

If you prefer other platforms, Cerberus backend works on:
- **Railway** - Easy Node.js deployment with free tier
- **Render** - Free tier with auto-sleep
- **Fly.io** - Edge deployment with generous free tier
- **Vercel/Netlify** - May need adaptation (serverless functions)

Contact support if you need help with other platforms!

## Cost Considerations

- **Hugging Face Spaces**: Free tier available with sleep mode
  - Pro tier ($9/month): Always-on, faster hardware, private Spaces
- **n8n Webhook**: Ensure your n8n instance can handle the load
  - Self-hosted: Free but requires server
  - n8n Cloud: Starts at $20/month

## Security Notes

- Your n8n webhook URL should be kept private (use HF secrets)
- Consider adding authentication to your backend if deploying publicly
- Rate limiting is already configured to prevent abuse
- The backend has CORS configured to accept VS Code extension requests

## Need Help?

- Check the Space logs for error messages
- Verify environment variables are set correctly
- Test the n8n webhook independently
- Open an issue on the GitHub repository

---

**Happy scanning!** 🛡️

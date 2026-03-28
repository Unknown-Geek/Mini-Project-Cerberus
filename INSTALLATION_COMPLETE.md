# ✅ Cerberus Extension - Installation Complete

## Installation Status

### ✅ Extension Installed
- **Name**: Cerberus (shravan-pandala.cerberus)
- **Version**: 0.0.1
- **Status**: Successfully installed in VS Code
- **File**: cerberus-latest.vsix (2.2 MB)

### ✅ Backend Server Running
- **URL**: http://localhost:5000
- **Status**: Running and responsive
- **Version**: 0.0.2
- **Endpoints**: 
  - `/api/health` - Health check
  - `/api/scan-file` - Scan single file
  - `/api/scan-folder` - Scan folder

## Recent Improvements

This version includes critical bug fixes:

1. **Line Number Accuracy** ✨
   - Fixes now apply to correct line numbers
   - Smart search finds code within ±10 lines if file changed
   - Line-by-line matching instead of character-based search

2. **Indentation Preservation** ✨
   - Original code formatting maintained
   - Base indentation detected automatically
   - Relative indentation preserved within fixes

## Next Steps

### 1. Test the Extension

Open the test file with intentional vulnerabilities:
```bash
code /Users/shravanpandala/Projects/Mini-Project-Cerberus/test_vulnerable.py
```

### 2. Run Your First Scan

1. Open Command Palette: `⌘+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
2. Type: `Cerberus: Scan for Vulnerabilities`
3. Press Enter
4. Wait for the scan to complete

### 3. View Results

- Check the **Cerberus sidebar** (left panel) for detected vulnerabilities
- Each vulnerability shows:
  - Severity level (Critical/High/Medium/Low)
  - Line number
  - Vulnerability type
  - Original vs Fixed code preview

### 4. Apply Fixes

**Individual Fix**:
1. Expand a vulnerability in the sidebar
2. Right-click → "Apply Fix"
3. Watch it apply to the correct line with proper indentation!

**Fix All**:
1. Right-click on a file in the sidebar
2. Select "Fix All Vulnerabilities in File"
3. All fixes applied in one go (bottom-to-top to avoid line shifts)

## Features to Try

### Real-Time Scanning
- Automatically enabled for Python files
- Scans as you type (with 2-second debounce)
- To disable: Command Palette → `Cerberus: Stop Real-Time Scanning`

### Manual Scanning
- Works on any Python file
- Command: `Cerberus: Scan for Vulnerabilities`
- Results appear in sidebar

### Stored Fixes
- Backend caches fixes from previous scans
- Command: `Cerberus: Apply Stored Fix`
- Useful for re-applying fixes after changes

## Quick Test

Try this in `test_vulnerable.py`:

1. **Scan the file** - Should find ~6 vulnerabilities:
   - Path Traversal (line ~13)
   - Insecure Deserialization (line ~22)
   - Hardcoded Credentials (line ~32)
   - Command Injection (line ~43)
   - SQL Injection (line ~51)

2. **Apply a fix** - Right-click any vulnerability → Apply Fix
   - Should apply to exact line
   - Should preserve indentation
   - Code should remain valid

3. **Check the results**:
   - Line numbers correct? ✅
   - Indentation preserved? ✅
   - Code still runs? ✅

## Status Bar

Look at the bottom-left of VS Code for the Cerberus status:
- `🛡️ Cerberus: Idle` - Ready to scan
- `⟳ Cerberus: Scanning...` - Scan in progress
- `✓ Cerberus: Patched` - Fix applied
- `✗ Cerberus: Error` - Something went wrong

## Configuration

Access settings via:
- VS Code Settings → Search "Cerberus"
- Or edit `.vscode/settings.json`:

```json
{
  "cerberus.backendUrl": "http://localhost:5000"
}
```

## Troubleshooting

### Extension not appearing?
- Restart VS Code: `⌘+Q` then reopen
- Check Extensions list: `⌘+Shift+X`
- Look for "Cerberus"

### Backend not responding?
- Check server is running: `lsof -ti:5000`
- Restart: `npm run server:start`
- Check logs for errors

### Fixes not working?
- Re-scan the file first (to get fresh data)
- Check console: View → Output → Cerberus
- Look for `[FIX]` or `[DIFF]` log messages

## Documentation

- **INSTALLATION.md** - Full installation guide
- **TESTING_GUIDE.md** - Detailed testing instructions
- **FIXES_SUMMARY.md** - Technical details of recent fixes
- **README.md** - Complete documentation

## Support

### Debug Logs
- View → Output → Select "Cerberus" from dropdown
- Look for `[FIX]` messages for fix application logs
- Look for `[DIFF]` messages for line number detection logs

### Server Logs
- Check terminal where server is running
- Look for API request/response logs

### Common Issues

**"Failed to connect to backend"**
```bash
# Restart the server
npm run server:start
```

**"No vulnerabilities found"**
- Only Python files are supported
- Backend may need n8n workflow configuration
- File might actually be secure!

**"Fix applied to wrong line"**
- This should be fixed now!
- If still happening, re-scan the file
- Report with details

## What's Working Now

✅ Extension installed in VS Code  
✅ Backend server running on port 5000  
✅ Line number accuracy improved  
✅ Indentation preservation working  
✅ Smart line search (±10 lines)  
✅ Code validation before applying fixes  
✅ Batch fixes working correctly  
✅ Real-time scanning enabled  
✅ Manual scanning working  
✅ Sidebar tree view functional  

## Ready to Use! 🚀

Your Cerberus extension is now fully installed and ready to scan for security vulnerabilities.

**Quick Start**: Open `test_vulnerable.py` and run `Cerberus: Scan for Vulnerabilities` from the Command Palette!

---

**Installation Date**: March 28, 2026  
**Version**: 0.0.1  
**Server**: http://localhost:5000  
**Status**: ✅ Ready

# Cerberus Extension Installation Guide

## Latest Version Details

- **File**: `cerberus-latest.vsix`
- **Size**: 2.2 MB
- **Version**: 0.0.1
- **Date**: March 28, 2026

## Recent Updates ✨

This version includes critical fixes for the "Apply Fix" feature:

✅ **Fixed Line Number Accuracy**: Fixes now apply to the correct line number, even if the file has changed slightly since scanning

✅ **Fixed Indentation Preservation**: Original code formatting and indentation are now properly maintained when applying fixes

## Installation Methods

### Method 1: Install from VSIX File (Recommended)

1. **From VS Code**:
   ```
   1. Open VS Code
   2. Click on Extensions (⌘+Shift+X on Mac, Ctrl+Shift+X on Windows)
   3. Click on the "..." menu at the top of the Extensions sidebar
   4. Select "Install from VSIX..."
   5. Navigate to and select: cerberus-latest.vsix
   6. Reload VS Code when prompted
   ```

2. **From Command Line**:
   ```bash
   code --install-extension /Users/shravanpandala/Projects/Mini-Project-Cerberus/cerberus-latest.vsix
   ```

### Method 2: Install from Source (Development)

1. **Clone or locate the repository**:
   ```bash
   cd /Users/shravanpandala/Projects/Mini-Project-Cerberus
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Compile the TypeScript**:
   ```bash
   npm run compile
   ```

4. **Open in VS Code**:
   ```bash
   code .
   ```

5. **Run in Extension Development Host**:
   - Press `F5` to launch the extension in a new VS Code window
   - Or go to Run > Start Debugging

## Post-Installation Setup

### 1. Start the Backend Server

The extension requires a backend server to analyze code:

**Option A: Local Development**
```bash
cd /Users/shravanpandala/Projects/Mini-Project-Cerberus
npm run server:start
```

**Option B: Use Deployed Backend** (if available)
- The extension is configured to use `http://localhost:5000` by default
- To use a remote backend, update the setting:
  1. Open VS Code Settings (⌘+, on Mac, Ctrl+, on Windows)
  2. Search for "Cerberus Backend URL"
  3. Change to your deployed backend URL

### 2. Verify Installation

1. Open a Python file in VS Code
2. Open Command Palette (⌘+Shift+P / Ctrl+Shift+P)
3. Type "Cerberus" - you should see:
   - Cerberus: Scan for Vulnerabilities
   - Cerberus: Apply Stored Fix
   - Cerberus: Start Real-Time Scanning
   - Cerberus: Stop Real-Time Scanning
   - Cerberus: View Results

4. Check the status bar - you should see "🛡️ Cerberus: Idle"

### 3. Test the Fixes

Use the provided test file:
```bash
# Open the test file
code /Users/shravanpandala/Projects/Mini-Project-Cerberus/test_vulnerable.py

# Run a scan
# Command Palette > "Cerberus: Scan for Vulnerabilities"

# View results in the Cerberus sidebar
# Try applying individual fixes or "Fix All"
```

## Configuration

### Backend URL
```json
{
  "cerberus.backendUrl": "http://localhost:5000"
}
```

Change this in VS Code Settings to point to your backend server.

## Features

### Security Scanning
- Manual scan: `Cerberus: Scan for Vulnerabilities`
- Real-time scanning: Automatically scans as you type (Python files)
- Detects: SQL Injection, Command Injection, Path Traversal, XSS, and more

### Vulnerability Fixing
- **Apply individual fix**: Right-click vulnerability → "Apply Fix"
- **Fix all vulnerabilities**: Right-click file → "Fix All Vulnerabilities in File"
- **Smart line matching**: Finds correct line even if file changed
- **Indentation preservation**: Maintains your code formatting

### Sidebar View
- Tree view of all vulnerabilities by file
- Severity indicators (Critical, High, Medium, Low)
- Code preview (original vs fixed)
- One-click navigation to issues

## Troubleshooting

### "Failed to connect to backend server"
**Solution**: Make sure the backend server is running:
```bash
npm run server:start
```

### "No vulnerabilities found"
**Possible causes**:
- File is already secure (good!)
- Backend not configured properly
- Only Python files are supported currently

### Fixes applying to wrong lines
**Solution**: This should now be fixed in this version! If you still see issues:
1. Re-scan the file to get fresh data
2. Check console logs for debugging info
3. Report the issue with details

### Permission errors on Mac
If you get permission errors installing:
```bash
sudo code --install-extension cerberus-latest.vsix
```

## Uninstallation

1. Open Extensions in VS Code
2. Search for "Cerberus"
3. Click gear icon → Uninstall

Or via command line:
```bash
code --uninstall-extension shravan-pandala.cerberus
```

## Next Steps

- Review the [TESTING_GUIDE.md](./TESTING_GUIDE.md) for detailed testing instructions
- Check [FIXES_SUMMARY.md](./FIXES_SUMMARY.md) for technical details on recent improvements
- Read [README.md](./README.md) for full documentation

## Support

For issues or questions:
- Check the console logs (View > Output > Cerberus)
- Review the test files and documentation
- Check backend server logs

## What's New in This Version

### Bug Fixes
1. **Line number accuracy**: Completely rewrote line number detection logic
   - Uses line-by-line matching instead of character position
   - Searches within ±10 lines if code has moved
   - Validates before applying fixes

2. **Indentation preservation**: Added smart indentation detection
   - Detects base indentation from original code
   - Preserves relative indentation within fixes
   - Handles tabs, spaces, and mixed indentation

### Improvements
- Better error messages and user warnings
- Enhanced logging for debugging
- Improved code validation before applying fixes
- Batch fix operations more reliable

---

**Version**: 0.0.1  
**Build Date**: March 28, 2026  
**File**: cerberus-latest.vsix (2.2 MB)

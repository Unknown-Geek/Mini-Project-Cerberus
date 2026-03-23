import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { VulnerabilityTreeDataProvider, Vulnerability, VulnerabilityItem } from './vulnerabilityTree';

// Get backend URL from settings or use default
function getBackendUrl(): string {
	const config = vscode.workspace.getConfiguration('cerberus');
	return config.get<string>('backendUrl') || 'http://localhost:5000';
}

let BACKEND_URL = getBackendUrl();

// Global references
let vulnerabilityProvider: VulnerabilityTreeDataProvider;
let statusBarItem: vscode.StatusBarItem;

// Debounce timers per file URI
const debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
const DEBOUNCE_MS = 2000;

// Guard: prevent re-entrant patching while we're applying a fix
let isPatchingInProgress = false;

// Toggle for real-time scanning
let realTimeEnabled = true;

// This method is called when your extension is activated
export function activate(context: vscode.ExtensionContext) {
	console.log('Cerberus security extension is now active!');

	// --- Status Bar ---
	statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
	statusBarItem.text = '$(shield) Cerberus: Idle';
	statusBarItem.tooltip = 'Cerberus real-time security scanner';
	statusBarItem.show();
	context.subscriptions.push(statusBarItem);

	// --- Configuration Change Listener ---
	const configChangeListener = vscode.workspace.onDidChangeConfiguration((e) => {
		if (e.affectsConfiguration('cerberus.backendUrl')) {
			BACKEND_URL = getBackendUrl();
			console.log(`Cerberus: Backend URL updated to ${BACKEND_URL}`);
		}
	});
	context.subscriptions.push(configChangeListener);

	// --- Tree View ---
	vulnerabilityProvider = new VulnerabilityTreeDataProvider();
	vscode.window.createTreeView('cerberus.vulnerabilityView', {
		treeDataProvider: vulnerabilityProvider,
		showCollapseAll: true,
	});

	// ============================
	// REAL-TIME LISTENER
	// ============================
	const changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
		const doc = event.document;

		// Check if real-time scanning is enabled
		if (!realTimeEnabled) { return; }
		// Only trigger for Python files
		if (doc.languageId !== 'python') { return; }
		// Skip untitled / dirty-from-us files
		if (doc.uri.scheme !== 'file') { return; }
		// Skip if we are currently applying a patch
		if (isPatchingInProgress) { return; }
		// Skip if no actual content changes
		if (event.contentChanges.length === 0) { return; }

		const fileKey = doc.uri.toString();

		// Clear previous debounce for this file
		if (debounceTimers.has(fileKey)) {
			clearTimeout(debounceTimers.get(fileKey)!);
		}

		// Set new debounce
		debounceTimers.set(fileKey, setTimeout(() => {
			debounceTimers.delete(fileKey);
			handleRealTimePatch(doc, event.contentChanges);
		}, DEBOUNCE_MS));
	});
	context.subscriptions.push(changeListener);

	// ============================
	// MANUAL SCAN COMMAND
	// ============================
	const scanDisposable = vscode.commands.registerCommand('cerberus.scan', async () => {
		const activeEditor = vscode.window.activeTextEditor;
		if (!activeEditor) {
			vscode.window.showErrorMessage('Please open a file to scan.');
			return;
		}

		const filePath = activeEditor.document.uri.fsPath;
		const fileName = path.basename(filePath);

		setStatus('scanning', fileName);

		try {
			const code = activeEditor.document.getText();

			const response = await axios.post(`${BACKEND_URL}/api/scan-file`, {
				path: filePath,
				code: code
			}, {
				timeout: 60000
			});

			const data = response.data;
			const vulnerabilities: Vulnerability[] = data.vulnerabilities || [];

			vulnerabilityProvider.setVulnerabilities(vulnerabilities);

			const analyzedVulns = vulnerabilities.filter((v: Vulnerability) => v.status === 'analyzed');
			const errorCount = vulnerabilities.filter((v: Vulnerability) => v.status === 'error').length;

			if (analyzedVulns.length > 0) {
				// Build a summary of found issues
				const typesSummary = [...new Set(analyzedVulns.map(v => v.type).filter(Boolean))];
				const summaryText = typesSummary.length > 0
					? `Found: ${typesSummary.join(', ')}`
					: `Found ${analyzedVulns.length} issues`;

				vscode.window.showInformationMessage(
					`✅ Cerberus: ${summaryText} in ${fileName}. Check the sidebar for details.`
				);
			} else if (errorCount > 0) {
				vscode.window.showWarningMessage(
					`⚠️ Cerberus: ${errorCount} errors while scanning ${fileName}.`
				);
			} else {
				vscode.window.showInformationMessage(
					`✅ Cerberus: No vulnerabilities found in ${fileName}.`
				);
			}

			setStatus('idle');
		} catch (error: any) {
			setStatus('error');
			let errorMessage = `❌ Cerberus: Failed to connect to backend server at ${BACKEND_URL}.`;

			if (error.code === 'ECONNREFUSED') {
				errorMessage += ' Is the server running? (npm run server:start)';
			} else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
				errorMessage += ' Request timed out.';
			} else if (error.response) {
				errorMessage += ` Server error: ${error.response.status}`;
			} else {
				errorMessage += ` ${error.message}`;
			}

			vscode.window.showErrorMessage(errorMessage);
		}
	});

	// ============================
	// FIX COMMANDS
	// ============================
	const fixDisposable = vscode.commands.registerCommand('cerberus.fixVulnerability', async (item?: VulnerabilityItem) => {
		if (!item || !item.vulnerability) {
			vscode.window.showWarningMessage('Please select a vulnerability from the Cerberus panel to fix.');
			return;
		}
		const vulnerability = item.vulnerability;
		if (vulnerability.status !== 'analyzed') {
			vscode.window.showErrorMessage('No fix available for this vulnerability.');
			return;
		}

		// If we have specific fixed code for this vulnerability
		if (vulnerability.fixedCode && vulnerability.originalCode && vulnerability.line) {
			await applyIndividualFix(vulnerability);
		} else if (vulnerability.result) {
			// Fall back to full file replacement
			await applyFix(vulnerability.file, vulnerability.result);
		} else {
			vscode.window.showErrorMessage('No fix available for this vulnerability.');
		}
	});

	const fixFileDisposable = vscode.commands.registerCommand('cerberus.fixFile', async (item?: VulnerabilityItem) => {
		if (!item) {
			vscode.window.showWarningMessage('Please select a file from the Cerberus panel.');
			return;
		}
		const fileVulns = vulnerabilityProvider.getVulnerabilitiesForFile(item.label);
		if (fileVulns.length === 0) {
			vscode.window.showWarningMessage('No vulnerabilities found for this file.');
			return;
		}

		// Get the full corrected code from stored fix
		const filePath = fileVulns[0].file;
		try {
			const response = await axios.get(`${BACKEND_URL}/api/stored-fix`, {
				params: { path: filePath },
				timeout: 10000
			});
			const { correctedCode } = response.data;
			await applyFix(filePath, correctedCode);
		} catch (error: any) {
			// Fallback: use the result from the first fixable vulnerability
			const fixableVuln = fileVulns.find(v => v.status === 'analyzed' && v.result);
			if (fixableVuln) {
				await applyFix(fixableVuln.file, fixableVuln.result!);
			} else {
				vscode.window.showErrorMessage('No fixes available for this file.');
			}
		}
	});

	const viewDisposable = vscode.commands.registerCommand('cerberus.viewResults', () => {
		vscode.commands.executeCommand('cerberus.vulnerabilityView.focus');
	});

	// ============================
	// START / STOP REAL-TIME
	// ============================
	const startDisposable = vscode.commands.registerCommand('cerberus.startRealTime', () => {
		realTimeEnabled = true;
		setStatus('idle');
		vscode.window.showInformationMessage('🟢 Cerberus: Real-time scanning started.');
	});

	const stopDisposable = vscode.commands.registerCommand('cerberus.stopRealTime', () => {
		realTimeEnabled = false;
		// Clear any pending debounce timers
		for (const timer of debounceTimers.values()) {
			clearTimeout(timer);
		}
		debounceTimers.clear();
		statusBarItem.text = '$(shield) Cerberus: Stopped';
		vscode.window.showInformationMessage('🔴 Cerberus: Real-time scanning stopped.');
	});

	// ============================
	// APPLY STORED FIX (command palette)
	// ============================
	const applyStoredFixDisposable = vscode.commands.registerCommand('cerberus.applyStoredFix', async () => {
		const activeEditor = vscode.window.activeTextEditor;
		if (!activeEditor) {
			vscode.window.showErrorMessage('Open the file you want to fix first.');
			return;
		}

		const filePath = activeEditor.document.uri.fsPath;
		const fileName = path.basename(filePath);

		setStatus('scanning', fileName);

		try {
			const response = await axios.get(`${BACKEND_URL}/api/stored-fix`, {
				params: { path: filePath },
				timeout: 10000
			});

			const { correctedCode, storedAt } = response.data;
			const age = storedAt
				? `(scanned ${new Date(storedAt).toLocaleTimeString()})`
				: '';

			const choice = await vscode.window.showInformationMessage(
				`Cerberus: Apply stored fix for ${fileName} ${age}?`,
				'Apply', 'Cancel'
			);
			if (choice !== 'Apply') {
				setStatus('idle');
				return;
			}

			await applyFix(filePath, correctedCode);
			setStatus('idle');
		} catch (error: any) {
			setStatus('idle');
			if (error.response?.status === 404) {
				vscode.window.showWarningMessage(
					`No stored fix for ${fileName}. Run "Cerberus: Scan for Vulnerabilities" first.`
				);
			} else if (error.code === 'ECONNREFUSED') {
				vscode.window.showErrorMessage('Cerberus server is not running. Start it with: npm run server:start');
			} else {
				vscode.window.showErrorMessage(`Failed to retrieve stored fix: ${error.message}`);
			}
		}
	});

	context.subscriptions.push(scanDisposable, fixDisposable, fixFileDisposable, viewDisposable, startDisposable, stopDisposable, applyStoredFixDisposable);
}

// ============================
// REAL-TIME PATCH HANDLER
// ============================
async function handleRealTimePatch(
	doc: vscode.TextDocument,
	contentChanges: readonly vscode.TextDocumentContentChangeEvent[]
) {
	// Determine the range of changed lines
	let minLine = Infinity;
	let maxLine = -Infinity;
	for (const change of contentChanges) {
		minLine = Math.min(minLine, change.range.start.line);
		// Account for inserted lines
		const newLineCount = change.text.split('\n').length - 1;
		const endLine = change.range.start.line + newLineCount;
		maxLine = Math.max(maxLine, endLine, change.range.end.line);
	}

	// Expand by context lines (5 above and below)
	const contextLines = 5;
	const startLine = Math.max(0, minLine - contextLines);
	const endLine = Math.min(doc.lineCount - 1, maxLine + contextLines);

	// Extract snippet
	const snippetRange = new vscode.Range(startLine, 0, endLine, doc.lineAt(endLine).text.length);
	const snippet = doc.getText(snippetRange);

	// Skip tiny snippets (less than 3 actual non-empty lines)
	const nonEmptyLines = snippet.split('\n').filter(l => l.trim().length > 0).length;
	if (nonEmptyLines < 3) { return; }

	const filePath = doc.uri.fsPath;
	const fileName = path.basename(filePath);

	setStatus('scanning', fileName);

	try {
		const response = await axios.post(`${BACKEND_URL}/api/patch-snippet`, {
			snippet,
			filePath,
			startLine,
			endLine,
			fullFileContext: doc.getText() // included for future use
		}, {
			timeout: 130000
		});

		const data = response.data;

		if (data.has_changes && data.patched_snippet && data.patched_snippet !== snippet) {
			// Apply the patched snippet back to the editor
			isPatchingInProgress = true;

			try {
				const edit = new vscode.WorkspaceEdit();
				// Re-read the document to get the current state (it may have changed during the request)
				const currentDoc = vscode.workspace.textDocuments.find(d => d.uri.toString() === doc.uri.toString());
				if (!currentDoc) { return; }

				const currentSnippetRange = new vscode.Range(
					startLine, 0,
					Math.min(endLine, currentDoc.lineCount - 1),
					currentDoc.lineAt(Math.min(endLine, currentDoc.lineCount - 1)).text.length
				);

				edit.replace(currentDoc.uri, currentSnippetRange, data.patched_snippet);
				const success = await vscode.workspace.applyEdit(edit);

				if (success) {
					setStatus('patched', fileName);
					// Reset to idle after 3 seconds
					setTimeout(() => setStatus('idle'), 3000);
				} else {
					setStatus('idle');
				}
			} finally {
				// Small delay before re-enabling to avoid retriggering on our own edit
				setTimeout(() => { isPatchingInProgress = false; }, 500);
			}
		} else {
			setStatus('idle');
		}
	} catch (error: any) {
		// Silently fail for real-time — don't spam the user
		console.error('Real-time patch error:', error.message);
		setStatus('idle');
	}
}

// ============================
// APPLY FIX (full file replace)
// ============================
async function applyFix(filePath: string, correctedCode: string) {
	try {
		if (!fs.existsSync(filePath)) {
			vscode.window.showErrorMessage(`File not found: ${filePath}`);
			return;
		}

		const document = await vscode.workspace.openTextDocument(filePath);
		await vscode.window.showTextDocument(document);

		const edit = new vscode.WorkspaceEdit();
		const fullRange = new vscode.Range(
			document.positionAt(0),
			document.positionAt(document.getText().length)
		);

		edit.replace(document.uri, fullRange, correctedCode);
		const success = await vscode.workspace.applyEdit(edit);

		if (success) {
			await document.save();
			vscode.window.showInformationMessage(`✅ Fix applied and saved: ${path.basename(filePath)}`);
		} else {
			vscode.window.showErrorMessage('Failed to apply fix.');
		}
	} catch (error) {
		vscode.window.showErrorMessage(`Error applying fix: ${error}`);
	}
}

// ============================
// APPLY INDIVIDUAL FIX (specific vulnerability)
// ============================
async function applyIndividualFix(vulnerability: Vulnerability) {
	try {
		const filePath = vulnerability.file;

		if (!fs.existsSync(filePath)) {
			vscode.window.showErrorMessage(`File not found: ${filePath}`);
			return;
		}

		const document = await vscode.workspace.openTextDocument(filePath);
		await vscode.window.showTextDocument(document);

		const originalCode = vulnerability.originalCode;
		const fixedCode = vulnerability.fixedCode;

		if (!originalCode || !fixedCode) {
			vscode.window.showErrorMessage('Invalid fix data for this vulnerability.');
			return;
		}

		// If original and fixed are the same, nothing to do
		if (originalCode === fixedCode) {
			vscode.window.showInformationMessage('This vulnerability appears to already be fixed.');
			return;
		}

		const documentText = document.getText();

		// Strategy 1: Try exact string match first
		let originalIndex = documentText.indexOf(originalCode);

		// Strategy 2: Try trimmed match (ignore leading/trailing whitespace differences)
		if (originalIndex === -1) {
			const trimmedOriginal = originalCode.trim();
			const trimmedDocText = documentText;
			// Search for trimmed version
			const searchIndex = trimmedDocText.indexOf(trimmedOriginal);
			if (searchIndex !== -1) {
				// Find the actual start (include leading whitespace on the line)
				const lineStart = trimmedDocText.lastIndexOf('\n', searchIndex) + 1;
				originalIndex = lineStart;
				// Adjust to use the trimmed original for replacement
			}
		}

		// Strategy 3: Line-based replacement DISABLED
		// This approach is unreliable because the fixedCode extraction from diffs
		// often produces incorrect/corrupted code. Instead, guide users to Fix All.
		if (originalIndex === -1) {
			vscode.window.showWarningMessage(
				`Could not locate the vulnerable code in the file. ` +
				`The file may have changed since scanning. Please re-scan or use "Fix Entire File" instead.`
			);
			return;
		}

		// If we found exact match, use it
		if (originalIndex !== -1) {
			const startPos = document.positionAt(originalIndex);
			const endPos = document.positionAt(originalIndex + originalCode.length);
			const range = new vscode.Range(startPos, endPos);

			const edit = new vscode.WorkspaceEdit();
			edit.replace(document.uri, range, fixedCode);

			isPatchingInProgress = true;
			try {
				const success = await vscode.workspace.applyEdit(edit);

				if (success) {
					await document.save();
					const vulnType = vulnerability.type || 'vulnerability';
					vscode.window.showInformationMessage(
						`✅ Fixed ${vulnType} at line ${vulnerability.line} in ${path.basename(filePath)}`
					);
				} else {
					vscode.window.showErrorMessage('Failed to apply fix.');
				}
			} finally {
				setTimeout(() => { isPatchingInProgress = false; }, 500);
			}
			return;
		}

		// No match found
		vscode.window.showWarningMessage(
			'Could not locate the vulnerable code. The file may have been modified.'
		);
	} catch (error) {
		vscode.window.showErrorMessage(`Error applying fix: ${error}`);
	}
}

// ============================
// HELPER FUNCTIONS
// ============================

/**
 * Calculate similarity between two strings (0-1 scale)
 * Uses a simple character-based comparison
 */
function calculateSimilarity(str1: string, str2: string): number {
	if (str1 === str2) return 1;
	if (!str1 || !str2) return 0;

	const longer = str1.length > str2.length ? str1 : str2;
	const shorter = str1.length > str2.length ? str2 : str1;

	if (longer.length === 0) return 1;

	// Count matching characters in order
	let matches = 0;
	let shorterIdx = 0;
	for (let i = 0; i < longer.length && shorterIdx < shorter.length; i++) {
		if (longer[i] === shorter[shorterIdx]) {
			matches++;
			shorterIdx++;
		}
	}

	return matches / longer.length;
}

// ============================
// STATUS BAR HELPER
// ============================
function setStatus(state: 'idle' | 'scanning' | 'patched' | 'error', fileName?: string) {
	switch (state) {
		case 'idle':
			statusBarItem.text = '$(shield) Cerberus: Idle';
			statusBarItem.backgroundColor = undefined;
			break;
		case 'scanning':
			statusBarItem.text = `$(sync~spin) Cerberus: Scanning ${fileName || ''}...`;
			statusBarItem.backgroundColor = undefined;
			break;
		case 'patched':
			statusBarItem.text = `$(check) Cerberus: Patched ${fileName || ''}`;
			statusBarItem.backgroundColor = undefined;
			break;
		case 'error':
			statusBarItem.text = '$(error) Cerberus: Error';
			statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
			break;
	}
}

export function deactivate() {
	// Clear all pending debounce timers
	for (const timer of debounceTimers.values()) {
		clearTimeout(timer);
	}
	debounceTimers.clear();
}

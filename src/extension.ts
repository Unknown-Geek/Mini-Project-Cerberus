import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { VulnerabilityTreeDataProvider, Vulnerability, VulnerabilityItem } from './vulnerabilityTree';

const BACKEND_URL = 'http://localhost:5000';

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

			const analyzedCount = vulnerabilities.filter((v: Vulnerability) => v.status === 'analyzed').length;
			const errorCount = vulnerabilities.filter((v: Vulnerability) => v.status === 'error').length;

			if (analyzedCount > 0) {
				vscode.window.showInformationMessage(
					`✅ Cerberus: Found ${analyzedCount} issues in ${fileName}.`
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
	// FIX COMMANDS (unchanged)
	// ============================
	const fixDisposable = vscode.commands.registerCommand('cerberus.fixVulnerability', async (item?: VulnerabilityItem) => {
		if (!item || !item.vulnerability) {
			vscode.window.showWarningMessage('Please select a vulnerability from the Cerberus panel to fix.');
			return;
		}
		const vulnerability = item.vulnerability;
		if (vulnerability.status !== 'analyzed' || !vulnerability.result) {
			vscode.window.showErrorMessage('No fix available for this vulnerability.');
			return;
		}
		await applyFix(vulnerability.file, vulnerability.result);
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
		const fixableVuln = fileVulns.find(v => v.status === 'analyzed' && v.result);
		if (!fixableVuln) {
			vscode.window.showErrorMessage('No fixes available for this file.');
			return;
		}
		await applyFix(fixableVuln.file, fixableVuln.result!);
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

	context.subscriptions.push(scanDisposable, fixDisposable, fixFileDisposable, viewDisposable, startDisposable, stopDisposable);
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

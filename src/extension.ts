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
	// AUTO-SCAN ON SAVE
	// ============================
	const saveListener = vscode.workspace.onDidSaveTextDocument((doc) => {
		// Only trigger for Python files and actual files on disk
		if (doc.languageId === 'python' && doc.uri.scheme === 'file') {
			// Check if real-time scanning is enabled
			if (!realTimeEnabled) { return; }
			
			// If it's the active document, we can run the scan command directly
			const activeEditor = vscode.window.activeTextEditor;
			if (activeEditor && activeEditor.document.uri.toString() === doc.uri.toString()) {
				vscode.commands.executeCommand('cerberus.scan');
			}
		}
	});
	context.subscriptions.push(saveListener);

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
				timeout: 180000
			});

			const data = response.data;
			const vulnerabilities: Vulnerability[] = data.vulnerabilities || [];
			const vulnTypes: string[] = data.vulnerability_types || [];
			const vulnCount: number = data.vulnerability_count || vulnerabilities.length;

			vulnerabilityProvider.setVulnerabilities(vulnerabilities);

			const analyzedVulns = vulnerabilities.filter((v: Vulnerability) => v.status === 'analyzed');
			const errorCount = vulnerabilities.filter((v: Vulnerability) => v.status === 'error').length;

			if (analyzedVulns.length > 0) {
				// Use n8n vulnerability types if available, otherwise extract from vulnerabilities
				const typesSummary = vulnTypes.length > 0
					? vulnTypes
					: [...new Set(analyzedVulns.map(v => v.type).filter(Boolean))];
				const summaryText = typesSummary.length > 0
					? `Found ${vulnCount} issue(s): ${typesSummary.join(', ')}`
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

		// Prefer line-based fix when we have line numbers and fixedCode
		if (vulnerability.fixedCode && vulnerability.line) {
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

		const filePath = fileVulns[0].file;

		// Prefer line-based fixes: apply each individually from bottom-to-top
		const fixableVulns = fileVulns
			.filter(v => v.status === 'analyzed' && v.fixedCode && v.line)
			.sort((a, b) => (b.line || 0) - (a.line || 0)); // bottom-to-top

		if (fixableVulns.length > 0) {
			let fixedCount = 0;
			for (const vuln of fixableVulns) {
				const success = await applyIndividualFix(vuln, true);
				if (success) { fixedCount++; }
			}
			vscode.window.showInformationMessage(
				`✅ Cerberus: Applied ${fixedCount}/${fixableVulns.length} fixes in ${path.basename(filePath)}`
			);
		} else {
			// Fallback: try stored full-file fix
			try {
				const response = await axios.get(`${BACKEND_URL}/api/stored-fix`, {
					params: { path: filePath },
					timeout: 10000
				});
				const { correctedCode } = response.data;
				await applyFix(filePath, correctedCode);
			} catch (error: any) {
				const fixableByResult = fileVulns.find(v => v.status === 'analyzed' && v.result);
				if (fixableByResult) {
					await applyFix(fixableByResult.file, fixableByResult.result!);
				} else {
					vscode.window.showErrorMessage('No fixes available for this file.');
				}
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

	// ============================
	// GLOBAL FIX ALL
	// ============================
	const fixAllGlobalDisposable = vscode.commands.registerCommand('cerberus.fixAllGlobal', async () => {
		const allVulns = vulnerabilityProvider.getAllVulnerabilities();
		if (!allVulns || allVulns.length === 0) {
			vscode.window.showInformationMessage('No vulnerabilities found to fix.');
			return;
		}

		// Get unique file names that have vulnerabilities
		const fileNames = [...new Set(allVulns.map(v => {
			return v.file.split('\\').pop()?.split('/').pop() || v.file;
		}))];

		if (fileNames.length === 0) {
			return;
		}

		vscode.window.showInformationMessage(`Cerberus: Starting global fix across ${fileNames.length} file(s)...`);

		// Iterate through each file and trigger the fixFile logic
		for (const fileName of fileNames) {
			// Create a mock tree item with the file name as the label
			const mockItem = new VulnerabilityItem(fileName, vscode.TreeItemCollapsibleState.None, undefined, undefined, 'file');
			await vscode.commands.executeCommand('cerberus.fixFile', mockItem);
		}
	});

	context.subscriptions.push(scanDisposable, fixDisposable, fixFileDisposable, viewDisposable, startDisposable, stopDisposable, applyStoredFixDisposable, fixAllGlobalDisposable);

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
// APPLY INDIVIDUAL FIX (line-number based)
// ============================
async function applyIndividualFix(vulnerability: Vulnerability, silent: boolean = false): Promise<boolean> {
	try {
		const filePath = vulnerability.file;

		if (!fs.existsSync(filePath)) {
			if (!silent) { vscode.window.showErrorMessage(`File not found: ${filePath}`); }
			return false;
		}

		const document = await vscode.workspace.openTextDocument(filePath);
		if (!silent) { await vscode.window.showTextDocument(document); }

		const fixedCode = vulnerability.fixedCode;

		if (!fixedCode) {
			if (!silent) { vscode.window.showErrorMessage('No fix data for this vulnerability.'); }
			return false;
		}

		// Use line numbers directly from the vulnerability data
		let startLine = (vulnerability.line || 1) - 1; // Convert to 0-indexed
		let endLine = (vulnerability.endLine || vulnerability.line || 1) - 1;

		// Additional validation: if we have originalCode, try to find the exact location
		if (vulnerability.originalCode && startLine >= 0 && startLine < document.lineCount) {
			const expectedLines = vulnerability.originalCode.split('\n').map(l => l.trim());
			const actualLines: string[] = [];
			
			for (let i = startLine; i <= Math.min(endLine, document.lineCount - 1); i++) {
				actualLines.push(document.lineAt(i).text.trim());
			}

			// Check if lines match
			let matches = true;
			if (expectedLines.length === actualLines.length) {
				for (let i = 0; i < expectedLines.length; i++) {
					if (expectedLines[i] !== actualLines[i]) {
						matches = false;
						break;
					}
				}
			} else {
				matches = false;
			}

			// If no match, try to find the correct location
			if (!matches) {
				console.warn(`[FIX] Line mismatch at ${startLine + 1}, searching for correct location...`);
				let found = false;
				
				// Search in a window around the expected line
				const searchRadius = 10;
				const searchStart = Math.max(0, startLine - searchRadius);
				const searchEnd = Math.min(document.lineCount - expectedLines.length, startLine + searchRadius);
				
				for (let searchLine = searchStart; searchLine <= searchEnd; searchLine++) {
					let searchMatches = true;
					for (let i = 0; i < expectedLines.length; i++) {
						if (searchLine + i >= document.lineCount || 
							document.lineAt(searchLine + i).text.trim() !== expectedLines[i]) {
							searchMatches = false;
							break;
						}
					}
					
					if (searchMatches) {
						console.log(`[FIX] Found correct location at line ${searchLine + 1} (was ${startLine + 1})`);
						startLine = searchLine;
						endLine = searchLine + expectedLines.length - 1;
						found = true;
						break;
					}
				}
				
				if (!found && !silent) {
					const proceed = await vscode.window.showWarningMessage(
						`Could not find exact code match near line ${vulnerability.line}. The file may have changed. Apply fix anyway?`,
						'Apply at original line', 'Cancel'
					);
					if (proceed !== 'Apply at original line') { 
						return false; 
					}
				} else if (!found) {
					console.error(`[FIX] Could not locate code for fix at line ${vulnerability.line}`);
					return false;
				}
			}
		}

		// Validate line numbers are within document bounds
		if (startLine < 0 || startLine >= document.lineCount) {
			if (!silent) {
				vscode.window.showWarningMessage(
					`Invalid line number ${vulnerability.line}. The file may have changed since scanning. Please re-scan.`
				);
			}
			return false;
		}

		const clampedEndLine = Math.min(endLine, document.lineCount - 1);

		// Build the range from start of startLine to end of endLine
		const range = new vscode.Range(
			new vscode.Position(startLine, 0),
			new vscode.Position(clampedEndLine, document.lineAt(clampedEndLine).text.length)
		);

		// Check if the code at these lines looks like what we expect (sanity check)
		if (vulnerability.originalCode) {
			const currentCode = document.getText(range);
			const currentTrimmed = currentCode.replace(/\s+/g, '');
			const originalTrimmed = vulnerability.originalCode.replace(/\s+/g, '');

			// If less than 50% similar after whitespace normalization, warn but still try
			if (currentTrimmed.length > 0 && originalTrimmed.length > 0) {
				const similarity = computeOverlap(currentTrimmed, originalTrimmed);
				if (similarity < 0.5) {
					if (!silent) {
						const proceed = await vscode.window.showWarningMessage(
							`The code at lines ${vulnerability.line}-${vulnerability.endLine || vulnerability.line} has changed since scanning. Apply fix anyway?`,
							'Apply', 'Cancel'
						);
						if (proceed !== 'Apply') { return false; }
					} else {
						// In silent (batch) mode, skip fixes with low confidence
						console.warn(`[FIX] Skipping fix at line ${vulnerability.line}: code has changed`);
						return false;
					}
				}
			}
		}

		// Preserve indentation: detect the base indentation from the first line
		const firstLineText = document.lineAt(startLine).text;
		const baseIndent = firstLineText.match(/^(\s*)/)?.[1] || '';
		
		// Apply base indentation to each line of the fixed code
		const fixedCodeLines = fixedCode.split('\n');
		const indentedFixedCode = fixedCodeLines.map((line, index) => {
			// Skip empty lines
			if (line.trim() === '') { return line; }
			
			// For the first line, detect if it already has indentation
			if (index === 0) {
				const fixedLineIndent = line.match(/^(\s*)/)?.[1] || '';
				// If fixed code has no indentation, add base indent
				if (fixedLineIndent === '') {
					return baseIndent + line;
				}
				// If fixed code has indentation, preserve it (it might be relative)
				return line;
			}
			
			// For subsequent lines, detect relative indentation
			const fixedLineIndent = line.match(/^(\s*)/)?.[1] || '';
			const firstFixedLineIndent = fixedCodeLines[0].match(/^(\s*)/)?.[1] || '';
			
			// Calculate relative indentation from the first fixed line
			const relativeIndent = fixedLineIndent.slice(firstFixedLineIndent.length);
			return baseIndent + relativeIndent + line.trim();
		}).join('\n');

		// Apply the fix using line-based replacement
		const edit = new vscode.WorkspaceEdit();
		edit.replace(document.uri, range, indentedFixedCode);

		isPatchingInProgress = true;
		try {
			const success = await vscode.workspace.applyEdit(edit);

			if (success) {
				await document.save();
				if (!silent) {
					const vulnType = vulnerability.type || 'vulnerability';
					vscode.window.showInformationMessage(
						`✅ Fixed ${vulnType} at line ${vulnerability.line} in ${path.basename(filePath)}`
					);
				}
				return true;
			} else {
				if (!silent) { vscode.window.showErrorMessage('Failed to apply fix.'); }
				return false;
			}
		} finally {
			setTimeout(() => { isPatchingInProgress = false; }, 500);
		}
	} catch (error) {
		if (!silent) { vscode.window.showErrorMessage(`Error applying fix: ${error}`); }
		return false;
	}
}

/**
 * Compute overlap ratio between two strings (0-1)
 */
function computeOverlap(a: string, b: string): number {
	const longer = a.length > b.length ? a : b;
	const shorter = a.length > b.length ? b : a;
	if (longer.length === 0) { return 1; }
	let matches = 0;
	let shortIdx = 0;
	for (let i = 0; i < longer.length && shortIdx < shorter.length; i++) {
		if (longer[i] === shorter[shortIdx]) { matches++; shortIdx++; }
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
}

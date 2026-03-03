import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { VulnerabilityTreeDataProvider, Vulnerability, VulnerabilityItem } from './vulnerabilityTree';

const BACKEND_URL = 'http://localhost:5000';

// Global reference to the tree provider
let vulnerabilityProvider: VulnerabilityTreeDataProvider;

// This method is called when your extension is activated
export function activate(context: vscode.ExtensionContext) {
	console.log('Cerberus security extension is now active!');

	// Create and register the tree data provider
	vulnerabilityProvider = new VulnerabilityTreeDataProvider();
	vscode.window.createTreeView('cerberus.vulnerabilityView', {
		treeDataProvider: vulnerabilityProvider,
		showCollapseAll: true,
	});

	// Register the scan command - scans the currently active file
	const scanDisposable = vscode.commands.registerCommand('cerberus.scan', async () => {
		// Get the active text editor
		const activeEditor = vscode.window.activeTextEditor;
		if (!activeEditor) {
			vscode.window.showErrorMessage('Please open a file to scan.');
			return;
		}

		const filePath = activeEditor.document.uri.fsPath;
		const fileName = path.basename(filePath);

		vscode.window.showInformationMessage(`🔍 Cerberus: Scanning ${fileName}...`);

		try {
			// Read the file content
			const code = activeEditor.document.getText();

			// Call the backend server to scan this specific file
			const response = await axios.post(`${BACKEND_URL}/api/scan-file`, {
				path: filePath,
				code: code
			}, {
				timeout: 60000 // 1 minute timeout for single file
			});

			// Extract vulnerabilities from response
			const data = response.data;
			const vulnerabilities: Vulnerability[] = data.vulnerabilities || [];

			// Update the tree view with results
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
		} catch (error: any) {
			let errorMessage = `❌ Cerberus: Failed to connect to backend server at ${BACKEND_URL}.`;

			if (error.code === 'ECONNREFUSED') {
				errorMessage += ' Is the server running? (npm run server:start)';
			} else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
				errorMessage += ' Request timed out. The scan may be taking too long.';
			} else if (error.response) {
				// Server responded with error status
				errorMessage += ` Server error: ${error.response.status} - ${JSON.stringify(error.response.data)}`;
			} else if (error.request) {
				// Request was made but no response
				errorMessage += ' No response from server.';
			} else {
				errorMessage += ` ${error.message}`;
			}

			vscode.window.showErrorMessage(errorMessage);
			console.error('Scan error details:', error);
		}
	});

	// Register the fix command - applies fix to currently active file
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

	// Register command to fix all vulnerabilities in a file
	const fixFileDisposable = vscode.commands.registerCommand('cerberus.fixFile', async (item?: VulnerabilityItem) => {
		if (!item) {
			vscode.window.showWarningMessage('Please select a file from the Cerberus panel.');
			return;
		}

		// Get all vulnerabilities for this file
		const fileVulns = vulnerabilityProvider.getVulnerabilitiesForFile(item.label);

		if (fileVulns.length === 0) {
			vscode.window.showWarningMessage('No vulnerabilities found for this file.');
			return;
		}

		// Apply the first available fix (or we could merge multiple fixes)
		const fixableVuln = fileVulns.find(v => v.status === 'analyzed' && v.result);
		if (!fixableVuln) {
			vscode.window.showErrorMessage('No fixes available for this file.');
			return;
		}

		await applyFix(fixableVuln.file, fixableVuln.result!);
	});

	// Register the view results command
	const viewDisposable = vscode.commands.registerCommand('cerberus.viewResults', () => {
		vscode.commands.executeCommand('cerberus.vulnerabilityView.focus');
	});

	context.subscriptions.push(scanDisposable, fixDisposable, fixFileDisposable, viewDisposable);
}

async function applyFix(filePath: string, correctedCode: string) {
	try {
		// Check if file exists
		if (!fs.existsSync(filePath)) {
			vscode.window.showErrorMessage(`File not found: ${filePath}`);
			return;
		}

		// Open the document
		const document = await vscode.workspace.openTextDocument(filePath);
		const editor = await vscode.window.showTextDocument(document);

		// Create a workspace edit to replace the entire file content
		const edit = new vscode.WorkspaceEdit();
		const fullRange = new vscode.Range(
			document.positionAt(0),
			document.positionAt(document.getText().length)
		);

		edit.replace(document.uri, fullRange, correctedCode);

		// Apply the edit
		const success = await vscode.workspace.applyEdit(edit);

		if (success) {
			// Save the document
			await document.save();
			vscode.window.showInformationMessage(`✅ Fixed applied and saved: ${path.basename(filePath)}`);
		} else {
			vscode.window.showErrorMessage('Failed to apply fix.');
		}
	} catch (error) {
		vscode.window.showErrorMessage(`Error applying fix: ${error}`);
		console.error('Fix error:', error);
	}
}

export function deactivate() { }

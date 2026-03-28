/**
 * Diff Analyzer
 * Maps n8n vulnerability data to the format expected by the VSCode extension.
 * Falls back to basic diff detection if n8n returns empty vulnerability arrays.
 */

/**
 * Severity mapping from n8n types to extension severity levels
 */
const SEVERITY_MAP = {
  'SQL Injection': 'critical',
  'Command Injection': 'critical',
  'Insecure Deserialization': 'critical',
  'Hardcoded Credentials': 'high',
  'Path Traversal': 'high',
  'XSS (Cross-Site Scripting)': 'high',
  'Weak Cryptography': 'high',
  'Debug Mode Enabled': 'medium',
  'Insecure Random': 'medium',
  'Missing Input Validation': 'medium',
};

/**
 * Map n8n severity string to extension severity level
 */
function normalizeSeverity(severity, type) {
  if (!severity) return SEVERITY_MAP[type] || 'medium';
  const s = severity.toLowerCase();
  if (s === 'high' || s === 'critical') return SEVERITY_MAP[type] || 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'medium';
}

/**
 * Extract individual vulnerabilities from n8n response data.
 * Primary strategy: use n8n's per-vulnerability mappings directly.
 * Fallback: basic diff detection if n8n data is incomplete.
 *
 * @param {string} original - Original source code
 * @param {string} corrected - Corrected code from n8n
 * @param {string} filePath - File path for display
 * @param {Array} n8nVulnerabilities - Vulnerability array from n8n workflow
 * @param {Array} n8nVulnDetails - Vulnerability details from n8n (type + line)
 * @returns {Array} Vulnerability objects for the extension
 */
function extractVulnerabilities(original, corrected, filePath, n8nVulnerabilities = [], n8nVulnDetails = []) {

  // ── Strategy 1: Direct n8n vulnerability mapping ──────────────────────────
  if (n8nVulnerabilities && n8nVulnerabilities.length > 0) {
    console.log(`[DIFF] Mapping ${n8nVulnerabilities.length} vulnerabilities from n8n`);

    const vulns = n8nVulnerabilities.map(nv => {
      const originalCode = nv.original_code || nv.originalCode || '';
      const fixedCode = nv.fixed_code || nv.fixedCode || '';
      const lineNumber = nv.line_number || nv.line || 0;
      const type = nv.type || 'Security Issue';
      const severity = normalizeSeverity(nv.severity, type);
      const issueText = nv.issue_text || nv.fix_recommendation || `${type} detected`;

      // Resolve line number from code if not provided
      let line = lineNumber;
      if (!line && originalCode) {
        // Find the line by matching the trimmed code content line-by-line
        const originalLines = original.split('\n');
        const searchLines = originalCode.trim().split('\n');
        
        // Try to find exact match first
        for (let i = 0; i <= originalLines.length - searchLines.length; i++) {
          let match = true;
          for (let j = 0; j < searchLines.length; j++) {
            if (originalLines[i + j].trim() !== searchLines[j].trim()) {
              match = false;
              break;
            }
          }
          if (match) {
            line = i + 1; // Convert to 1-indexed
            break;
          }
        }
        
        // If no exact match, try finding by the first significant line
        if (!line && searchLines.length > 0) {
          const firstSignificantLine = searchLines[0].trim();
          if (firstSignificantLine) {
            for (let i = 0; i < originalLines.length; i++) {
              if (originalLines[i].trim() === firstSignificantLine) {
                line = i + 1; // Convert to 1-indexed
                console.warn(`[DIFF] Used fuzzy match for line number: ${line}`);
                break;
              }
            }
          }
        }
      }

      // Validate line number
      if (!line || line < 1) {
        console.error(`[DIFF] Invalid line number: ${line} for type: ${type}`);
        line = 1; // Fallback to line 1
      }

      const endLine = line + (originalCode ? originalCode.split('\n').length - 1 : 0);

      return {
        file: filePath,
        line,
        endLine,
        type,
        severity,
        description: `${type} at line ${line}: ${issueText}`,
        originalCode,
        fixedCode,
        status: 'analyzed',
        isFixed: false,
        result: fixedCode
      };
    });

    // Sort by line number
    vulns.sort((a, b) => a.line - b.line);
    return vulns;
  }

  // ── Strategy 2: Fallback — code changed but no vulnerability data ─────────
  if (original !== corrected) {
    console.log('[DIFF] No n8n vulnerability data, creating generic vulnerability from diff');
    return [{
      file: filePath,
      line: 1,
      endLine: original.split('\n').length,
      type: 'Security Issues',
      severity: 'medium',
      description: 'Multiple security improvements applied',
      originalCode: original,
      fixedCode: corrected,
      status: 'analyzed',
      isFixed: false,
      result: corrected
    }];
  }

  // No changes detected
  return [];
}

/**
 * Apply a specific vulnerability fix to the full file code.
 * Used by the /api/apply-individual-fix endpoint.
 *
 * @param {string} fullCode - Full file code
 * @param {Object} vulnerability - Vulnerability object with line, endLine, fixedCode
 * @returns {string} Code with the fix applied
 */
function applyIndividualFix(fullCode, vulnerability) {
  const lines = fullCode.split('\n');
  const fixedLines = vulnerability.fixedCode.split('\n');

  const startIdx = (vulnerability.line || 1) - 1;
  const endIdx = (vulnerability.endLine || vulnerability.line || 1) - 1;
  const deleteCount = endIdx - startIdx + 1;

  lines.splice(startIdx, deleteCount, ...fixedLines);

  return lines.join('\n');
}

module.exports = {
  extractVulnerabilities,
  applyIndividualFix,
  normalizeSeverity,
  SEVERITY_MAP
};

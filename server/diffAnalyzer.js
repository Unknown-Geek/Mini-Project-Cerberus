/**
 * Diff Analyzer
 * Compares original and corrected code to extract individual vulnerabilities
 */

/**
 * Known vulnerability patterns to detect and categorize
 */
const VULNERABILITY_PATTERNS = [
  {
    type: 'SQL Injection',
    severity: 'critical',
    patterns: [
      /execute\s*\(\s*["'`].*%s.*["'`]\s*%/,
      /execute\s*\(\s*f["'`]/,
      /execute\s*\(\s*["'`].*\+.*["'`]/,
      /cursor\.execute\s*\(\s*query\s*\)/,
    ],
    fixPatterns: [/execute\s*\(\s*\w+\s*,\s*\(/]
  },
  {
    type: 'Command Injection',
    severity: 'critical',
    patterns: [
      /subprocess\.call\s*\([^)]*shell\s*=\s*True/,
      /subprocess\.run\s*\([^)]*shell\s*=\s*True/,
      /os\.system\s*\(/,
      /os\.popen\s*\(/,
      /subprocess\.Popen\s*\([^)]*shell\s*=\s*True/,
    ],
    fixPatterns: [/subprocess\.run\s*\(\s*\[/, /with\s+open\s*\(/]
  },
  {
    type: 'Insecure Deserialization',
    severity: 'critical',
    patterns: [
      /pickle\.loads?\s*\(/,
      /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)/,
      /marshal\.loads?\s*\(/,
    ],
    fixPatterns: [/json\.loads?\s*\(/, /yaml\.safe_load\s*\(/]
  },
  {
    type: 'Hardcoded Credentials',
    severity: 'high',
    patterns: [
      /(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["'][^"']+["']/i,
      /(?:PASSWORD|API_KEY|SECRET)\s*=\s*["'][^"']+["']/,
    ],
    fixPatterns: [/os\.getenv\s*\(/, /os\.environ\.get\s*\(/]
  },
  {
    type: 'Path Traversal',
    severity: 'high',
    patterns: [
      /open\s*\(\s*(?:request\.|user_input|filename|file_path)/,
      /os\.path\.join\s*\([^)]*(?:request\.|user_input)/,
    ],
    fixPatterns: [/os\.path\.basename\s*\(/, /os\.path\.abspath\s*\(/]
  },
  {
    type: 'XSS (Cross-Site Scripting)',
    severity: 'high',
    patterns: [
      /return\s*["'`]<[^>]+>.*\+.*(?:request\.|name|user)/,
      /\.format\s*\(\s*(?:request\.|name|user)/,
      /f["'`]<[^>]+>.*\{.*(?:request\.|name|user)/,
    ],
    fixPatterns: [/escape\s*\(/, /html\.escape\s*\(/, /markupsafe\.escape\s*\(/]
  },
  {
    type: 'Debug Mode Enabled',
    severity: 'medium',
    patterns: [
      /debug\s*=\s*True/i,
      /DEBUG\s*=\s*True/,
    ],
    fixPatterns: [/debug\s*=\s*False/i]
  },
  {
    type: 'Insecure Random',
    severity: 'medium',
    patterns: [
      /random\.random\s*\(/,
      /random\.randint\s*\(/,
    ],
    fixPatterns: [/secrets\./, /os\.urandom\s*\(/]
  },
  {
    type: 'Missing Input Validation',
    severity: 'medium',
    patterns: [
      /request\.args\.get\s*\([^)]+\)\s*(?!\s*(?:if|and|or|\?|is))/,
    ],
    fixPatterns: [/if\s+\w+\s+is\s+None/, /if\s+not\s+\w+/]
  }
];

/**
 * Simple line-by-line diff to find changes between original and corrected code
 * @param {string} original - Original code
 * @param {string} corrected - Corrected code
 * @returns {Array} Array of change objects
 */
function computeLineDiff(original, corrected) {
  const originalLines = original.split('\n');
  const correctedLines = corrected.split('\n');
  const changes = [];

  // Use longest common subsequence approach for better diff
  const lcs = computeLCS(originalLines, correctedLines);

  let origIdx = 0;
  let corrIdx = 0;
  let lcsIdx = 0;

  while (origIdx < originalLines.length || corrIdx < correctedLines.length) {
    if (lcsIdx < lcs.length &&
        origIdx < originalLines.length &&
        corrIdx < correctedLines.length &&
        originalLines[origIdx] === lcs[lcsIdx] &&
        correctedLines[corrIdx] === lcs[lcsIdx]) {
      // Lines match - no change
      origIdx++;
      corrIdx++;
      lcsIdx++;
    } else if (corrIdx < correctedLines.length &&
               (lcsIdx >= lcs.length || correctedLines[corrIdx] !== lcs[lcsIdx])) {
      // Line was added or modified
      if (origIdx < originalLines.length &&
          (lcsIdx >= lcs.length || originalLines[origIdx] !== lcs[lcsIdx])) {
        // Modified line
        changes.push({
          type: 'modified',
          originalLine: origIdx + 1,
          correctedLine: corrIdx + 1,
          original: originalLines[origIdx],
          corrected: correctedLines[corrIdx]
        });
        origIdx++;
        corrIdx++;
      } else {
        // Added line
        changes.push({
          type: 'added',
          correctedLine: corrIdx + 1,
          corrected: correctedLines[corrIdx]
        });
        corrIdx++;
      }
    } else if (origIdx < originalLines.length) {
      // Line was removed
      changes.push({
        type: 'removed',
        originalLine: origIdx + 1,
        original: originalLines[origIdx]
      });
      origIdx++;
    }
  }

  return changes;
}

/**
 * Compute Longest Common Subsequence of two arrays
 */
function computeLCS(arr1, arr2) {
  const m = arr1.length;
  const n = arr2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (arr1[i - 1] === arr2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack to find LCS
  const lcs = [];
  let i = m, j = n;
  while (i > 0 && j > 0) {
    if (arr1[i - 1] === arr2[j - 1]) {
      lcs.unshift(arr1[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  return lcs;
}

/**
 * Group consecutive changes into vulnerability blocks
 */
function groupChangesIntoBlocks(changes) {
  if (changes.length === 0) return [];

  const blocks = [];
  let currentBlock = {
    startLine: changes[0].originalLine || changes[0].correctedLine,
    endLine: changes[0].originalLine || changes[0].correctedLine,
    changes: [changes[0]]
  };

  for (let i = 1; i < changes.length; i++) {
    const change = changes[i];
    const changeLine = change.originalLine || change.correctedLine;

    // If this change is within 3 lines of the previous, group them
    if (changeLine - currentBlock.endLine <= 3) {
      currentBlock.endLine = changeLine;
      currentBlock.changes.push(change);
    } else {
      blocks.push(currentBlock);
      currentBlock = {
        startLine: changeLine,
        endLine: changeLine,
        changes: [change]
      };
    }
  }
  blocks.push(currentBlock);

  return blocks;
}

/**
 * Detect vulnerability type from code context
 */
function detectVulnerabilityType(originalCode, correctedCode, lineNumber, fullOriginal) {
  // Get surrounding context (5 lines before and after)
  const originalLines = fullOriginal.split('\n');
  const startContext = Math.max(0, lineNumber - 5);
  const endContext = Math.min(originalLines.length, lineNumber + 5);
  const context = originalLines.slice(startContext, endContext).join('\n');

  for (const vulnPattern of VULNERABILITY_PATTERNS) {
    // Check if original matches vulnerability pattern
    for (const pattern of vulnPattern.patterns) {
      if (pattern.test(originalCode) || pattern.test(context)) {
        // Verify fix was applied
        for (const fixPattern of vulnPattern.fixPatterns) {
          if (fixPattern.test(correctedCode)) {
            return {
              type: vulnPattern.type,
              severity: vulnPattern.severity
            };
          }
        }
        // Even without fix pattern match, if original had vuln, return it
        return {
          type: vulnPattern.type,
          severity: vulnPattern.severity
        };
      }
    }
  }

  // Check for import removals (like subprocess)
  if (/^import\s+subprocess/.test(originalCode) && !correctedCode.includes('subprocess')) {
    return { type: 'Command Injection', severity: 'critical' };
  }

  // Check for added checks/validation
  if (correctedCode.includes('if') && correctedCode.includes('None')) {
    return { type: 'Missing Input Validation', severity: 'medium' };
  }

  return { type: 'Security Issue', severity: 'medium' };
}

/**
 * Extract individual vulnerabilities from original and corrected code
 * @param {string} original - Original code
 * @param {string} corrected - Corrected code
 * @param {string} filePath - Path to the file
 * @returns {Array} Array of vulnerability objects
 */
function extractVulnerabilities(original, corrected, filePath) {
  if (original === corrected) {
    return []; // No changes means no vulnerabilities found
  }

  const changes = computeLineDiff(original, corrected);
  const blocks = groupChangesIntoBlocks(changes);

  const vulnerabilities = [];

  for (const block of blocks) {
    // Get original and corrected code for this block
    const originalCode = block.changes
      .filter(c => c.original)
      .map(c => c.original)
      .join('\n');

    const correctedCode = block.changes
      .filter(c => c.corrected)
      .map(c => c.corrected)
      .join('\n');

    // Skip if only whitespace/formatting changes
    if (originalCode.replace(/\s/g, '') === correctedCode.replace(/\s/g, '')) {
      continue;
    }

    // Detect vulnerability type
    const { type, severity } = detectVulnerabilityType(
      originalCode,
      correctedCode,
      block.startLine,
      original
    );

    // Build description
    let description = `${type} vulnerability detected`;
    if (block.startLine === block.endLine) {
      description += ` at line ${block.startLine}`;
    } else {
      description += ` at lines ${block.startLine}-${block.endLine}`;
    }

    vulnerabilities.push({
      file: filePath,
      line: block.startLine,
      endLine: block.endLine,
      type: type,
      severity: severity,
      description: description,
      originalCode: originalCode,
      fixedCode: correctedCode,
      status: 'analyzed'
    });
  }

  return vulnerabilities;
}

/**
 * Generate a consolidated fix for a specific vulnerability
 * @param {string} fullCode - Full file code
 * @param {Object} vulnerability - Vulnerability object
 * @returns {string} Code with just this fix applied
 */
function applyIndividualFix(fullCode, vulnerability) {
  const lines = fullCode.split('\n');
  const originalLines = vulnerability.originalCode.split('\n');
  const fixedLines = vulnerability.fixedCode.split('\n');

  // Replace lines from startLine to endLine with fixed code
  const startIdx = vulnerability.line - 1;
  const deleteCount = vulnerability.endLine - vulnerability.line + 1;

  lines.splice(startIdx, deleteCount, ...fixedLines);

  return lines.join('\n');
}

module.exports = {
  extractVulnerabilities,
  applyIndividualFix,
  computeLineDiff,
  groupChangesIntoBlocks,
  detectVulnerabilityType,
  VULNERABILITY_PATTERNS
};

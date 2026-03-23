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
      /execute\s*\(\s*["']SELECT.*\+/i,
      /execute\s*\(\s*["']INSERT.*\+/i,
      /execute\s*\(\s*["']UPDATE.*\+/i,
      /execute\s*\(\s*["']DELETE.*\+/i,
    ],
    fixPatterns: [/execute\s*\(\s*\w+\s*,\s*\(/, /execute\s*\(\s*\w+\s*,\s*\[/],
    commentMarker: /vulnerability.*sql\s*injection/i
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
      /import\s+subprocess/,
    ],
    fixPatterns: [/subprocess\.run\s*\(\s*\[/, /with\s+open\s*\(/],
    commentMarker: /vulnerability.*command\s*injection/i
  },
  {
    type: 'Insecure Deserialization',
    severity: 'critical',
    patterns: [
      /pickle\.loads?\s*\(/,
      /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)/,
      /marshal\.loads?\s*\(/,
      /yaml\.unsafe_load/,
    ],
    fixPatterns: [/json\.loads?\s*\(/, /yaml\.safe_load\s*\(/],
    commentMarker: /vulnerability.*deserialization/i
  },
  {
    type: 'Hardcoded Credentials',
    severity: 'high',
    patterns: [
      /(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{4,}["']/i,
      /(?:PASSWORD|API_KEY|SECRET|TOKEN)\s*=\s*["'][^"']{4,}["']/,
    ],
    fixPatterns: [/os\.getenv\s*\(/, /os\.environ\.get\s*\(/, /os\.environ\[/],
    commentMarker: /vulnerability.*(?:hardcoded|credential)/i
  },
  {
    type: 'Path Traversal',
    severity: 'high',
    patterns: [
      /open\s*\(\s*(?:request\.|user_input|filename|file_path|filepath)/,
      /os\.path\.join\s*\([^)]*(?:request\.|user_input)/,
      /open\s*\(\s*\w+\s*\)(?!.*basename)/,
    ],
    fixPatterns: [/os\.path\.basename\s*\(/, /os\.path\.abspath\s*\(/],
    commentMarker: /vulnerability.*path\s*traversal/i
  },
  {
    type: 'XSS (Cross-Site Scripting)',
    severity: 'high',
    patterns: [
      /return\s*["'`]<[^>]+>.*\+.*(?:request\.|name|user)/,
      /\.format\s*\(\s*(?:request\.|name|user)/,
      /f["'`]<[^>]+>.*\{.*(?:request\.|name|user)/,
      /return\s*['"].*['"].*\+.*request\./,
    ],
    fixPatterns: [/escape\s*\(/, /html\.escape\s*\(/, /markupsafe\.escape\s*\(/],
    commentMarker: /vulnerability.*xss|cross.site.scripting/i
  },
  {
    type: 'Debug Mode Enabled',
    severity: 'medium',
    patterns: [
      /app\.run\s*\([^)]*debug\s*=\s*True/i,
      /DEBUG\s*=\s*True/,
    ],
    fixPatterns: [/debug\s*=\s*False/i],
    commentMarker: /vulnerability.*debug/i
  },
  {
    type: 'Insecure Random',
    severity: 'medium',
    patterns: [
      /random\.random\s*\(/,
      /random\.randint\s*\(/,
      /random\.choice\s*\(/,
    ],
    fixPatterns: [/secrets\./, /os\.urandom\s*\(/],
    commentMarker: /vulnerability.*random/i
  },
  {
    type: 'Missing Input Validation',
    severity: 'medium',
    patterns: [
      /request\.args\.get\s*\([^)]+\)\s*$/,
      /request\.form\.get\s*\([^)]+\)\s*$/,
    ],
    fixPatterns: [/if\s+\w+\s+is\s+None/, /if\s+not\s+\w+/],
    commentMarker: /vulnerability.*validation/i
  }
];

/**
 * Scan code for vulnerability patterns and comments
 * Returns vulnerabilities found via pattern matching
 */
function scanForVulnerabilityPatterns(code, filePath) {
  const lines = code.split('\n');
  const vulnerabilities = [];
  const foundVulnTypes = new Set();

  // First pass: look for vulnerability comments (# Vulnerability X: Type)
  const vulnCommentRegex = /#\s*vulnerability\s*(\d+)?:?\s*(.+)/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(vulnCommentRegex);

    if (match) {
      const vulnDescription = match[2].trim();

      // Find the vulnerability type from description
      let vulnType = 'Security Issue';
      let severity = 'medium';

      for (const pattern of VULNERABILITY_PATTERNS) {
        if (pattern.commentMarker && pattern.commentMarker.test(vulnDescription)) {
          vulnType = pattern.type;
          severity = pattern.severity;
          break;
        }
      }

      // Check if already fixed (comment contains "FIXED" or "mitigated")
      const isFixed = /fixed|mitigated|already/i.test(vulnDescription);

      // Find the end of this vulnerability block (next comment or significant gap)
      let endLine = i + 1;
      for (let j = i + 1; j < lines.length && j < i + 20; j++) {
        if (lines[j].match(vulnCommentRegex) || lines[j].match(/^#\s*vulnerability/i)) {
          break;
        }
        if (lines[j].trim()) {
          endLine = j + 1;
        }
      }

      // Extract the code block
      const codeBlock = lines.slice(i, endLine).join('\n');

      vulnerabilities.push({
        file: filePath,
        line: i + 1,
        endLine: endLine,
        type: vulnType,
        severity: severity,
        description: `${vulnType}${isFixed ? ' (Fixed)' : ''} at line ${i + 1}`,
        originalCode: codeBlock,
        fixedCode: codeBlock, // Will be updated if AI provides a fix
        status: 'analyzed',
        isFixed: isFixed
      });

      foundVulnTypes.add(vulnType);
    }
  }

  return vulnerabilities;
}

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
 * Uses both comment-based detection and diff-based detection
 * @param {string} original - Original code
 * @param {string} corrected - Corrected code
 * @param {string} filePath - Path to the file
 * @returns {Array} Array of vulnerability objects
 */
function extractVulnerabilities(original, corrected, filePath) {
  // First, scan for vulnerability comments in the original code
  const commentVulns = scanForVulnerabilityPatterns(original, filePath);

  // If code is identical, return just the comment-based vulnerabilities
  if (original === corrected) {
    return commentVulns;
  }

  const originalLines = original.split('\n');
  const correctedLines = corrected.split('\n');
  const changes = computeLineDiff(original, corrected);
  const blocks = groupChangesIntoBlocks(changes);

  // Track which comment-based vulns have been matched with fixes
  const matchedVulnIndices = new Set();

  // Process diff blocks and try to match with comment-based vulnerabilities
  for (const block of blocks) {
    const startIdx = block.startLine - 1;
    const endIdx = block.endLine;

    const originalBlockLines = originalLines.slice(startIdx, endIdx);
    const originalCode = originalBlockLines.join('\n');

    const correctedCode = block.changes
      .filter(c => c.corrected !== undefined)
      .map(c => c.corrected)
      .join('\n');

    // Skip if only whitespace changes
    if (originalCode.replace(/\s/g, '') === correctedCode.replace(/\s/g, '')) {
      continue;
    }

    // Try to match this block with a comment-based vulnerability
    let matched = false;
    for (let i = 0; i < commentVulns.length; i++) {
      if (matchedVulnIndices.has(i)) continue;

      const vuln = commentVulns[i];
      // Check if this block overlaps with the vulnerability's line range
      if ((block.startLine >= vuln.line && block.startLine <= vuln.endLine) ||
          (block.endLine >= vuln.line && block.endLine <= vuln.endLine) ||
          (block.startLine <= vuln.line && block.endLine >= vuln.endLine)) {
        // Update the vulnerability with the actual fix
        vuln.originalCode = originalCode;
        vuln.fixedCode = correctedCode;
        vuln.isFixed = false; // It has a pending fix
        vuln.description = `${vuln.type} at line ${vuln.line}`;
        matchedVulnIndices.add(i);
        matched = true;
        break;
      }
    }

    // If no match found, create a new vulnerability from the diff
    if (!matched) {
      const { type, severity } = detectVulnerabilityType(
        originalCode,
        correctedCode,
        block.startLine,
        original
      );

      let description = `${type} detected`;
      if (block.startLine === block.endLine) {
        description += ` at line ${block.startLine}`;
      } else {
        description += ` at lines ${block.startLine}-${block.endLine}`;
      }

      commentVulns.push({
        file: filePath,
        line: block.startLine,
        endLine: block.endLine,
        type: type,
        severity: severity,
        description: description,
        originalCode: originalCode,
        fixedCode: correctedCode,
        status: 'analyzed',
        isFixed: false
      });
    }
  }

  // Sort by line number
  commentVulns.sort((a, b) => a.line - b.line);

  return commentVulns;
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
  scanForVulnerabilityPatterns,
  computeLineDiff,
  groupChangesIntoBlocks,
  detectVulnerabilityType,
  VULNERABILITY_PATTERNS
};

/**
 * API Routes
 * Express routes for the Cerberus security scanner API
 */

const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { glob } = require('glob');
const rateLimit = require('express-rate-limit');
const {
  patchCodeViaN8n,
  N8NWebhookTimeoutError,
  N8NWebhookUpstreamError,
  N8NWebhookResponseError
} = require('./n8nClient');
const {
  extractVulnerabilities,
  applyIndividualFix
} = require('./diffAnalyzer');

const router = express.Router();

// Rate limiting for scan endpoint (10 requests per 15 minutes per IP)
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Too many scan requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Validate and sanitize folder path to prevent directory traversal
 * @param {string} inputPath - The user-provided path
 * @returns {Object} - { isValid: boolean, resolvedPath?: string, error?: string }
 */
function validateScanPath(inputPath) {
  // Check for null bytes and path traversal attempts
  if (inputPath.includes('\0')) {
    return { isValid: false, error: 'Path contains null bytes' };
  }

  // Resolve the absolute path
  const resolvedPath = path.resolve(inputPath);

  // Define allowed base directory (default to current working directory)
  const allowedBase = path.resolve(process.env.SCAN_BASE_PATH || process.cwd());

  // Ensure the resolved path is within the allowed base directory
  if (!resolvedPath.startsWith(allowedBase)) {
    return { isValid: false, error: 'Path is outside allowed directory' };
  }

  return { isValid: true, resolvedPath };
}

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

/**
 * POST /api/patch-code
 * Send code to n8n for vulnerability analysis and correction
 */
router.post('/api/patch-code', async (req, res) => {
  // Validate request is JSON
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'code': 'raw python string'}"
    });
  }

  const { code } = req.body;

  // Validate code field
  if (typeof code !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'code' is required and must be a string."
    });
  }

  console.log(`Processing patch request code_length=${code.length}`);

  try {
    const correctedCode = await patchCodeViaN8n({
      code,
      webhookUrl: process.env.N8N_WEBHOOK_URL,
      timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '20')
    });

    return res.json({ corrected_code: correctedCode });
  } catch (error) {
    console.error('n8n webhook call failed:', error);

    if (error instanceof N8NWebhookTimeoutError ||
      error instanceof N8NWebhookUpstreamError ||
      error instanceof N8NWebhookResponseError) {
      return res.status(502).json({
        error: 'Bad Gateway',
        message: 'Unable to retrieve corrected code from n8n webhook.'
      });
    }

    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'An unexpected error occurred.'
    });
  }
});

// Rate limiting for real-time snippet patching (30 requests per minute per IP)
const snippetLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: {
    error: 'Too many requests',
    message: 'Too many snippet patch requests, please slow down'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * POST /api/patch-snippet
 * Real-time snippet patching — receives a code snippet, sends to n8n, returns patched version
 */
router.post('/api/patch-snippet', snippetLimiter, async (req, res) => {
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON"
    });
  }

  const { snippet, filePath, startLine, endLine, fullFileContext } = req.body;

  if (typeof snippet !== 'string' || snippet.trim().length === 0) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'snippet' is required and must be a non-empty string."
    });
  }

  console.log(`[SNIPPET] Patching ${path.basename(filePath || 'unknown')} lines ${startLine}-${endLine} (${snippet.length} chars)`);

  try {
    const patchedSnippet = await patchCodeViaN8n({
      code: snippet,
      webhookUrl: process.env.N8N_WEBHOOK_URL,
      timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120')
    });

    const hasChanges = patchedSnippet !== snippet;

    return res.json({
      patched_snippet: patchedSnippet,
      has_changes: hasChanges
    });
  } catch (error) {
    console.error('[SNIPPET] n8n call failed:', error.message);

    if (error instanceof N8NWebhookTimeoutError ||
      error instanceof N8NWebhookUpstreamError ||
      error instanceof N8NWebhookResponseError) {
      return res.status(502).json({
        error: 'Bad Gateway',
        message: 'Unable to patch snippet via n8n.'
      });
    }

    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'An unexpected error occurred.'
    });
  }
});

/**
 * POST /api/scan
 * Scan a folder for vulnerabilities
 */
router.post('/api/scan', scanLimiter, async (req, res) => {
  // Validate request is JSON
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'path': 'folder path'}"
    });
  }

  const { path: folderPath } = req.body;

  // Validate path field
  if (typeof folderPath !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'path' is required and must be a string."
    });
  }

  // Resolve the path (allow any directory for local testing)
  const sanitizedPath = path.resolve(folderPath);

  // Check if path exists and is a directory
  try {
    const stats = await fs.stat(sanitizedPath);
    if (!stats.isDirectory()) {
      return res.status(400).json({
        error: 'Invalid path',
        message: `Path is not a directory: ${folderPath}`
      });
    }
  } catch (error) {
    return res.status(400).json({
      error: 'Invalid path',
      message: `Path does not exist or is not a directory: ${folderPath}`
    });
  }

  console.log(`Scanning folder: ${sanitizedPath}`);

  // Collect all code files
  const extensions = ['*.py', '*.js', '*.ts', '*.tsx', '*.jsx', '*.java', '*.go', '*.rb', '*.php'];
  const codeFiles = [];

  for (const ext of extensions) {
    const pattern = path.join(sanitizedPath, '**', ext).replace(/\\/g, '/');
    const files = await glob(pattern, { nodir: true });
    codeFiles.push(...files);
  }

  const vulnerabilities = [];

  // Scan each file
  for (const filePath of codeFiles) {
    try {
      const code = await fs.readFile(filePath, 'utf-8');
      console.log(`Analyzing file: ${filePath}`);

      try {
        const result = await patchCodeViaN8n({
          code,
          webhookUrl: process.env.N8N_WEBHOOK_URL,
          timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '20')
        });

        vulnerabilities.push({
          file: filePath,
          status: 'analyzed',
          result
        });
      } catch (error) {
        if (error instanceof N8NWebhookTimeoutError ||
          error instanceof N8NWebhookUpstreamError ||
          error instanceof N8NWebhookResponseError) {
          vulnerabilities.push({
            file: filePath,
            status: 'error',
            error: error.message
          });
        } else {
          throw error;
        }
      }
    } catch (error) {
      console.error(`Error reading file ${filePath}:`, error.message);
      vulnerabilities.push({
        file: filePath,
        status: 'error',
        error: error.message
      });
    }
  }

  return res.json({
    scan_complete: true,
    files_scanned: codeFiles.length,
    vulnerabilities
  });
});

// ── Chunking helper ──────────────────────────────────────────────────────────
// Splits code into line-based chunks that target MAX_CHUNK_CHARS characters
// each, so every n8n call stays well under a reverse-proxy 60-second timeout.
const MAX_CHUNK_CHARS = parseInt(process.env.MAX_CHUNK_CHARS || '1500', 10);
// Lines of previous chunk to prepend as context so the AI understands continuations
const OVERLAP_LINES = parseInt(process.env.OVERLAP_LINES || '5', 10);

// Responses the n8n AI emits when it can't make sense of a snippet
const BOGUS_PATTERNS = [
  /^$/,                          // empty string
  /INSERT_ORIGINAL_CODE_HERE/i,  // literal placeholder
  /^null$/i,                     // null string
  /^undefined$/i,
];

/**
 * Strip markdown code fences that the AI sometimes wraps responses in.
 * e.g.  ```python\n...\n```  →  just the inner code
 */
function stripMarkdownFences(code) {
  if (typeof code !== 'string') return code;
  // Match optional language tag: ```python\n...\n``` or ```\n...\n```
  const fenceMatch = code.match(/^\s*```[\w]*\n([\s\S]*?)\n```\s*$/);
  if (fenceMatch) return fenceMatch[1];
  // Also handle no trailing newline before closing fence
  const fenceMatch2 = code.match(/^\s*```[\w]*\n([\s\S]*?)```\s*$/);
  if (fenceMatch2) return fenceMatch2[1];
  return code;
}

/**
 * Return true if the n8n response should be discarded in favour of the original chunk.
 */
function isBogusResponse(original, corrected) {
  if (typeof corrected !== 'string') return true;
  const trimmed = corrected.trim();
  if (BOGUS_PATTERNS.some(re => re.test(trimmed))) return true;
  // If the response is less than 10% the length of a non-trivial chunk, it's likely garbage
  if (original.length > 100 && trimmed.length < original.length * 0.10) return true;
  return false;
}

/**
 * Split code into chunks of ~targetChars characters, aligned to line boundaries.
 * @param {string} code
 * @param {number} targetChars
 * @returns {{ lines: string[], startLine: number }[]}
 */
function chunkCode(code, targetChars) {
  const lines = code.split('\n');
  const avgLen = Math.max(1, code.length / lines.length);
  const linesPerChunk = Math.max(20, Math.round(targetChars / avgLen));

  const chunks = [];
  for (let i = 0; i < lines.length; i += linesPerChunk) {
    chunks.push({ lines: lines.slice(i, i + linesPerChunk), startLine: i });
  }
  return chunks;
}

/**
 * Scan a file, using chunked n8n calls when the file exceeds MAX_CHUNK_CHARS.
 * Each chunk is sent with OVERLAP_LINES of context from the previous chunk so
 * the AI understands mid-file continuations. Bogus responses are replaced with
 * the original chunk so no code is silently dropped.
 */
async function scanFileCode(code, filePath) {
  const timeoutSeconds = parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120');
  const webhookUrl = process.env.N8N_WEBHOOK_URL;

  if (code.length <= MAX_CHUNK_CHARS) {
    // Small file — single call
    let result = await patchCodeViaN8n({ code, webhookUrl, timeoutSeconds });
    result = stripMarkdownFences(result);
    if (isBogusResponse(code, result)) {
      console.warn(`[CHUNK] Single-call response looks bogus, keeping original`);
      return code;
    }
    return result;
  }

  // Large file — split into chunks, scan each, reassemble
  const allLines = code.split('\n');
  const chunks = chunkCode(code, MAX_CHUNK_CHARS);
  console.log(`[CHUNK] ${path.basename(filePath)}: ${code.length} chars → ${chunks.length} chunks (limit ${MAX_CHUNK_CHARS})`);

  const correctedLines = [...allLines]; // start with original; patch in place

  // lineOffset tracks how many lines have been added/removed by previous chunks
  // so we can splice at the correct adjusted position in correctedLines.
  let lineOffset = 0;

  for (let i = 0; i < chunks.length; i++) {
    const { lines: chunkLines, startLine } = chunks[i];
    const adjustedStart = startLine + lineOffset;
    const endLine = startLine + chunkLines.length - 1;

    // Prepend overlap context from the already-corrected lines above
    const contextLines = adjustedStart > 0
      ? correctedLines.slice(Math.max(0, adjustedStart - OVERLAP_LINES), adjustedStart)
      : [];
    const payload = [...contextLines, ...chunkLines].join('\n');

    console.log(`[CHUNK] Processing chunk ${i + 1}/${chunks.length} (lines ${startLine}-${endLine}, adjusted ${adjustedStart}, ${payload.length} chars, ${contextLines.length} context lines)`);

    try {
      let corrected = await patchCodeViaN8n({ code: payload, webhookUrl, timeoutSeconds });
      corrected = stripMarkdownFences(corrected);

      if (isBogusResponse(payload, corrected)) {
        console.warn(`[CHUNK] Chunk ${i + 1} response looks bogus, keeping original`);
        // correctedLines already has the original — nothing to do, offset unchanged
        continue;
      }

      // Strip the context lines back off the top of the response
      const correctedAllLines = corrected.split('\n');
      const stripped = contextLines.length > 0
        ? correctedAllLines.slice(contextLines.length)
        : correctedAllLines;

      // Write stripped result back into correctedLines at the adjusted position
      correctedLines.splice(adjustedStart, chunkLines.length, ...stripped);

      // Update offset: positive if AI added lines, negative if it removed them
      lineOffset += stripped.length - chunkLines.length;

    } catch (err) {
      console.warn(`[CHUNK] Chunk ${i + 1} failed (${err.message}), keeping original`);
    }
  }

  return correctedLines.join('\n');
}

// ── Temp result store ────────────────────────────────────────────────────────
const CERBERUS_TMP_DIR = path.join(os.tmpdir(), 'cerberus-results');

// Ensure temp dir exists (sync so it's ready before any request)
try { fsSync.mkdirSync(CERBERUS_TMP_DIR, { recursive: true }); } catch {}

/**
 * Persist corrected code to a temp file so Apply Fix can retrieve it later.
 * Key: SHA-1 of the absolute file path.
 */
async function storeResult(filePath, correctedCode) {
  const key = crypto.createHash('sha1').update(filePath).digest('hex');
  const tmpFile = path.join(CERBERUS_TMP_DIR, `${key}.json`);
  await fs.writeFile(tmpFile, JSON.stringify({
    filePath,
    correctedCode,
    storedAt: new Date().toISOString()
  }), 'utf8');
  console.log(`[STORE] Saved result for ${path.basename(filePath)} → ${tmpFile}`);
}

/**
 * GET /api/stored-fix?path=<absolute-file-path>
 * Returns the most recently stored corrected code for a given file.
 */
router.get('/api/stored-fix', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath || typeof filePath !== 'string') {
    return res.status(400).json({ error: 'Missing query param: path' });
  }
  const key = crypto.createHash('sha1').update(filePath).digest('hex');
  const tmpFile = path.join(CERBERUS_TMP_DIR, `${key}.json`);
  try {
    const raw = await fs.readFile(tmpFile, 'utf8');
    const { correctedCode, storedAt } = JSON.parse(raw);
    return res.json({ filePath, correctedCode, storedAt });
  } catch {
    return res.status(404).json({
      error: 'No stored fix',
      message: `No scan result stored for ${path.basename(filePath)}. Run a scan first.`
    });
  }
});

/**
 * POST /api/scan-file
 * Scan a single file for vulnerabilities (with automatic chunking for large files)
 * Returns individual vulnerabilities with line numbers and specific fixes
 */
router.post('/api/scan-file', async (req, res) => {
  // Validate request is JSON
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'path': 'file path', 'code': 'file content'}"
    });
  }

  const { path: filePath, code } = req.body;

  // Validate required fields
  if (typeof filePath !== 'string' || typeof code !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Fields 'path' and 'code' are required and must be strings."
    });
  }

  console.log(`Scanning single file: ${filePath} (${code.length} chars)`);

  try {
    const correctedCode = await scanFileCode(code, filePath);

    // Extract individual vulnerabilities by comparing original and corrected code
    const vulnerabilities = extractVulnerabilities(code, correctedCode, filePath);

    // If no individual vulnerabilities found but code changed, create a generic one
    if (vulnerabilities.length === 0 && code !== correctedCode) {
      vulnerabilities.push({
        file: filePath,
        line: 1,
        endLine: code.split('\n').length,
        type: 'Security Issues',
        severity: 'medium',
        description: 'Multiple security improvements applied',
        originalCode: code,
        fixedCode: correctedCode,
        status: 'analyzed',
        result: correctedCode // Keep for backward compatibility
      });
    }

    // Also add the full corrected code as 'result' for backward compatibility
    vulnerabilities.forEach(v => {
      if (!v.result) {
        v.result = v.fixedCode;
      }
    });

    // Persist full corrected code to temp file for Apply Fix command
    if (correctedCode !== code) {
      await storeResult(filePath, correctedCode);
    }

    // Also store individual vulnerabilities for the dashboard
    await storeVulnerabilities(filePath, vulnerabilities, correctedCode);

    console.log(`✅ File analyzed successfully: ${filePath} - Found ${vulnerabilities.length} issues`);

    res.json({
      files_scanned: 1,
      vulnerabilities,
      full_corrected_code: correctedCode
    });
  } catch (error) {
    console.error(`❌ Error analyzing file ${filePath}:`, error.message);

    const vulnerabilities = [];
    if (error instanceof N8NWebhookTimeoutError) {
      vulnerabilities.push({ file: filePath, status: 'error', error: 'Analysis timed out' });
    } else if (error instanceof N8NWebhookUpstreamError || error instanceof N8NWebhookResponseError) {
      vulnerabilities.push({ file: filePath, status: 'error', error: error.message });
    } else {
      vulnerabilities.push({ file: filePath, status: 'error', error: 'Unexpected error during analysis' });
    }

    res.json({
      files_scanned: 1,
      vulnerabilities
    });
  }
});

/**
 * Store individual vulnerabilities to temp file
 */
async function storeVulnerabilities(filePath, vulnerabilities, fullCorrectedCode) {
  const key = crypto.createHash('sha1').update(filePath).digest('hex');
  const tmpFile = path.join(CERBERUS_TMP_DIR, `${key}-vulns.json`);
  await fs.writeFile(tmpFile, JSON.stringify({
    filePath,
    vulnerabilities,
    fullCorrectedCode,
    storedAt: new Date().toISOString()
  }), 'utf8');
  console.log(`[STORE] Saved ${vulnerabilities.length} vulnerabilities for ${path.basename(filePath)}`);
}

/**
 * GET /api/stored-vulnerabilities?path=<absolute-file-path>
 * Returns stored individual vulnerabilities for a given file
 */
router.get('/api/stored-vulnerabilities', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath || typeof filePath !== 'string') {
    return res.status(400).json({ error: 'Missing query param: path' });
  }
  const key = crypto.createHash('sha1').update(filePath).digest('hex');
  const tmpFile = path.join(CERBERUS_TMP_DIR, `${key}-vulns.json`);
  try {
    const raw = await fs.readFile(tmpFile, 'utf8');
    const data = JSON.parse(raw);
    return res.json(data);
  } catch {
    return res.status(404).json({
      error: 'No stored vulnerabilities',
      message: `No scan result stored for ${path.basename(filePath)}. Run a scan first.`
    });
  }
});

/**
 * POST /api/apply-individual-fix
 * Apply a specific fix for one vulnerability
 */
router.post('/api/apply-individual-fix', async (req, res) => {
  const { filePath, vulnerabilityIndex, currentCode } = req.body;

  if (!filePath || vulnerabilityIndex === undefined || !currentCode) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: 'Fields filePath, vulnerabilityIndex, and currentCode are required'
    });
  }

  const key = crypto.createHash('sha1').update(filePath).digest('hex');
  const tmpFile = path.join(CERBERUS_TMP_DIR, `${key}-vulns.json`);

  try {
    const raw = await fs.readFile(tmpFile, 'utf8');
    const { vulnerabilities } = JSON.parse(raw);

    if (vulnerabilityIndex < 0 || vulnerabilityIndex >= vulnerabilities.length) {
      return res.status(400).json({ error: 'Invalid vulnerability index' });
    }

    const vuln = vulnerabilities[vulnerabilityIndex];
    const fixedCode = applyIndividualFix(currentCode, vuln);

    return res.json({ fixedCode, appliedVulnerability: vuln });
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to apply fix',
      message: error.message
    });
  }
});

module.exports = router;
/**
 * API Routes
 * Express routes for the Cerberus security scanner API
 */

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { glob } = require('glob');
const rateLimit = require('express-rate-limit');
const {
  patchCodeViaN8n,
  N8NWebhookTimeoutError,
  N8NWebhookUpstreamError,
  N8NWebhookResponseError
} = require('./n8nClient');

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

/**
 * Split code into chunks of ~targetChars characters, aligned to line boundaries.
 * @param {string} code
 * @param {number} targetChars
 * @returns {{ chunk: string, startLine: number, endLine: number }[]}
 */
function chunkCode(code, targetChars) {
  const lines = code.split('\n');
  const avgLen = Math.max(1, code.length / lines.length);
  const linesPerChunk = Math.max(20, Math.round(targetChars / avgLen));

  const chunks = [];
  for (let i = 0; i < lines.length; i += linesPerChunk) {
    const slice = lines.slice(i, i + linesPerChunk);
    chunks.push({ chunk: slice.join('\n'), startLine: i, endLine: i + slice.length - 1 });
  }
  return chunks;
}

/**
 * Scan a file, using chunked n8n calls when the file exceeds MAX_CHUNK_CHARS.
 * Reassembles corrected chunks into a single corrected file.
 */
async function scanFileCode(code, filePath) {
  const timeoutSeconds = parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120');
  const webhookUrl = process.env.N8N_WEBHOOK_URL;

  if (code.length <= MAX_CHUNK_CHARS) {
    // Small file — single call
    return await patchCodeViaN8n({ code, webhookUrl, timeoutSeconds });
  }

  // Large file — split into chunks, scan each, reassemble
  const chunks = chunkCode(code, MAX_CHUNK_CHARS);
  console.log(`[CHUNK] ${path.basename(filePath)}: ${code.length} chars → ${chunks.length} chunks (limit ${MAX_CHUNK_CHARS})`);

  const correctedParts = [];
  for (let i = 0; i < chunks.length; i++) {
    const { chunk, startLine, endLine } = chunks[i];
    console.log(`[CHUNK] Processing chunk ${i + 1}/${chunks.length} (lines ${startLine}-${endLine}, ${chunk.length} chars)`);
    try {
      const corrected = await patchCodeViaN8n({ code: chunk, webhookUrl, timeoutSeconds });
      correctedParts.push(corrected);
    } catch (err) {
      // Keep original chunk on failure so the rest of the file is still returned
      console.warn(`[CHUNK] Chunk ${i + 1} failed (${err.message}), keeping original`);
      correctedParts.push(chunk);
    }
  }

  return correctedParts.join('\n');
}

/**
 * POST /api/scan-file
 * Scan a single file for vulnerabilities (with automatic chunking for large files)
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

  const vulnerabilities = [];

  try {
    const result = await scanFileCode(code, filePath);

    vulnerabilities.push({
      file: filePath,
      status: 'analyzed',
      result
    });

    console.log(`✅ File analyzed successfully: ${filePath}`);
  } catch (error) {
    console.error(`❌ Error analyzing file ${filePath}:`, error.message);

    if (error instanceof N8NWebhookTimeoutError) {
      vulnerabilities.push({ file: filePath, status: 'error', error: 'Analysis timed out' });
    } else if (error instanceof N8NWebhookUpstreamError || error instanceof N8NWebhookResponseError) {
      vulnerabilities.push({ file: filePath, status: 'error', error: error.message });
    } else {
      vulnerabilities.push({ file: filePath, status: 'error', error: 'Unexpected error during analysis' });
    }
  }

  res.json({
    files_scanned: 1,
    vulnerabilities
  });
});

module.exports = router;
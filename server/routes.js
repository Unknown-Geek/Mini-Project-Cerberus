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

// Root route for HF Spaces health display
router.get('/', (req, res) => {
  res.json({
    name: 'Cerberus Security Scanner',
    status: 'running',
    version: '0.0.1',
    endpoints: ['/api/health', '/api/scan-file', '/api/scan-folder']
  });
});

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
    const { correctedCode } = await patchCodeViaN8n({
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
    const { correctedCode: patchedSnippet } = await patchCodeViaN8n({
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

// ── Logical Chunking ─────────────────────────────────────────────────────────
// Splits code into logically independent chunks (functions, classes, blocks)
// so each n8n call has complete context for proper analysis.

/**
 * Parse Python code into logical blocks (imports, functions, classes, etc.)
 * Each block is a self-contained unit that can be analyzed independently.
 * @param {string} code - The Python source code
 * @returns {Array<{type: string, name: string, startLine: number, endLine: number, code: string}>}
 */
function parseIntoLogicalBlocks(code) {
  const lines = code.split('\n');
  const blocks = [];

  let currentBlock = null;
  let importBlock = { type: 'imports', name: 'imports', startLine: 0, lines: [] };
  let globalBlock = { type: 'global', name: 'global', startLine: 0, lines: [] };

  // Patterns to detect block starts
  const functionPattern = /^(\s*)def\s+(\w+)\s*\(/;
  const classPattern = /^(\s*)class\s+(\w+)/;
  const decoratorPattern = /^(\s*)@(\w+)/;
  const asyncFunctionPattern = /^(\s*)async\s+def\s+(\w+)\s*\(/;
  const importPattern = /^(import\s+|from\s+\w+\s+import)/;
  const commentBlockPattern = /^#\s*(?:Vulnerability|TODO|FIXME|NOTE)/i;

  let decoratorLines = [];
  let inClass = false;
  let classIndent = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmedLine = line.trimStart();
    const indent = line.length - trimmedLine.length;

    // Check for decorator
    const decoratorMatch = line.match(decoratorPattern);
    if (decoratorMatch && !currentBlock) {
      decoratorLines.push({ lineNum: i, line });
      continue;
    }

    // Check for import statements
    if (importPattern.test(trimmedLine) && !currentBlock) {
      if (importBlock.lines.length === 0) {
        importBlock.startLine = i;
      }
      importBlock.lines.push({ lineNum: i, line });
      decoratorLines = [];
      continue;
    }

    // Check for class definition
    const classMatch = line.match(classPattern);
    if (classMatch && (!currentBlock || indent <= (currentBlock.indent || 0))) {
      // Save previous block
      if (currentBlock) {
        currentBlock.endLine = i - 1;
        currentBlock.code = currentBlock.lines.map(l => l.line).join('\n');
        blocks.push(currentBlock);
      }

      // Start new class block
      currentBlock = {
        type: 'class',
        name: classMatch[2],
        startLine: decoratorLines.length > 0 ? decoratorLines[0].lineNum : i,
        indent: indent,
        lines: [...decoratorLines.map(d => d), { lineNum: i, line }]
      };
      decoratorLines = [];
      inClass = true;
      classIndent = indent;
      continue;
    }

    // Check for function definition
    const funcMatch = line.match(functionPattern) || line.match(asyncFunctionPattern);
    if (funcMatch) {
      const funcIndent = funcMatch[1].length;

      // If this is a top-level function or we're outside the current block
      if (!currentBlock || funcIndent <= (currentBlock.indent || 0)) {
        // Save previous block
        if (currentBlock) {
          currentBlock.endLine = i - 1;
          currentBlock.code = currentBlock.lines.map(l => l.line).join('\n');
          blocks.push(currentBlock);
        }

        // Start new function block
        currentBlock = {
          type: 'function',
          name: funcMatch[2],
          startLine: decoratorLines.length > 0 ? decoratorLines[0].lineNum : i,
          indent: funcIndent,
          lines: [...decoratorLines.map(d => d), { lineNum: i, line }]
        };
        decoratorLines = [];
        inClass = false;
        continue;
      }
    }

    // Check for vulnerability comment block (treat as separate analyzable unit)
    if (commentBlockPattern.test(trimmedLine) && !currentBlock) {
      // This starts a new logical section
      if (globalBlock.lines.length > 0) {
        globalBlock.endLine = i - 1;
        globalBlock.code = globalBlock.lines.map(l => l.line).join('\n');
        if (globalBlock.code.trim()) {
          blocks.push({ ...globalBlock });
        }
        globalBlock = { type: 'global', name: 'global', startLine: i, lines: [] };
      }
    }

    // Add line to current block or global
    if (currentBlock) {
      // Check if we've exited the current block (dedented)
      if (trimmedLine && indent <= currentBlock.indent && !line.match(/^\s*#/) && !line.match(/^\s*$/)) {
        // End current block
        currentBlock.endLine = i - 1;
        currentBlock.code = currentBlock.lines.map(l => l.line).join('\n');
        blocks.push(currentBlock);
        currentBlock = null;

        // This line starts something new, reprocess it
        i--;
        continue;
      }
      currentBlock.lines.push({ lineNum: i, line });
    } else {
      // Add to global block
      if (globalBlock.lines.length === 0) {
        globalBlock.startLine = i;
      }
      globalBlock.lines.push({ lineNum: i, line });
    }
  }

  // Finalize any remaining blocks
  if (currentBlock) {
    currentBlock.endLine = lines.length - 1;
    currentBlock.code = currentBlock.lines.map(l => l.line).join('\n');
    blocks.push(currentBlock);
  }

  // Add imports block if it has content
  if (importBlock.lines.length > 0) {
    importBlock.endLine = importBlock.lines[importBlock.lines.length - 1].lineNum;
    importBlock.code = importBlock.lines.map(l => l.line).join('\n');
    blocks.unshift(importBlock); // Put imports first
  }

  // Add remaining global block
  if (globalBlock.lines.length > 0) {
    globalBlock.endLine = globalBlock.lines[globalBlock.lines.length - 1].lineNum;
    globalBlock.code = globalBlock.lines.map(l => l.line).join('\n');
    if (globalBlock.code.trim()) {
      blocks.push(globalBlock);
    }
  }

  return blocks;
}

/**
 * Group small blocks together to avoid too many API calls,
 * while keeping logical separation.
 * @param {Array} blocks - Parsed logical blocks
 * @param {number} maxChars - Maximum characters per chunk
 * @returns {Array<{blocks: Array, code: string, startLine: number, endLine: number}>}
 */
function groupBlocksIntoChunks(blocks, maxChars) {
  const chunks = [];
  let currentChunk = { blocks: [], code: '', startLine: 0, endLine: 0 };

  for (const block of blocks) {
    const blockCode = block.code || '';

    // If adding this block would exceed the limit, start a new chunk
    if (currentChunk.code.length > 0 &&
        currentChunk.code.length + blockCode.length > maxChars) {
      chunks.push(currentChunk);
      currentChunk = { blocks: [], code: '', startLine: block.startLine, endLine: block.endLine };
    }

    // Add block to current chunk
    currentChunk.blocks.push(block);
    currentChunk.code += (currentChunk.code ? '\n\n' : '') + blockCode;
    if (currentChunk.blocks.length === 1) {
      currentChunk.startLine = block.startLine;
    }
    currentChunk.endLine = block.endLine;
  }

  // Add the last chunk
  if (currentChunk.blocks.length > 0) {
    chunks.push(currentChunk);
  }

  return chunks;
}

// Maximum characters per logical chunk (larger than before since chunks are coherent)
const MAX_CHUNK_CHARS = parseInt(process.env.MAX_CHUNK_CHARS || '3000', 10);

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
 * Scan a file using logical chunking.
 * Splits code into functions, classes, and logical blocks so each AI call
 * has complete context. Reassembles the corrected chunks at the end.
 */
async function scanFileCode(code, filePath) {
  const timeoutSeconds = parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120');
  const webhookUrl = process.env.N8N_WEBHOOK_URL;

  // For small files, send the whole thing
  if (code.length <= MAX_CHUNK_CHARS) {
    let { correctedCode: result, vulnerabilities: n8nVulns, typesOfVulnerabilities, numberOfVulnerabilitiesFixed, vulnerabilitiesDetails } = await patchCodeViaN8n({ code, webhookUrl, timeoutSeconds });
    result = stripMarkdownFences(result);
    if (isBogusResponse(code, result)) {
      console.warn(`[SCAN] Single-call response looks bogus, keeping original`);
      return { correctedCode: code, n8nVulnerabilities: [], vulnerabilityTypes: [], vulnerabilityCount: 0, vulnerabilitiesDetails: [] };
    }
    return { correctedCode: result, n8nVulnerabilities: n8nVulns || [], vulnerabilityTypes: typesOfVulnerabilities || [], vulnerabilityCount: numberOfVulnerabilitiesFixed || 0, vulnerabilitiesDetails: vulnerabilitiesDetails || [] };
  }

  // Parse code into logical blocks (functions, classes, imports, etc.)
  const blocks = parseIntoLogicalBlocks(code);
  console.log(`[SCAN] ${path.basename(filePath)}: Parsed ${blocks.length} logical blocks`);

  // Log the blocks for debugging
  blocks.forEach((b, i) => {
    console.log(`  Block ${i + 1}: ${b.type} "${b.name}" (lines ${b.startLine + 1}-${b.endLine + 1}, ${b.code?.length || 0} chars)`);
  });

  // Group small blocks into chunks to reduce API calls
  const chunks = groupBlocksIntoChunks(blocks, MAX_CHUNK_CHARS);
  console.log(`[SCAN] Grouped into ${chunks.length} chunks for analysis`);

  // Process each chunk
  const correctedChunks = [];

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const blockNames = chunk.blocks.map(b => `${b.type}:${b.name}`).join(', ');
    console.log(`[SCAN] Processing chunk ${i + 1}/${chunks.length}: ${blockNames} (${chunk.code.length} chars)`);

    try {
      let { correctedCode: corrected } = await patchCodeViaN8n({
        code: chunk.code,
        webhookUrl,
        timeoutSeconds
      });
      corrected = stripMarkdownFences(corrected);

      if (isBogusResponse(chunk.code, corrected)) {
        console.warn(`[SCAN] Chunk ${i + 1} response looks bogus, keeping original`);
        correctedChunks.push(chunk.code);
      } else {
        correctedChunks.push(corrected);
      }
    } catch (err) {
      console.warn(`[SCAN] Chunk ${i + 1} failed (${err.message}), keeping original`);
      correctedChunks.push(chunk.code);
    }
  }

  // Reassemble the corrected code and clean up duplicate blank lines
  const correctedCode = correctedChunks.join('\n\n').replace(/\n{3,}/g, '\n\n');
  // For chunked processing, we don't have per-vulnerability mappings
  return { correctedCode, n8nVulnerabilities: [], vulnerabilityTypes: [], vulnerabilityCount: 0, vulnerabilitiesDetails: [] };
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
    const { correctedCode, n8nVulnerabilities, vulnerabilityTypes, vulnerabilityCount, vulnerabilitiesDetails } = await scanFileCode(code, filePath);

    // Extract individual vulnerabilities by comparing original and corrected code
    // Pass n8n's per-vulnerability mappings and type details for accurate labeling
    const vulnerabilities = extractVulnerabilities(code, correctedCode, filePath, n8nVulnerabilities, vulnerabilitiesDetails);

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
      full_corrected_code: correctedCode,
      vulnerability_types: vulnerabilityTypes || [],
      vulnerability_count: vulnerabilityCount || vulnerabilities.length
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
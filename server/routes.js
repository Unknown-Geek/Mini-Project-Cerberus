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
    version: '0.0.2',
    endpoints: ['/api/health', '/api/scan-file', '/api/scan-folder']
  });
});

// Rate limiting for scan endpoint (10 requests per 15 minutes per IP)
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    error: 'Too many requests',
    message: 'Too many scan requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

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
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'code': 'raw python string'}"
    });
  }

  const { code } = req.body;

  if (typeof code !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'code' is required and must be a string."
    });
  }

  console.log(`Processing patch request code_length=${code.length}`);

  try {
    const result = await patchCodeViaN8n({
      code,
      webhookUrl: process.env.N8N_WEBHOOK_URL,
      timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120')
    });

    return res.json({
      corrected_code: result.correctedCode,
      vulnerabilities: result.vulnerabilities,
      vulnerability_types: result.typesOfVulnerabilities,
      vulnerability_count: result.numberOfVulnerabilitiesFixed
    });
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

  const { snippet, filePath, startLine, endLine } = req.body;

  if (typeof snippet !== 'string' || snippet.trim().length === 0) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'snippet' is required and must be a non-empty string."
    });
  }

  console.log(`[SNIPPET] Patching ${path.basename(filePath || 'unknown')} lines ${startLine}-${endLine} (${snippet.length} chars)`);

  try {
    const result = await patchCodeViaN8n({
      code: snippet,
      webhookUrl: process.env.N8N_WEBHOOK_URL,
      timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120')
    });

    const hasChanges = result.correctedCode !== snippet;

    return res.json({
      patched_snippet: result.correctedCode,
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
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'path': 'folder path'}"
    });
  }

  const { path: folderPath } = req.body;

  if (typeof folderPath !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Field 'path' is required and must be a string."
    });
  }

  const sanitizedPath = path.resolve(folderPath);

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

  const extensions = ['*.py', '*.js', '*.ts', '*.tsx', '*.jsx', '*.java', '*.go', '*.rb', '*.php'];
  const codeFiles = [];

  for (const ext of extensions) {
    const pattern = path.join(sanitizedPath, '**', ext).replace(/\\/g, '/');
    const files = await glob(pattern, { nodir: true });
    codeFiles.push(...files);
  }

  const vulnerabilities = [];

  for (const filePath of codeFiles) {
    try {
      const code = await fs.readFile(filePath, 'utf-8');
      console.log(`Analyzing file: ${filePath}`);

      try {
        const result = await patchCodeViaN8n({
          code,
          webhookUrl: process.env.N8N_WEBHOOK_URL,
          timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120')
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
 * Scan a single file for vulnerabilities.
 * Sends code to n8n and maps the response to the extension's vulnerability format.
 */
router.post('/api/scan-file', async (req, res) => {
  if (!req.is('application/json')) {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Request must be JSON: {'path': 'file path', 'code': 'file content'}"
    });
  }

  const { path: filePath, code } = req.body;

  if (typeof filePath !== 'string' || typeof code !== 'string') {
    return res.status(400).json({
      error: 'Invalid payload',
      message: "Fields 'path' and 'code' are required and must be strings."
    });
  }

  console.log(`Scanning single file: ${filePath} (${code.length} chars)`);

  try {
    const n8nResult = await patchCodeViaN8n({
      code,
      webhookUrl: process.env.N8N_WEBHOOK_URL,
      timeoutSeconds: parseFloat(process.env.N8N_TIMEOUT_SECONDS || '120')
    });

    const correctedCode = n8nResult.correctedCode;

    // Map n8n vulnerabilities to the extension's expected format
    const vulnerabilities = extractVulnerabilities(
      code,
      correctedCode,
      filePath,
      n8nResult.vulnerabilities,
      n8nResult.vulnerabilitiesDetails
    );

    // Persist full corrected code to temp file for Apply Fix command
    if (correctedCode !== code) {
      await storeResult(filePath, correctedCode);
    }

    // Store individual vulnerabilities for the dashboard
    await storeVulnerabilities(filePath, vulnerabilities, correctedCode);

    console.log(`✅ File analyzed successfully: ${filePath} - Found ${vulnerabilities.length} issues`);

    res.json({
      files_scanned: 1,
      vulnerabilities,
      full_corrected_code: correctedCode,
      vulnerability_types: n8nResult.typesOfVulnerabilities || [],
      vulnerability_count: n8nResult.numberOfVulnerabilitiesFixed || vulnerabilities.length
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
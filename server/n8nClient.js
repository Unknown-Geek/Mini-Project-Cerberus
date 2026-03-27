/**
 * n8n Webhook Client
 * Handles communication with the n8n workflow for code analysis and patching
 */

const axios = require('axios');

class N8NWebhookError extends Error {
  constructor(message) {
    super(message);
    this.name = 'N8NWebhookError';
  }
}

class N8NWebhookTimeoutError extends N8NWebhookError {
  constructor(message) {
    super(message);
    this.name = 'N8NWebhookTimeoutError';
  }
}

class N8NWebhookUpstreamError extends N8NWebhookError {
  constructor(message) {
    super(message);
    this.name = 'N8NWebhookUpstreamError';
  }
}

class N8NWebhookResponseError extends N8NWebhookError {
  constructor(message) {
    super(message);
    this.name = 'N8NWebhookResponseError';
  }
}

/**
 * Sleep helper
 * @param {number} ms - milliseconds to wait
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Send code to n8n webhook for vulnerability analysis and correction.
 * Retries up to MAX_RETRIES times on 504 / upstream errors with exponential backoff.
 *
 * @param {Object} params
 * @param {string} params.code            - The code to analyze
 * @param {string} params.webhookUrl      - The n8n webhook URL
 * @param {number} params.timeoutSeconds  - Per-attempt request timeout in seconds
 * @param {number} [params.maxRetries=2]  - How many times to retry on 5xx
 * @param {number} [params.retryDelayMs=8000] - Base delay between retries (ms)
 * @returns {Promise<{correctedCode: string, vulnerabilities: Array}>} - The corrected code and per-vulnerability fix mappings from Patcher Agent
 */
async function patchCodeViaN8n({ code, webhookUrl, timeoutSeconds, maxRetries = 2, retryDelayMs = 8000 }) {
  let lastError;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      const delay = retryDelayMs * attempt; // 8s, 16s …
      console.log(`[RETRY] Attempt ${attempt + 1}/${maxRetries + 1} after ${delay}ms (last error: ${lastError?.message})`);
      await sleep(delay);
    }

    try {
      console.log(`[DEBUG] Sending code to n8n (length: ${code.length} chars, attempt ${attempt + 1})`);
      console.log(`[DEBUG] First 100 chars: ${code.substring(0, 100).replace(/\n/g, '\\n')}...`);

      const response = await axios.post(
        webhookUrl,
        { code },
        {
          timeout: timeoutSeconds * 1000,
          headers: { 'Content-Type': 'application/json' }
        }
      );

      console.log(`[DEBUG] n8n response status: ${response.status}`);
      console.log(`[DEBUG] Response preview: ${JSON.stringify(response.data).substring(0, 100)}...`);

      if (response.status >= 500) {
        // Retryable — 504 Gateway Timeout, 502 Bad Gateway, 503 Unavailable
        lastError = new N8NWebhookUpstreamError(`n8n webhook returned server error ${response.status}`);
        continue; // go to next attempt
      }
      if (response.status >= 400) {
        throw new N8NWebhookUpstreamError(`n8n webhook returned unexpected status ${response.status}`);
      }

      const payload = response.data;
      const correctedCode = payload.corrected_code;

      if (typeof correctedCode !== 'string') {
        throw new N8NWebhookResponseError("n8n webhook response missing 'corrected_code' string");
      }

      // Return both the corrected code AND the per-vulnerability mappings
      // from the Patcher Agent (original_code/fixed_code for each vuln)
      return {
        correctedCode,
        vulnerabilities: payload.vulnerabilities || [],
        numberOfVulnerabilitiesFixed: payload.number_of_vulnerabilities_fixed || 0,
        typesOfVulnerabilities: payload.types_of_vulnerabilities || [],
        vulnerabilitiesDetails: payload.vulnerabilities_details || []
      };

    } catch (error) {
      if (error instanceof N8NWebhookResponseError) throw error; // not retryable

      if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        lastError = new N8NWebhookTimeoutError('n8n webhook request timed out');
      } else if (error.response && error.response.status >= 500) {
        lastError = new N8NWebhookUpstreamError(`n8n webhook returned server error ${error.response.status}`);
      } else if (error.response && error.response.status >= 400) {
        throw new N8NWebhookUpstreamError(`n8n webhook returned unexpected status ${error.response.status}`);
      } else if (error instanceof N8NWebhookError) {
        lastError = error;
      } else {
        lastError = new N8NWebhookUpstreamError(`Failed to call n8n webhook: ${error.message}`);
      }
      // fall through to next attempt
    }
  }

  // All attempts exhausted
  throw lastError;
}

module.exports = {
  N8NWebhookError,
  N8NWebhookTimeoutError,
  N8NWebhookUpstreamError,
  N8NWebhookResponseError,
  patchCodeViaN8n
};
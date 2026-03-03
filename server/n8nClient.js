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
 * Send code to n8n webhook for vulnerability analysis and correction
 * @param {Object} params
 * @param {string} params.code - The code to analyze
 * @param {string} params.webhookUrl - The n8n webhook URL
 * @param {number} params.timeoutSeconds - Request timeout in seconds
 * @returns {Promise<string>} - The corrected code
 */
async function patchCodeViaN8n({ code, webhookUrl, timeoutSeconds }) {
  try {
    console.log(`[DEBUG] Sending code to n8n (length: ${code.length} chars)`);
    console.log(`[DEBUG] First 100 chars: ${code.substring(0, 100).replace(/\n/g, '\\n')}...`);
    
    const response = await axios.post(
      webhookUrl,
      { code },
      {
        timeout: timeoutSeconds * 1000,
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`[DEBUG] n8n response status: ${response.status}`);
    console.log(`[DEBUG] Response preview: ${JSON.stringify(response.data).substring(0, 100)}...`);

    if (response.status >= 500) {
      throw new N8NWebhookUpstreamError(`n8n webhook returned server error ${response.status}`);
    }
    if (response.status >= 400) {
      throw new N8NWebhookUpstreamError(`n8n webhook returned unexpected status ${response.status}`);
    }

    const payload = response.data;
    const correctedCode = payload.corrected_code;

    if (typeof correctedCode !== 'string') {
      throw new N8NWebhookResponseError("n8n webhook response missing 'corrected_code' string");
    }

    return correctedCode;
  } catch (error) {
    if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      throw new N8NWebhookTimeoutError('n8n webhook request timed out');
    }
    if (error.response) {
      if (error.response.status >= 500) {
        throw new N8NWebhookUpstreamError(`n8n webhook returned server error ${error.response.status}`);
      }
      if (error.response.status >= 400) {
        throw new N8NWebhookUpstreamError(`n8n webhook returned unexpected status ${error.response.status}`);
      }
    }
    if (error instanceof N8NWebhookError) {
      throw error;
    }
    throw new N8NWebhookUpstreamError(`Failed to call n8n webhook: ${error.message}`);
  }
}

module.exports = {
  N8NWebhookError,
  N8NWebhookTimeoutError,
  N8NWebhookUpstreamError,
  N8NWebhookResponseError,
  patchCodeViaN8n
};
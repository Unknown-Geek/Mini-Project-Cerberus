from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .n8n_client import (
    N8NWebhookResponseError,
    N8NWebhookTimeoutError,
    N8NWebhookUpstreamError,
    patch_code_via_n8n,
)

api_bp = Blueprint("api", __name__)


@api_bp.get("/api/health")
def health():
    return jsonify({"status": "ok"}), 200


@api_bp.post("/api/patch-code")
def patch_code():
    if not request.is_json:
        return (
            jsonify(
                {
                    "error": "Invalid payload",
                    "message": "Request must be JSON: {'code': 'raw python string'}",
                }
            ),
            400,
        )

    payload = request.get_json(silent=True) or {}
    code = payload.get("code")

    if not isinstance(code, str):
        return (
            jsonify(
                {
                    "error": "Invalid payload",
                    "message": "Field 'code' is required and must be a string.",
                }
            ),
            400,
        )

    current_app.logger.info("Processing patch request code_length=%s", len(code))

    try:
        corrected_code = patch_code_via_n8n(
            code=code,
            webhook_url=current_app.config["N8N_WEBHOOK_URL"],
            timeout_seconds=current_app.config["N8N_TIMEOUT_SECONDS"],
        )
    except (N8NWebhookTimeoutError, N8NWebhookUpstreamError, N8NWebhookResponseError):
        current_app.logger.exception("n8n webhook call failed")
        return (
            jsonify(
                {
                    "error": "Bad Gateway",
                    "message": "Unable to retrieve corrected code from n8n webhook.",
                }
            ),
            502,
        )

    return jsonify({"corrected_code": corrected_code}), 200

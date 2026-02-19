from __future__ import annotations

import requests
from requests.exceptions import RequestException, Timeout


class N8NWebhookError(Exception):
    pass


class N8NWebhookTimeoutError(N8NWebhookError):
    pass


class N8NWebhookUpstreamError(N8NWebhookError):
    pass


class N8NWebhookResponseError(N8NWebhookError):
    pass


def patch_code_via_n8n(*, code: str, webhook_url: str, timeout_seconds: float) -> str:
    try:
        response = requests.post(
            webhook_url,
            json={"code": code},
            timeout=timeout_seconds,
        )
    except Timeout as exc:
        raise N8NWebhookTimeoutError("n8n webhook request timed out") from exc
    except RequestException as exc:
        raise N8NWebhookUpstreamError("Failed to call n8n webhook") from exc

    if response.status_code >= 500:
        raise N8NWebhookUpstreamError(
            f"n8n webhook returned server error {response.status_code}"
        )
    if response.status_code >= 400:
        raise N8NWebhookUpstreamError(
            f"n8n webhook returned unexpected status {response.status_code}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise N8NWebhookResponseError("n8n webhook response was not valid JSON") from exc

    corrected_code = payload.get("corrected_code")
    if not isinstance(corrected_code, str):
        raise N8NWebhookResponseError(
            "n8n webhook response missing 'corrected_code' string"
        )

    return corrected_code

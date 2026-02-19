"""
Tests for Cerberus API endpoints.

Uses Flask's built-in test client — no running server needed.
n8n webhook calls are mocked with unittest.mock.
"""

import unittest
from unittest.mock import patch, MagicMock

from app import app


class TestHealthEndpoint(unittest.TestCase):
    """Tests for GET /api/health."""

    def setUp(self):
        self.client = app.test_client()

    def test_health_returns_ok(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"status": "ok"})


class TestPatchCodeEndpoint(unittest.TestCase):
    """Tests for POST /api/patch-code."""

    def setUp(self):
        self.client = app.test_client()

    # ── Validation tests (no mocking needed) ──────────────────────

    def test_rejects_non_json_request(self):
        resp = self.client.post("/api/patch-code", data="not json")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid payload", resp.get_json()["error"])

    def test_rejects_missing_code_field(self):
        resp = self.client.post("/api/patch-code", json={"foo": "bar"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("code", resp.get_json()["message"])

    def test_rejects_non_string_code(self):
        resp = self.client.post("/api/patch-code", json={"code": 123})
        self.assertEqual(resp.status_code, 400)

    # ── Success test (mock the n8n webhook) ───────────────────────

    @patch("cerberus_api.n8n_client.requests.post")
    def test_success_returns_corrected_code(self, mock_post):
        # Simulate a successful n8n webhook response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "corrected_code": "import os\nprint(os.getenv('SECRET'))"
        }
        mock_post.return_value = mock_response

        resp = self.client.post(
            "/api/patch-code",
            json={"code": "print('hello')"},
        )

        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("corrected_code", data)
        self.assertIsInstance(data["corrected_code"], str)

    # ── Error tests (mock failures) ───────────────────────────────

    @patch("cerberus_api.n8n_client.requests.post")
    def test_webhook_timeout_returns_502(self, mock_post):
        from requests.exceptions import Timeout

        mock_post.side_effect = Timeout("timed out")

        resp = self.client.post(
            "/api/patch-code",
            json={"code": "x = 1"},
        )

        self.assertEqual(resp.status_code, 502)
        self.assertIn("Bad Gateway", resp.get_json()["error"])

    @patch("cerberus_api.n8n_client.requests.post")
    def test_webhook_server_error_returns_502(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        resp = self.client.post(
            "/api/patch-code",
            json={"code": "x = 1"},
        )

        self.assertEqual(resp.status_code, 502)


if __name__ == "__main__":
    unittest.main()

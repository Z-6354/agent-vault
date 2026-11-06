"""Regression for the model_call error path: upstream bodies that echo the
submitted key must never reach the output."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "model_call", ROOT / "scripts" / "model_call.py")
model_call = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model_call)

CANARY = "synthetic-review-key-not-for-model"


class _ErrorOpener:
    def open(self, request, timeout=60):
        body = f"upstream diagnostic echoed Authorization: Bearer {CANARY}".encode()
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(body))


class ModelCallErrorPathTests(unittest.TestCase):
    def test_http_error_output_never_carries_the_key(self):
        with patch("urllib.request.build_opener", return_value=_ErrorOpener()):
            with self.assertRaises(SystemExit) as raised:
                model_call.call_model("https://synthetic.invalid/v1", CANARY, "synthetic-model", "hi")
        self.assertNotIn(CANARY, str(raised.exception))

    def test_success_response_echoing_the_key_is_discarded(self):
        echo = {"choices": [{"message": {"content": "hi"}}],
                "usage": {"total_tokens": 1}, "note": CANARY}
        with patch("urllib.request.build_opener", return_value=_EchoOpener(echo)):
            with self.assertRaises(SystemExit) as raised:
                model_call.call_model("https://synthetic.invalid/v1", CANARY, "synthetic-model", "hi")
        self.assertNotIn(CANARY, str(raised.exception))


class _EchoOpener:
    def __init__(self, value):
        self.value = value
    def open(self, request, timeout=60):
        class _Response:
            def __init__(self, value):
                self._body = json.dumps(value).encode()
            def read(self, limit=-1):
                return self._body[:limit] if limit > 0 else self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            code = 200
        return _Response(self.value)


if __name__ == "__main__":
    unittest.main()

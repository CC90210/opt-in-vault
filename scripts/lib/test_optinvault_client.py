import json
import unittest

from scripts.lib.optinvault_client import OptInVaultClient


class _Response:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        payload = b'{"consent_id":"consent-1","created":true}'
        return payload if size < 0 else payload[:size]


class OptInVaultClientTest(unittest.TestCase):
    def test_rejects_cleartext_remote_base_url(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            OptInVaultClient(
                "http://vault.example",
                site_key="oiv_pk_" + "f" * 43,
            )

    def test_log_consent_uses_stdlib_request_shape_without_tenant_identity(self):
        captured = {}

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _Response()

        client = OptInVaultClient(
            "https://vault.example/",
            site_key="oiv_pk_" + "f" * 43,
            opener=opener,
            timeout=3.5,
        )
        result = client.log_consent(
            origin="https://example.test",
            idempotency_key="idem-python-0001",
            disclosure_version="v1",
            affirmative_action="form_submit",
            form_url="https://example.test/signup",
            email="person@example.test",
            occurred_at="2026-08-08T12:00:00.000Z",
        )

        request = captured["request"]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, "https://vault.example/api/v1/consent/log")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Origin"), "https://example.test")
        self.assertEqual(request.get_header("Idempotency-key"), "idem-python-0001")
        self.assertEqual(
            request.get_header("X-optinvault-site-key"), "oiv_pk_" + "f" * 43
        )
        self.assertEqual(body["affirmative_action"], "form_submit")
        self.assertNotIn("tenant_id", body)
        self.assertEqual(captured["timeout"], 3.5)
        self.assertEqual(result["consent_id"], "consent-1")


if __name__ == "__main__":
    unittest.main()

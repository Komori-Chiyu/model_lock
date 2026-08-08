import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from server.server import Store, ModelLockServer, make_handler
from http.server import ThreadingHTTPServer


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="modelock-test-"))
        cls.db = str(cls.tmp / "test.db")
        cls.admin = "test-admin-key"
        cls.secret = b"test-secret-0123456789abcdef"
        cls.store = Store(cls.db)
        cls.api = ModelLockServer(cls.store, cls.admin, cls.secret, token_ttl=3600)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.api))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from cryptography.hazmat.primitives import serialization
        cls.spki = cls.device_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        import base64
        cls.spki_b64 = base64.b64encode(cls.spki).decode()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, path, body):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def _make_codes(self, model="model-1", count=1, max_devices=1):
        status, body = self._post("/api/admin/codes", {
            "admin_key": self.admin, "model_id": model,
            "count": count, "max_devices": max_devices,
        })
        self.assertEqual(status, 200, body)
        return body["codes"]

    def test_health(self):
        status, body = self._post("/health", {})
        self.assertEqual(status, 404)  # GET only

    def test_activate_and_status(self):
        code = self._make_codes()[0]
        status, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
            "hwids": {"machine_guid": "x"},
        })
        self.assertEqual(status, 200, body)
        self.assertTrue(body["token"])
        token = body["token"]
        status, body = self._post("/api/status", {"token": token})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["model_id"], "model-1")
        self.assertEqual(body["device_id"], "dev-a")

    def test_one_code_one_device(self):
        code = self._make_codes()[0]
        status, _ = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
        })
        self.assertEqual(status, 200)
        status, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-b", "pubkey_spki": self.spki_b64,
        })
        self.assertEqual(status, 403, body)
        self.assertEqual(body["code"], "DEVICE_MISMATCH")

    def test_same_device_rebind_ok(self):
        code = self._make_codes()[0]
        for _ in range(2):
            status, _ = self._post("/api/activate", {
                "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
            })
            self.assertEqual(status, 200)

    def test_unbind_then_new_device(self):
        code = self._make_codes()[0]
        self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
        })
        status, body = self._post("/api/admin/unbind", {
            "admin_key": self.admin, "code": code, "device_id": "dev-a",
        })
        self.assertEqual(status, 200, body)
        status, _ = self._post("/api/activate", {
            "code": code, "device_id": "dev-b", "pubkey_spki": self.spki_b64,
        })
        self.assertEqual(status, 200)

    def test_revoked_code_rejected(self):
        code = self._make_codes()[0]
        self._post("/api/admin/unbind", {
            "admin_key": self.admin, "code": code, "action": "revoke",
        })
        status, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
        })
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "CODE_REVOKED")

    def test_bad_admin_rejected(self):
        status, body = self._post("/api/admin/codes", {
            "admin_key": "wrong", "model_id": "m", "count": 1,
        })
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "FORBIDDEN")

    def test_tampered_token_rejected(self):
        code = self._make_codes()[0]
        _, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
        })
        token = body["token"]
        bad = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
        status, body = self._post("/api/status", {"token": bad})
        self.assertEqual(status, 401)
        self.assertEqual(body["code"], "BAD_TOKEN")

    def test_bad_pubkey_rejected(self):
        code = self._make_codes()[0]
        status, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": "bm90LWEta2V5",
        })
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "BAD_PUBKEY")

    def test_refresh(self):
        code = self._make_codes()[0]
        _, body = self._post("/api/activate", {
            "code": code, "device_id": "dev-a", "pubkey_spki": self.spki_b64,
        })
        status, body = self._post("/api/refresh", {"token": body["token"]})
        self.assertEqual(status, 200)
        self.assertTrue(body["token"])


if __name__ == "__main__":
    unittest.main()

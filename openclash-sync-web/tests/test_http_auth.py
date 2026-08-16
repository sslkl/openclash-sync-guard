#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HttpAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        cls.port = listener.getsockname()[1]
        listener.close()
        cls.host = f"127.0.0.1:{cls.port}"
        cls.user = "test-admin"
        cls.password = "test-only-password"
        cls.tmp = tempfile.TemporaryDirectory(prefix="openclash-http-auth-")
        source = f"{cls.user}:OpenClash Sync:{cls.password}".encode()
        ha1 = hashlib.sha256(source).hexdigest()
        md5_ha1 = hashlib.md5(source, usedforsecurity=False).hexdigest()
        cls.ha1 = Path(cls.tmp.name) / "ha1"
        cls.ha1.write_text(f"sha256:{ha1}\nmd5:{md5_ha1}\n")
        cls.ha1.chmod(0o600)
        env = dict(os.environ)
        env.update({
            "OPENCLASH_WEB_HOST": "127.0.0.1",
            "OPENCLASH_WEB_PORT": str(cls.port),
            "OPENCLASH_WEB_AUTH_USER": cls.user,
            "OPENCLASH_WEB_AUTH_HA1_FILE": str(cls.ha1),
            "OPENCLASH_WEB_ALLOWED_HOSTS": cls.host,
            "OPENCLASH_WEB_ALLOWED_NETWORKS": "127.0.0.0/8",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        cls.stderr_path = Path(cls.tmp.name) / "server.stderr"
        cls.stderr_handle = cls.stderr_path.open("wb")
        cls.process = subprocess.Popen([sys.executable, str(ROOT / "server.py")], cwd=ROOT, env=env,
                                       stdout=subprocess.DEVNULL, stderr=cls.stderr_handle)
        deadline = time.time() + 8
        ready = False
        while time.time() < deadline:
            if cls.process.poll() is not None:
                break
            try:
                connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1)
                connection.request("GET", "/healthz", headers={"Host": cls.host})
                response = connection.getresponse()
                status = response.status
                response.read()
                connection.close()
                if status == 200:
                    ready = True
                    break
            except OSError:
                pass
            time.sleep(0.1)
        if not ready:
            if cls.process.poll() is None:
                cls.process.terminate()
                cls.process.wait(timeout=5)
            cls.stderr_handle.close()
            detail = cls.stderr_path.read_text(errors="replace")[-1000:].strip()
            cls.tmp.cleanup()
            raise RuntimeError(f"测试 Web 服务未启动：{detail or '无错误输出'}")
    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.stderr_handle.close()
        cls.tmp.cleanup()

    def request(self, path, body=None, origin=True, algorithm="SHA-256"):
        headers = {"Host": self.host}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if origin:
                headers["Origin"] = f"http://{self.host}"
                headers["Sec-Fetch-Site"] = "same-origin"
        method = "POST" if data is not None else "GET"
        first = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        first.request(method, path, body=data, headers=headers)
        challenge_response = first.getresponse()
        self.assertEqual(challenge_response.status, 401)
        challenges = [value for name, value in challenge_response.getheaders() if name.lower() == "www-authenticate"]
        challenge_response.read()
        first.close()
        challenge = next(value for value in challenges if f"algorithm={algorithm}" in value)
        nonce_match = re.search(r'nonce="([^"]+)"', challenge)
        self.assertIsNotNone(nonce_match)
        nonce = nonce_match.group(1)
        nc, cnonce = "00000001", secrets.token_hex(8)
        hash_function = hashlib.sha256 if algorithm == "SHA-256" else hashlib.md5
        ha1 = hash_function(f"{self.user}:OpenClash Sync:{self.password}".encode()).hexdigest()
        ha2 = hash_function(f"{method}:{path}".encode()).hexdigest()
        digest = hash_function(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        headers["Authorization"] = (
            f'Digest username="{self.user}", realm="OpenClash Sync", nonce="{nonce}", '
            f'uri="{path}", algorithm={algorithm}, response="{digest}", qop=auth, '
            f'nc={nc}, cnonce="{cnonce}"'
        )
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, payload

    def test_unauthenticated_challenge_uses_sha256(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/", headers={"Host": self.host})
        response = connection.getresponse()
        self.assertEqual(response.status, 401)
        challenges = [value for name, value in response.getheaders() if name.lower() == "www-authenticate"]
        self.assertEqual(len(challenges), 2)
        self.assertIn("algorithm=SHA-256", challenges[0])
        self.assertIn("algorithm=MD5", challenges[1])
        self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
        self.assertGreater(int(response.getheader("Content-Length")), 0)

    def test_wrong_host_is_rejected_before_auth(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/", headers={"Host": "evil.example"})
        self.assertEqual(connection.getresponse().status, 421)

    def test_digest_login_reads_page(self):
        status, payload = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("OpenClash同步器", payload.decode())

    def test_md5_digest_fallback_reads_page(self):
        status, payload = self.request("/", algorithm="MD5")
        self.assertEqual(status, 200)
        self.assertIn("OpenClash同步器", payload.decode())

    def test_cross_site_post_is_rejected(self):
        status, _ = self.request("/api/custom/validate", {"customization": {"rules": [], "fake_ip_filter": []}}, origin=False)
        self.assertEqual(status, 403)

    def test_authenticated_custom_validation(self):
        payload = {"customization": {"rules": [{"type": "DOMAIN", "value": "api.example.com", "policy": "DIRECT"}], "fake_ip_filter": ["*.example.com"]}}
        status, response_body = self.request("/api/custom/validate", payload)
        self.assertEqual(status, 200)
        result = json.loads(response_body)
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"rules": 1, "fake_ip_filter": 1})


if __name__ == "__main__":
    unittest.main()

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
        # HA1 files require trusted ancestors; Linux /tmp is deliberately rejected.
        cls.tmp = tempfile.TemporaryDirectory(prefix="openclash-http-auth-", dir=ROOT)
        cls.tmp_root = Path(cls.tmp.name).resolve()
        source = f"{cls.user}:OpenClash Sync:{cls.password}".encode()
        ha1 = hashlib.sha256(source).hexdigest()
        md5_ha1 = hashlib.md5(source, usedforsecurity=False).hexdigest()
        cls.ha1 = cls.tmp_root / "ha1"
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
            "PYTHONPATH": os.pathsep.join(filter(None, [
                str(ROOT.parent / "vendor" / "pyyaml-6.0.2"),
                env.get("PYTHONPATH", ""),
            ])),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        cls.stderr_path = cls.tmp_root / "server.stderr"
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

    def request(self, path, body=None, origin=True, algorithm="SHA-256", method=None):
        headers = {"Host": self.host}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            if origin:
                headers["Origin"] = f"http://{self.host}"
                headers["Sec-Fetch-Site"] = "same-origin"
        method = method or ("POST" if data is not None else "GET")
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

    def test_malformed_request_target_returns_400_without_traceback(self):
        target = "http://[invalid/synthetic-private?key=synthetic-only"
        for method in ("GET", "HEAD", "POST", "OPTIONS", "PUT", "UNKNOWN"):
            with self.subTest(method=method):
                request = (f"{method} {target} HTTP/1.1\r\nHost: {self.host}\r\n"
                           "Connection: close\r\nContent-Length: 0\r\n\r\n").encode()
                with socket.create_connection(("127.0.0.1", self.port), timeout=3) as connection:
                    connection.sendall(request)
                    chunks = []
                    while chunk := connection.recv(65536):
                        chunks.append(chunk)
                response = b"".join(chunks)
                self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response[:100])
                self.assertNotIn(b"synthetic-private", response)
                self.assertNotIn(b"synthetic-only", response)
        self.assertNotIn("Traceback", self.stderr_path.read_text(errors="replace"))

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
        response.read()
        connection.close()

    def test_wrong_host_is_rejected_before_auth(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/", headers={"Host": "evil.example"})
        response = connection.getresponse()
        self.assertEqual(response.status, 421)
        response.read()
        connection.close()

    def test_expect_continue_is_rejected_before_body_upload(self):
        request = (
            f"POST /api/custom/validate HTTP/1.1\r\nHost: {self.host}\r\n"
            "Expect: 100-continue\r\nContent-Type: application/json\r\n"
            "Content-Length: 1000000\r\n\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as connection:
            connection.sendall(request)
            response = connection.recv(4096)
        self.assertRegex(response.split(b"\r\n", 1)[0], rb"^HTTP/1\.1 417 ")
        self.assertNotIn(b"100 Continue", response)

    def test_unsupported_method_obeys_host_boundary(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("TRACE", "/", headers={"Host": "evil.example"})
        response = connection.getresponse()
        self.assertEqual(response.status, 421)
        response.read()
        connection.close()

    def test_unknown_method_also_obeys_host_boundary(self):
        request = b"BREW / HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as connection:
            connection.sendall(request)
            response = connection.recv(4096)
        self.assertRegex(response.split(b"\r\n", 1)[0], rb"^HTTP/1\.1 421 ")

    def test_digest_login_reads_page(self):
        status, payload = self.request("/")
        self.assertEqual(status, 200)
        self.assertTrue(payload == (ROOT / "static" / "index.html").read_bytes(),
                        "authenticated response must match the current index asset")

    def test_md5_digest_fallback_reads_page(self):
        status, payload = self.request("/", algorithm="MD5")
        self.assertEqual(status, 200)
        self.assertTrue(payload == (ROOT / "static" / "index.html").read_bytes(),
                        "authenticated response must match the current index asset")

    def test_cross_site_post_is_rejected(self):
        status, _ = self.request("/api/custom/validate", {"customization": {"rules": [], "fake_ip_filter": []}}, origin=False)
        self.assertEqual(status, 403)

    def test_converter_service_requires_nonce_and_consumes_once(self):
        path = "/api/converter/service"
        status, _ = self.request(path, {"action": "gist_list"})
        self.assertEqual(status, 409)
        status, payload = self.request("/api/bootstrap")
        self.assertEqual(status, 200)
        nonce = json.loads(payload)["nonce"]
        request = {"action": "gist_list", "nonce": nonce}
        status, payload = self.request(path, request)
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(payload)["code"], "SERVICE_CONFIRM")
        # Even rejected operations consume their nonce; no blind write retry.
        status, _ = self.request(path, request)
        self.assertEqual(status, 409)

    def test_converter_service_origin_rejection_preserves_nonce(self):
        _, payload = self.request("/api/bootstrap")
        request = {"action": "gist_list", "nonce": json.loads(payload)["nonce"]}
        status, _ = self.request("/api/converter/service", request, origin=False)
        self.assertEqual(status, 403)
        status, payload = self.request("/api/converter/service", request)
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(payload)["code"], "SERVICE_CONFIRM")

    def test_converter_service_invalid_input_does_not_echo_credentials(self):
        _, payload = self.request("/api/bootstrap")
        marker = "synthetic-invalid-token-value!"
        status, payload = self.request("/api/converter/service", {
            "nonce": json.loads(payload)["nonce"], "action": "gist_list",
            "confirm_external": True, "token": marker,
        })
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(payload)["code"], "SERVICE_AUTH")
        self.assertNotIn(marker.encode(), payload)

    def test_converter_assets_support_authenticated_get_and_head(self):
        for path in ("/converter.js", "/converter_apply.js", "/converter_services.js"):
            with self.subTest(path=path):
                status, content = self.request(path)
                self.assertEqual(status, 200)
                self.assertGreater(len(content), 100)
                status, content = self.request(path, method="HEAD")
                self.assertEqual(status, 200)
                self.assertEqual(content, b"")

    def test_converter_runtime_is_not_an_arbitrary_static_file_mount(self):
        for path in ("/converter_services.py", "/SHA256SUMS", "/../converter_services.py",
                     "/%2e%2e/converter_services.py", "/static/converter_services.js"):
            with self.subTest(path=path):
                status, _ = self.request(path)
                self.assertEqual(status, 404)

    def test_authenticated_custom_validation(self):
        payload = {"customization": {"rules": [{"type": "DOMAIN", "value": "api.example.com", "policy": "DIRECT"}], "fake_ip_filter": ["*.example.com"]}}
        status, response_body = self.request("/api/custom/validate", payload)
        self.assertEqual(status, 200)
        result = json.loads(response_body)
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"rules": 1, "fake_ip_filter": 1})

    def test_rejected_body_cannot_be_reparsed_as_a_second_request(self):
        embedded = f"GET /healthz HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n".encode()
        packet = (f"POST /api/validate HTTP/1.1\r\nHost: {self.host}\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(embedded)}\r\n\r\n").encode() + embedded
        with socket.create_connection(("127.0.0.1", self.port), timeout=4) as sock:
            sock.sendall(packet)
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 401)
            response.read()
            self.assertEqual(response.getheader("Connection"), "close")
            self.assertEqual(sock.recv(1), b"")

    def test_head_health_matches_get_without_a_response_body(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        try:
            connection.request("HEAD", "/healthz", headers={"Host": self.host})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
            self.assertGreater(int(response.getheader("Content-Length")), 0)
            self.assertEqual(response.read(), b"")
            # Prove the HEAD body did not contaminate the next keepalive response.
            connection.request("GET", "/healthz", headers={"Host": self.host})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read())["ok"])
        finally:
            connection.close()

    def test_authenticated_head_api_uses_get_route_without_body(self):
        status, body = self.request("/api/converter/options", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")


if __name__ == "__main__":
    unittest.main()

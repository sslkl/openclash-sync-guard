import importlib.util
import hashlib
import io
import inspect
import os
import pathlib
import sys
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.pop("OPENCLASH_WEB_AUTH_USER", None)
os.environ.pop("OPENCLASH_WEB_AUTH_HA1_FILE", None)
spec = importlib.util.spec_from_file_location("server", ROOT / "server.py")
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)


class ValidationTests(unittest.TestCase):
    def test_valid_openclash_shape(self):
        result = server.validate_yaml("proxies: []\nproxy-groups: []\nrules: []\n")
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"proxies": 0, "groups": 0, "rules": 0})

    def test_error_has_chinese_location(self):
        result = server.validate_yaml("proxies:\n  - name: [\nproxy-groups: []\nrules: []\n")
        self.assertFalse(result["ok"])
        self.assertIn("YAML 语法错误", result["message"])
        self.assertGreaterEqual(result["line"], 2)
        self.assertGreaterEqual(result["column"], 1)

    def test_rejects_wrong_top_level(self):
        result = server.validate_yaml("- one\n- two\n")
        self.assertFalse(result["ok"])
        self.assertIn("顶层", result["message"])

    def test_requires_openclash_sections(self):
        result = server.validate_yaml("proxies: []\n")
        self.assertFalse(result["ok"])
        self.assertIn("proxy-groups", result["message"])

    def test_rejects_recursive_yaml_alias(self):
        result = server.validate_yaml("root: &root\n  child: *root\nproxies: []\nproxy-groups: []\nrules: []\n")
        self.assertFalse(result["ok"])
        self.assertIn("别名", result["message"])

    def test_rejects_yaml_anchor_without_loading_document(self):
        original = server.yaml.safe_load
        server.yaml.safe_load = lambda _value: self.fail("safe_load 不应处理含锚点的文档")
        try:
            result = server.validate_yaml("proxies: &p []\nproxy-groups: []\nrules: []\n")
        finally:
            server.yaml.safe_load = original
        self.assertFalse(result["ok"])
        self.assertIn("锚点", result["message"])

    def test_rejects_deep_yaml_and_invalid_unicode_without_exception(self):
        deep = "value: " + "[" * 500 + "0" + "]" * 500
        self.assertFalse(server.validate_yaml(deep)["ok"])
        self.assertFalse(server.validate_yaml("value: \ud800\nproxies: []\nproxy-groups: []\nrules: []\n")["ok"])

    def test_nonce_is_single_use(self):
        value = server.new_nonce()
        self.assertTrue(server.consume_nonce(value))
        self.assertFalse(server.consume_nonce(value))

    def test_operation_nonce_budget_is_bounded(self):
        previous = dict(server.NONCES)
        server.NONCES.clear()
        try:
            for _ in range(server.MAX_OPERATION_NONCES + 25):
                server.new_nonce()
            self.assertEqual(len(server.NONCES), server.MAX_OPERATION_NONCES)
        finally:
            server.NONCES.clear()
            server.NONCES.update(previous)

    def test_digest_failure_clients_are_bounded(self):
        auth = server.DigestAuth("a" * 64)
        for index in range(server.MAX_AUTH_FAILURE_CLIENTS + 25):
            auth.record_failure(f"client-{index}")
        self.assertEqual(len(auth.failures), server.MAX_AUTH_FAILURE_CLIENTS)

    def test_digest_duplicate_fields_are_rejected(self):
        self.assertEqual(server.DigestAuth.parse('Digest realm="one", realm="two"'), {})
        self.assertEqual(server.DigestAuth.parse('Digest Realm="one", realm="two"'), {})
        self.assertEqual(server.DigestAuth.parse('Digest realm="one", trailing'), {})
        self.assertEqual(server.DigestAuth.parse('Digest realm="one",'), {})

    def test_digest_replay_failure_uses_bounded_failure_path(self):
        source = inspect.getsource(server.DigestAuth.verify)
        self.assertIn("self._record_failure_locked(client, now)", source)
        self.assertNotIn("self.failures.setdefault", source)

    def test_deep_json_is_rejected_without_handler_exception(self):
        body = ('{"value":' + '[' * 100 + '0' + ']' * 100 + '}').encode()
        fake = type("FakeHandler", (), {
            "headers": {"Content-Length": str(len(body)), "Content-Type": "application/json"},
            "rfile": io.BytesIO(body),
            "close_connection": False,
            "header_values": server.Handler.header_values,
        })()
        self.assertIsNone(server.Handler.read_json(fake))

    def test_json_framing_rejects_duplicate_headers_and_short_body(self):
        class Headers:
            def __init__(self, values):
                self.values = values

            def get(self, name, default=None):
                values = self.values.get(name, [])
                return values[0] if values else default

            def get_all(self, name):
                return list(self.values.get(name, []))

        duplicate = type("FakeHandler", (), {
            "headers": Headers({"Content-Length": ["2"], "Content-Type": ["application/json", "text/plain"]}),
            "rfile": io.BytesIO(b"{}"),
            "close_connection": False,
            "header_values": server.Handler.header_values,
        })()
        self.assertIsNone(server.Handler.read_json(duplicate))
        self.assertTrue(duplicate.close_connection)

        short = type("FakeHandler", (), {
            "headers": Headers({"Content-Length": ["3"], "Content-Type": ["application/json"]}),
            "rfile": io.BytesIO(b"{}"),
            "close_connection": False,
            "header_values": server.Handler.header_values,
        })()
        self.assertIsNone(server.Handler.read_json(short))
        self.assertTrue(short.close_connection)

    def test_bridge_validation_checks_root_owned_directory_chain(self):
        self.assertIn("root_owned_directory_chain(path.parent)", inspect.getsource(server.Bridge._validate_helper))

    def test_allowed_origins_are_explicit_and_host_bound(self):
        allowed = {"console.example.test", "127.0.0.1:18088"}
        self.assertEqual(
            server.parse_allowed_origins("https://console.example.test,http://127.0.0.1:18088", allowed),
            {"https://console.example.test", "http://127.0.0.1:18088"},
        )
        authenticated = "https://" + "user" + ":" + "pass" + "@console.example.test"
        for value in ("https://other.example.test", authenticated, "file://console.example.test"):
            with self.assertRaises(RuntimeError):
                server.parse_allowed_origins(value, allowed)

    def test_preview_never_claims_live_write(self):
        result = server.Bridge.demo({"action": "rollback", "target": "router_a"})
        self.assertEqual(result["mode"], "preview")
        self.assertIn("未操作路由器", result["message"])

    def test_managed_file_name_allowlist_shape(self):
        self.assertTrue(server.NAME_RE.fullmatch("Nexitally-Maying_dnspolicy-pilot"))
        self.assertFalse(server.NAME_RE.fullmatch("../etc/passwd"))

    def test_chinese_rollback_phrase(self):
        self.assertTrue(server.valid_rollback_phrase("确认回滚主配置"))
        self.assertFalse(server.valid_rollback_phrase("错误短语"))

    def test_empty_customization_is_valid(self):
        result = server.validate_customization({"rules": [], "fake_ip_filter": []})
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"], {"rules": 0, "fake_ip_filter": 0})

    def test_customization_normalizes_domains_and_networks(self):
        result = server.validate_customization({"rules": [
            {"type": "domain", "value": "API.Example.COM.", "policy": "DIRECT"},
            {"type": "IP-CIDR", "value": "198.51.100.7", "policy": "AI"},
            {"type": "IP-CIDR6", "value": "2001:db8::1", "policy": "Proxies"},
        ], "fake_ip_filter": ["*.Example.COM.", "+.lan"]})
        self.assertTrue(result["ok"])
        self.assertEqual(result["rules"][0]["value"], "api.example.com")
        self.assertEqual(result["rules"][1]["value"], "198.51.100.7/32")
        self.assertEqual(result["rules"][2]["value"], "2001:db8::1/128")
        self.assertEqual(result["fake_ip_filter"], ["*.example.com", "+.lan"])

    def test_customization_reports_precise_rows(self):
        result = server.validate_customization({"rules": [
            {"type": "DOMAIN", "value": "bad_domain", "policy": "DIRECT"},
            {"type": "IP-CIDR", "value": "2001:db8::1", "policy": "AI"},
        ], "fake_ip_filter": ["*", "*.good.test", "*.good.test"]})
        self.assertFalse(result["ok"])
        self.assertIn({"section": "rules", "index": 0, "field": "value", "message": "域名格式错误；示例：api.example.com 或 example.com"}, result["errors"])
        self.assertTrue(any(item["section"] == "fake_ip_filter" and item["index"] == 0 for item in result["errors"]))
        self.assertTrue(any(item["section"] == "fake_ip_filter" and item["index"] == 2 for item in result["errors"]))

    def test_rejects_ipv4_embedded_ipv6_for_router_runtime_compatibility(self):
        result = server.validate_customization({"rules": [
            {"type": "IP-CIDR6", "value": "::ffff:192.0.2.1/128", "policy": "DIRECT"},
        ], "fake_ip_filter": []})
        self.assertFalse(result["ok"])
        self.assertIn("IP/CIDR", result["errors"][0]["message"])

    def test_customization_rejects_duplicate_matcher_even_with_other_policy(self):
        result = server.validate_customization({"rules": [
            {"type": "DOMAIN", "value": "a.example", "policy": "DIRECT"},
            {"type": "DOMAIN", "value": "a.example", "policy": "AI"},
        ], "fake_ip_filter": []})
        self.assertFalse(result["ok"])
        self.assertIn("重复", result["errors"][-1]["message"])

    def test_customization_rejects_non_text_fields(self):
        result = server.validate_customization({"rules": [
            {"type": "DOMAIN", "value": 123, "policy": "DIRECT"},
        ], "fake_ip_filter": [123]})
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"][0]["field"], "row")
        self.assertEqual(result["errors"][1]["section"], "fake_ip_filter")

    def test_digest_sha256_and_replay_protection(self):
        old_user = server.AUTH_USER
        server.AUTH_USER = "admin"
        try:
            password = "test-only-password"
            ha1 = hashlib.sha256(f"admin:{server.AUTH_REALM}:{password}".encode()).hexdigest()
            auth = server.DigestAuth(ha1)
            nonce = auth.new_nonce()
            uri = "/api/status"
            nc = "00000001"
            cnonce = "abcdef12"
            ha2 = hashlib.sha256(f"GET:{uri}".encode()).hexdigest()
            response = hashlib.sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
            header = f'Digest username="admin", realm="{server.AUTH_REALM}", nonce="{nonce}", uri="{uri}", algorithm=SHA-256, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
            self.assertTrue(auth.verify("GET", uri, header, "192.0.2.30"))
            self.assertFalse(auth.verify("GET", uri, header, "192.0.2.30"))
            self.assertFalse(auth.verify("GET", uri, header.replace("nc=00000001", "nc=00000000"), "192.0.2.31"))
            self.assertFalse(auth.verify("GET", uri, "Digest " + "x" * 5000, "192.0.2.32"))
        finally:
            server.AUTH_USER = old_user

    def test_digest_concurrent_replay_allows_exactly_one(self):
        old_user = server.AUTH_USER
        server.AUTH_USER = "admin"
        try:
            ha1 = hashlib.sha256(f"admin:{server.AUTH_REALM}:test-only-password".encode()).hexdigest()
            auth = server.DigestAuth(ha1)
            nonce, uri, nc, cnonce = auth.new_nonce(), "/api/status", "00000001", "abcdef12"
            ha2 = hashlib.sha256(f"GET:{uri}".encode()).hexdigest()
            response = hashlib.sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
            header = f'Digest username="admin", realm="{server.AUTH_REALM}", nonce="{nonce}", uri="{uri}", algorithm=SHA-256, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'
            barrier = threading.Barrier(3)
            results = []

            def attempt():
                barrier.wait()
                results.append(auth.verify("GET", uri, header, "192.0.2.30"))

            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(results), [False, True])
        finally:
            server.AUTH_USER = old_user

    def test_digest_accepts_unique_out_of_order_nonce_counts(self):
        old_user = server.AUTH_USER
        server.AUTH_USER = "admin"
        try:
            ha1 = hashlib.sha256(f"admin:{server.AUTH_REALM}:test-only-password".encode()).hexdigest()
            auth = server.DigestAuth(ha1)
            nonce, uri, cnonce = auth.new_nonce(), "/api/status", "abcdef12"

            def header(number):
                nc = f"{number:08x}"
                ha2 = hashlib.sha256(f"GET:{uri}".encode()).hexdigest()
                response = hashlib.sha256(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
                return f'Digest username="admin", realm="{server.AUTH_REALM}", nonce="{nonce}", uri="{uri}", algorithm=SHA-256, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"'

            self.assertTrue(auth.verify("GET", uri, header(2), "192.0.2.30"))
            self.assertTrue(auth.verify("GET", uri, header(1), "192.0.2.30"))
            self.assertFalse(auth.verify("GET", uri, header(1), "192.0.2.30"))
        finally:
            server.AUTH_USER = old_user


if __name__ == "__main__":
    unittest.main()

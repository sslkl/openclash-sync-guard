import hashlib
import importlib.util
import ipaddress
import inspect
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDORED_PYYAML_ROOT = ROOT.parent / "vendor" / "pyyaml-6.0.2"
sys.path.insert(0, str(VENDORED_PYYAML_ROOT))
os.environ.pop("OPENCLASH_WEB_AUTH_USER", None)
os.environ.pop("OPENCLASH_WEB_AUTH_HA1_FILE", None)
spec = importlib.util.spec_from_file_location("server", ROOT / "server.py")
server = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = server
spec.loader.exec_module(server)


class ValidationTests(unittest.TestCase):
    def test_provider_config_write_is_rejected_before_router_request(self):
        source = inspect.getsource(server.Handler.do_POST)
        reject = source.index("normalized_name != MAIN_CONFIG_NAME")
        bridge = source.index("BRIDGE.call(request)")
        self.assertLess(reject, bridge)

    def test_route_check_binds_decision_to_authenticated_client_source_ip(self):
        source = inspect.getsource(server.Handler.do_POST)
        route = source[source.index('if path == "/api/route-check"'):]
        self.assertIn('source_ip = self.client_address[0]', route)
        self.assertIn('ipaddress.ip_address(source_ip)', route)
        self.assertIn('{"value": value.strip(), "source_ip": source_ip}', route)

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

    def test_rejects_duplicate_and_non_text_mapping_keys(self):
        duplicate = server.validate_yaml("proxies: []\nproxies: []\nproxy-groups: []\nrules: []\n")
        self.assertFalse(duplicate["ok"])
        self.assertIn("duplicate mapping key", duplicate["message"])
        non_text = server.validate_yaml("proxies: []\nproxy-groups: []\nrules: []\ntrue: rejected\n")
        self.assertFalse(non_text["ok"])
        self.assertIn("mapping key must be text", non_text["message"])

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
            "finish_request_reading": server.Handler.finish_request_reading,
        })()
        self.assertIsNone(server.Handler.read_json(fake))

    def test_missing_optional_header_values_are_empty(self):
        headers = type("Headers", (), {"get_all": lambda _self, _name: None})()
        handler = type("FakeHandler", (), {"headers": headers})()
        self.assertEqual(server.Handler.header_values(handler, "Authorization"), [])

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
            "finish_request_reading": server.Handler.finish_request_reading,
        })()
        self.assertIsNone(server.Handler.read_json(duplicate))
        self.assertTrue(duplicate.close_connection)

        short = type("FakeHandler", (), {
            "headers": Headers({"Content-Length": ["3"], "Content-Type": ["application/json"]}),
            "rfile": io.BytesIO(b"{}"),
            "close_connection": False,
            "header_values": server.Handler.header_values,
            "finish_request_reading": server.Handler.finish_request_reading,
        })()
        self.assertIsNone(server.Handler.read_json(short))
        self.assertTrue(short.close_connection)

    def test_bridge_validation_checks_root_owned_directory_chain(self):
        self.assertIn("root_owned_directory_chain(path.parent)", inspect.getsource(server.Bridge._validate_helper))

    def test_bridge_response_schema_rejects_malformed_status_and_health(self):
        status_request = {"action": "status", "target": "router_a"}
        valid_status = {"ok": True, "targets": [{
            "id": "router_a", "name": "路由器 A", "address": "192.0.2.10",
            "state": "运行中", "active": "main.yaml",
        }]}
        self.assertTrue(server.bridge_result_ok(status_request, valid_status))
        poisoned = {"ok": True, "targets": [{**valid_status["targets"][0], "name": "<b>fake</b>"}]}
        self.assertFalse(server.bridge_result_ok(status_request, poisoned))
        stage_request = {"action": "stage_main", "target": "router_a"}
        valid_stage = {"ok": True, "message": "ok", "sha256": "a" * 64, "service_restarted": True, "node_health": {
            "maying": {"passed": 99, "total": 100}, "nexitally": {"passed": 140, "total": 142},
        }}
        self.assertTrue(server.bridge_result_ok(stage_request, valid_stage))
        for field in ("sha256", "service_restarted", "node_health"):
            with self.subTest(missing=field):
                self.assertFalse(server.bridge_result_ok(stage_request, {key: value for key, value in valid_stage.items() if key != field}))
        for field, value in (("sha256", "a" * 63), ("service_restarted", "false"), ("node_health", None)):
            with self.subTest(field=field, value=value):
                self.assertFalse(server.bridge_result_ok(stage_request, {**valid_stage, field: value}))
        self.assertFalse(server.bridge_result_ok(stage_request, {**valid_stage, "node_health": {
            "maying": {"passed": "<img>", "total": 100}, "nexitally": {"passed": 1, "total": 1},
        }}))

    def test_bridge_response_schema_checks_custom_read_elements_without_limiting_baseline_to_editable_items(self):
        request = {"action": "custom_read", "target": "router_a"}
        valid = server.Bridge.demo(request)
        self.assertTrue(server.bridge_result_ok(request, valid))
        self.assertTrue(server.bridge_result_ok(request, {**valid, "configured_rules": ["MATCH,DIRECT"] * 12000}))
        invalid_fields = (
            ("groups", [{}]), ("groups", ["AI", "AI"]), ("rules", ["DOMAIN,x.test,DIRECT"]),
            ("owned_rules", [{"type": "DOMAIN", "value": [], "policy": "DIRECT"}]),
            ("configured_rules", [None]), ("configured_fake_ip_filter", ["bad\nentry"]),
            ("supplemental_rules", ["x" * (server.MAX_EXACT_ITEM + 1)]),
            ("fake_ip_filter", ["*.example.com"] * (server.MAX_CUSTOM_ITEMS + 1)),
            ("config_sha256", None),
        )
        for field, value in invalid_fields:
            with self.subTest(field=field):
                self.assertFalse(server.bridge_result_ok(request, {**valid, field: value}))

    def test_route_result_enum_types_are_rejected_without_exception(self):
        request = {"action": "route_check", "target": "router_a"}
        valid = {"ok": True, "mode": "DIRECT", "reachability": "REACHABLE", "certainty": "EXACT",
                 "policy": "DIRECT", "rule_type": "DOMAIN"}
        self.assertTrue(server.bridge_result_ok(request, valid))
        bridge = server.Bridge()
        bridge.helper = "/synthetic/helper"
        for field in ("mode", "reachability", "certainty"):
            for value in ([], {}, None, True, 1):
                with self.subTest(field=field, value=value):
                    malformed = {**valid, field: value}
                    self.assertFalse(server.bridge_result_ok(request, malformed))
                    output = subprocess.CompletedProcess([], 0, json.dumps(malformed).encode())
                    with mock.patch.object(server.subprocess, "run", return_value=output):
                        self.assertFalse(bridge._call_unlocked(request)["ok"])

    def test_json_shape_rejects_non_utf8_strings_and_nonfinite_numbers(self):
        for value in ({"message": "\ud800"}, {"\udfff": "value"}, {"nested": [float("nan")]}, {"value": float("inf")}):
            with self.subTest(value=repr(value)):
                self.assertFalse(server.json_shape_ok(value))
        self.assertTrue(server.json_shape_ok({"message": "中文", "value": 1.5}))
        self.assertFalse(server.bridge_result_ok({"action": "stage_main"}, {"ok": False, "message": "\ud800"}))

    def test_bridge_does_not_claim_no_commit_after_transport_or_schema_failure(self):
        bridge = server.Bridge()
        bridge.helper = "/synthetic/helper"
        outputs = (subprocess.CompletedProcess([], 1, b""), subprocess.CompletedProcess([], 0, b"{}"),
                   subprocess.CompletedProcess([], 0, b'{"ok": true}'))
        for output in outputs:
            with self.subTest(returncode=output.returncode, output=output.stdout), mock.patch.object(server.subprocess, "run", return_value=output):
                result = bridge._call_unlocked({"action": "stage_main", "target": "router_a"})
                self.assertFalse(result["ok"])
                self.assertIn("UNKNOWN", result["message"])
                self.assertNotIn("未提交任何变更", result["message"])
        with mock.patch.object(server.subprocess, "run", side_effect=subprocess.TimeoutExpired("helper", 420)):
            self.assertIn("UNKNOWN", bridge._call_unlocked({"action": "custom_apply"})["message"])

    def test_main_allows_only_exact_rendered_lan_exposure(self):
        source = inspect.getsource(server.main)
        self.assertIn("bind_address == LAN_BIND_ADDRESS", source)
        self.assertIn("frozenset(ALLOWED_NETWORKS) != LAN_CLIENT_NETWORKS", source)
        self.assertIn("ALLOWED_HOSTS != {expected_host}", source)
        self.assertIn('ALLOWED_ORIGINS != {f"http://{expected_host}"}', source)
        self.assertIn("root_owned_directory_chain(STATIC)", source)
        self.assertIn('raise RuntimeError("OPENCLASH_WEB_HOST 只允许回环地址或 192.0.2.20")', source)
        self.assertIn("if not AUTH_REQUIRED", source)
        self.assertEqual(
            server.LAN_CLIENT_NETWORKS,
            frozenset({ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("127.0.0.0/8")}),
        )

    def test_http_server_has_a_hard_thread_budget(self):
        source = inspect.getsource(server.BoundedThreadingHTTPServer)
        self.assertIn("threading.BoundedSemaphore", source)
        self.assertIn("acquire(blocking=False)", source)
        self.assertIn("self.shutdown_request(request)", source)
        self.assertIn("self._request_slots.release()", source)
        self.assertEqual(server.MAX_HTTP_THREADS, 32)
        self.assertIn("BoundedThreadingHTTPServer((host, port), Handler)", inspect.getsource(server.main))
        handler = inspect.getsource(server.Handler)
        self.assertIn("def handle_expect_100", handler)
        self.assertIn("if code == 501", handler)
        self.assertIn("do_TRACE = method_not_allowed", handler)

    def test_auth_ha1_is_descriptor_bound_and_rejects_links(self):
        old_required = server.AUTH_REQUIRED
        old_path = server.AUTH_HA1_FILE
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory).resolve()
                digest = "a" * 64
                auth = root / "auth-ha1"
                auth.write_text(digest + "\n", encoding="ascii")
                auth.chmod(0o600)
                server.AUTH_REQUIRED = True
                server.AUTH_HA1_FILE = str(auth)
                self.assertEqual(server.read_auth_ha1(), {"SHA-256": digest})

                hardlink = root / "auth-hardlink"
                os.link(auth, hardlink)
                with self.assertRaises(RuntimeError):
                    server.read_auth_ha1()
                hardlink.unlink()

                symlink = root / "auth-symlink"
                symlink.symlink_to(auth)
                server.AUTH_HA1_FILE = str(symlink)
                with self.assertRaises(RuntimeError):
                    server.read_auth_ha1()
        finally:
            server.AUTH_REQUIRED = old_required
            server.AUTH_HA1_FILE = old_path

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

    def test_preview_route_check_is_explicitly_unknown(self):
        result = server.Bridge.demo({"action": "route_check", "target": "router_a", "value": "example.com"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "UNKNOWN")
        self.assertEqual(result["policy"], "UNKNOWN")
        self.assertEqual(result["reachability"], "UNKNOWN")
        self.assertEqual(result["certainty"], "UNKNOWN")

    def test_preview_custom_read_matches_live_contract(self):
        result = server.Bridge.demo({"action": "custom_read", "target": "router_a"})
        self.assertRegex(result["state_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["config_sha256"], result["state_sha256"])
        for key in (
            "supplemental_rules", "supplemental_fake_ip_filter",
            "owned_supplemental_rules", "owned_supplemental_fake_ip_filter",
        ):
            self.assertEqual(result[key], [])
        self.assertIn("IP-CIDR,192.0.2.7,DIRECT", result["configured_rules"])

    def test_read_only_batch_calls_start_both_subnets_concurrently(self):
        bridge = server.Bridge()
        barrier = threading.Barrier(len(server.TARGETS))

        def fake_call(request):
            try:
                barrier.wait(timeout=1)
            except threading.BrokenBarrierError:
                return {"ok": False, "message": "read did not overlap"}
            return {"ok": True, "message": request["target"]}

        bridge._call_unlocked = fake_call
        result = bridge.call_all("custom_read")
        self.assertTrue(result["ok"])
        self.assertEqual(result["completed"], list(server.TARGETS))

    def test_mutating_batch_calls_remain_serial(self):
        source = inspect.getsource(server.Bridge.call_all)
        self.assertIn('{"status", "custom_read", "route_check"}', source)
        self.assertIn("ThreadPoolExecutor", source)
        self.assertNotIn('"stage_main", "custom_read"', source)

    def test_custom_preflight_reads_overlap_under_lock_but_writes_remain_ordered(self):
        bridge = server.Bridge()
        barrier = threading.Barrier(len(server.TARGETS))
        writes = []

        def fake_call(request):
            self.assertTrue(bridge.operation_lock.locked())
            if request["action"] == "custom_read":
                barrier.wait(timeout=2)
                return {**server.Bridge.demo(request), "state_sha256": "a" * 64, "config_sha256": "a" * 64}
            writes.append((request["action"], request["target"]))
            return {"ok": True, "message": "synthetic"}

        bridge._call_unlocked = fake_call
        desired = {"rules": [{"type": "DOMAIN", "value": "saved.example.com", "policy": "DIRECT"}],
                   "fake_ip_filter": ["*.saved.example.com"], "supplemental_rules": [], "supplemental_fake_ip_filter": []}
        hashes = {target: "a" * 64 for target in server.TARGETS}
        result = bridge.custom_apply_all(desired, hashes, hashes)
        self.assertTrue(result["ok"], result)
        self.assertEqual(writes, [(action, target) for action in ("custom_preview", "custom_apply") for target in server.TARGETS])
        self.assertFalse(bridge.operation_lock.locked())

    def test_custom_apply_preserves_partial_commit_when_second_target_fails(self):
        bridge = server.Bridge()
        writes = []

        def fake_call(request):
            if request["action"] == "custom_read":
                return {**server.Bridge.demo(request), "state_sha256": "a" * 64, "config_sha256": "a" * 64}
            writes.append((request["action"], request["target"]))
            return {"ok": not (request["action"] == "custom_apply" and request["target"] == "router_b"),
                    "message": "synthetic"}

        bridge._call_unlocked = fake_call
        hashes = {target: "a" * 64 for target in server.TARGETS}
        result = bridge.custom_apply_all({"rules": [], "fake_ip_filter": [], "supplemental_rules": [],
                                          "supplemental_fake_ip_filter": []}, hashes, hashes)
        self.assertFalse(result["ok"])
        self.assertEqual(result["completed"], ["router_a"])
        self.assertEqual(result["failed"], "router_b")
        self.assertIn("请勿把它视为双子网整体成功", result["message"])
        self.assertEqual(writes, [(action, target) for action in ("custom_preview", "custom_apply") for target in server.TARGETS])
        self.assertFalse(bridge.operation_lock.locked())

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

    def test_configured_rule_fast_path_matches_state_validation(self):
        original = server.validate_customization
        server.validate_customization = lambda _value: self.fail("configured rule fast path must not validate whole state")
        try:
            self.assertEqual(server.configured_rule_matcher("domain,API.Example.COM.,DIRECT,no-resolve"),
                             ("DOMAIN", "api.example.com"))
            self.assertEqual(server.configured_rule_matcher("IP-CIDR,192.0.2.7,AI"),
                             ("IP-CIDR", "192.0.2.7/32"))
            self.assertEqual(server.configured_replayable_rule_matcher("IP-CIDR,192.0.2.7,AI,no-resolve"),
                             ("IP-CIDR", "192.0.2.7/32"))
            self.assertIsNone(server.configured_replayable_rule_matcher("IP-CIDR, 192.0.2.7,AI"))
            self.assertIsNone(server.configured_replayable_rule_matcher("IP-CIDR,192.0.2.7, AI"))
            self.assertIsNone(server.configured_rule_matcher("IP-CIDR6,::ffff:192.0.2.1,DIRECT"))
            self.assertEqual(server.configured_manageable_rule("DOMAIN,api.example.com,DIRECT"),
                             {"type": "DOMAIN", "value": "api.example.com", "policy": "DIRECT"})
        finally:
            server.validate_customization = original

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

    def test_customization_is_sorted_by_safe_category_and_specificity(self):
        result = server.validate_customization({"rules": [
            {"type": "IP-CIDR", "value": "192.0.2.0/24", "policy": "DIRECT"},
            {"type": "DOMAIN-SUFFIX", "value": "example.com", "policy": "Proxies"},
            {"type": "DOMAIN", "value": "z.example", "policy": "DIRECT"},
            {"type": "IP-CIDR", "value": "192.0.2.128/25", "policy": "DIRECT"},
            {"type": "DOMAIN-SUFFIX", "value": "sub.example.com", "policy": "Proxies"},
            {"type": "DOMAIN", "value": "a.example", "policy": "DIRECT"},
        ], "fake_ip_filter": ["*.z.example", "a.example", "+.a.example"]})
        self.assertTrue(result["ok"])
        self.assertEqual(
            [(item["type"], item["value"]) for item in result["rules"]],
            [("DOMAIN", "a.example"), ("DOMAIN", "z.example"),
             ("DOMAIN-SUFFIX", "sub.example.com"), ("DOMAIN-SUFFIX", "example.com"),
             ("IP-CIDR", "192.0.2.0/24"), ("IP-CIDR", "192.0.2.128/25")],
        )
        self.assertEqual(result["fake_ip_filter"], ["a.example", "+.a.example", "*.z.example"])

    def test_customization_rejects_worst_case_owned_state_over_one_mib(self):
        oversized = [f"opaque-{index}-" + "x" * 8160 for index in range(70)]
        result = server.validate_customization({
            "rules": [], "fake_ip_filter": [], "supplemental_rules": [],
            "supplemental_fake_ip_filter": oversized,
        })
        self.assertFalse(result["ok"])
        self.assertIn("1 MiB", result["message"])

    def test_merge_custom_reads_unions_both_subnets_and_preserves_both_hashes(self):
        empty = hashlib.sha256(b"").hexdigest()
        results = {
            "router_a": {"groups": ["Proxies", "AI"], "rules": [
                {"type": "DOMAIN", "value": "A.Example.", "policy": "DIRECT"},
            ], "fake_ip_filter": ["*.one.example"], "owned_rules": [], "owned_fake_ip_filter": [],
                "configured_rules": ["DOMAIN,a.example,DIRECT"],
                "configured_fake_ip_filter": ["*.one.example"], "state_sha256": empty},
            "router_b": {"groups": ["Proxies", "AI"], "rules": [
                {"type": "IP-CIDR", "value": "192.0.2.7", "policy": "AI"},
            ], "fake_ip_filter": ["+.two.example"], "owned_rules": [], "owned_fake_ip_filter": [],
                "configured_rules": ["IP-CIDR,192.0.2.7/32,AI"],
                "configured_fake_ip_filter": ["+.two.example"], "state_sha256": "a" * 64},
        }
        merged = server.merge_custom_reads(results)
        self.assertTrue(merged["ok"])
        self.assertTrue(merged["diverged"])
        self.assertEqual(merged["state_sha256"], {"router_a": empty, "router_b": "a" * 64})
        self.assertEqual([item["value"] for item in merged["rules"]], ["a.example", "192.0.2.7/32"])

    def test_merge_custom_reads_rejects_cross_subnet_policy_conflict(self):
        base = {"groups": ["Proxies", "AI"], "fake_ip_filter": [], "owned_rules": [],
                "owned_fake_ip_filter": [], "configured_fake_ip_filter": [], "state_sha256": "a" * 64}
        results = {
            "router_a": {**base, "rules": [{"type": "DOMAIN", "value": "same.example", "policy": "DIRECT"}],
                         "configured_rules": ["DOMAIN,same.example,DIRECT"]},
            "router_b": {**base, "state_sha256": "b" * 64,
                          "rules": [{"type": "DOMAIN", "value": "same.example", "policy": "AI"}],
                          "configured_rules": ["DOMAIN,same.example,AI"]},
        }
        merged = server.merge_custom_reads(results)
        self.assertFalse(merged["ok"])
        self.assertIn("不同策略", merged["message"])

    def test_merge_custom_reads_imports_safe_one_sided_baseline_delta(self):
        base = {
            "groups": ["Proxies", "AI"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "state_sha256": "a" * 64,
        }
        results = {
            "router_a": {
                **base,
                "configured_rules": ["DOMAIN,one-sided.example,DIRECT", "MATCH,Proxies"],
                "configured_fake_ip_filter": ["*.one-sided.example"],
            },
            "router_b": {
                **base, "state_sha256": "b" * 64,
                "configured_rules": ["MATCH,Proxies"], "configured_fake_ip_filter": [],
            },
        }
        merged = server.merge_custom_reads(results)
        self.assertTrue(merged["ok"])
        self.assertTrue(merged["diverged"])
        self.assertEqual(merged["rules"], [
            {"type": "DOMAIN", "value": "one-sided.example", "policy": "DIRECT"},
        ])
        self.assertEqual(merged["fake_ip_filter"], ["*.one-sided.example"])
        self.assertEqual(merged["editable_rules"], [])
        self.assertEqual(merged["editable_fake_ip_filter"], [])
        self.assertEqual(merged["reconciliation_rules"], merged["rules"])
        self.assertEqual(merged["reconciliation_fake_ip_filter"], merged["fake_ip_filter"])
        self.assertEqual(merged["baseline_delta"]["rules"], 1)
        self.assertEqual(merged["baseline_delta"]["fake_ip_filter"], 1)
        self.assertTrue(merged["repairable_diverged"])

    def test_public_custom_read_keeps_ui_contract_and_hides_internal_indexes(self):
        merged = {
            "ok": True, "message": "ok", "rules": [], "editable_rules": [],
            "state_sha256": {"router_a": "a" * 64, "router_b": "b" * 64},
            "unowned_configured_rules": [
                "IP-CIDR,192.0.2.7,DIRECT", "IP-CIDR,192.0.2.7/24,DIRECT",
                "IP-CIDR6,2001:db8::1,DIRECT", "DOMAIN,visible.example,DIRECT",
            ],
            "unowned_rules_by_target": {"router_a": ["private"]},
            "unowned_rule_matchers_by_target": {"router_a": [["DOMAIN", "private"]]},
            "missing_managed_by_target": {"router_a": {"rules": ["private"]}},
        }
        public = server.public_custom_read(merged)
        self.assertEqual(public["unowned_configured_rules"], [
            "IP-CIDR,192.0.2.7,DIRECT", "IP-CIDR,192.0.2.7/24,DIRECT",
            "IP-CIDR6,2001:db8::1,DIRECT", "DOMAIN,visible.example,DIRECT",
        ])
        self.assertEqual(public["unowned_rule_matcher_overrides"], [
            [0, "IP-CIDR", "192.0.2.7/32"],
            [1, "IP-CIDR", "192.0.2.0/24"],
            [2, "IP-CIDR6", "2001:db8::1/128"],
        ])
        self.assertNotIn("unowned_rules_by_target", public)
        self.assertNotIn("unowned_rule_matchers_by_target", public)
        self.assertNotIn("missing_managed_by_target", public)

    def test_merge_custom_reads_imports_exact_domain_ip_rule_with_no_resolve(self):
        base = {
            "groups": ["Proxies"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "configured_fake_ip_filter": [],
            "state_sha256": "a" * 64,
        }
        results = {
            "router_a": {**base, "configured_rules": ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"]},
            "router_b": {**base, "state_sha256": "b" * 64, "configured_rules": []},
        }
        merged = server.merge_custom_reads(results)
        self.assertTrue(merged["ok"])
        self.assertTrue(merged["diverged"])
        self.assertTrue(merged["repairable_diverged"])
        self.assertEqual(merged["baseline_delta"]["unresolved_rules"], 0)
        self.assertEqual(merged["baseline_delta"]["exact_rules"], 1)
        self.assertEqual(merged["rules"], [])
        self.assertEqual(merged["supplemental_rules"], ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"])

    def test_merge_custom_reads_leaves_unreplayable_rule_as_unresolved(self):
        base = {
            "groups": ["Proxies"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "configured_fake_ip_filter": [],
            "state_sha256": "a" * 64,
        }
        raw = "IP-CIDR, 192.0.2.7,DIRECT"
        results = {
            "router_a": {**base, "configured_rules": [raw]},
            "router_b": {**base, "state_sha256": "b" * 64, "configured_rules": []},
        }
        merged = server.merge_custom_reads(results)
        self.assertTrue(merged["ok"])
        self.assertEqual(merged["supplemental_rules"], [])
        self.assertEqual(merged["baseline_delta"]["unresolved_rules"], 1)
        self.assertIn(raw, merged["unowned_configured_rules"])

    def test_customization_rejects_unreplayable_supplemental_rule_before_preview(self):
        result = server.validate_customization({
            "rules": [], "fake_ip_filter": [],
            "supplemental_rules": ["IP-CIDR, 192.0.2.7,DIRECT"],
            "supplemental_fake_ip_filter": [],
        })
        self.assertFalse(result["ok"])
        self.assertIn("有效的域名/IP 规则", result["errors"][0]["message"])

    def test_merge_custom_reads_imports_noncanonical_fake_filter_as_exact_text(self):
        base = {
            "groups": ["Proxies"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "configured_rules": [],
            "state_sha256": "a" * 64,
        }
        results = {
            "router_a": {**base, "configured_fake_ip_filter": ["GEOSITE:private"]},
            "router_b": {**base, "state_sha256": "b" * 64, "configured_fake_ip_filter": []},
        }
        merged = server.merge_custom_reads(results)
        self.assertTrue(merged["ok"])
        self.assertEqual(merged["supplemental_fake_ip_filter"], ["GEOSITE:private"])
        self.assertEqual(merged["baseline_delta"]["exact_fake_ip_filter"], 1)

    def test_merge_custom_reads_rejects_asymmetric_baseline_matcher_conflict(self):
        base = {
            "groups": ["Proxies", "AI"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "configured_fake_ip_filter": [],
            "state_sha256": "a" * 64,
        }
        results = {
            "router_a": {**base, "configured_rules": ["DOMAIN,conflict.example,DIRECT"]},
            "router_b": {**base, "state_sha256": "b" * 64,
                          "configured_rules": ["DOMAIN,conflict.example,AI"]},
        }
        merged = server.merge_custom_reads(results)
        self.assertFalse(merged["ok"])
        self.assertIn("同匹配条件冲突", merged["message"])

    def test_merge_custom_reads_rejects_owned_exact_rule_against_other_baseline_form(self):
        base = {
            "groups": ["Proxies"], "rules": [], "fake_ip_filter": [],
            "owned_rules": [], "owned_fake_ip_filter": [], "supplemental_fake_ip_filter": [],
            "owned_supplemental_fake_ip_filter": [], "configured_fake_ip_filter": [],
            "state_sha256": "a" * 64,
        }
        exact = "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"
        results = {
            "router_a": {**base, "supplemental_rules": [exact], "owned_supplemental_rules": [exact],
                         "configured_rules": [exact, "MATCH,Proxies"]},
            "router_b": {**base, "state_sha256": "b" * 64, "supplemental_rules": [],
                          "owned_supplemental_rules": [],
                          "configured_rules": ["IP-CIDR,192.0.2.0/24,DIRECT", "MATCH,Proxies"]},
        }
        merged = server.merge_custom_reads(results)
        self.assertFalse(merged["ok"])
        self.assertIn("同匹配条件冲突", merged["message"])

    def test_custom_ownership_separates_owned_prefix_from_subscription_baseline(self):
        result = {
            "rules": [
                {"type": "DOMAIN", "value": "owned.example", "policy": "DIRECT"},
                {"type": "DOMAIN-SUFFIX", "value": "base.example", "policy": "AI"},
            ],
            "fake_ip_filter": ["*.owned.example", "*.base.example"],
            "owned_rules": [{"type": "DOMAIN", "value": "owned.example", "policy": "DIRECT"}],
            "owned_fake_ip_filter": ["*.owned.example"],
            "configured_rules": [
                "DOMAIN,owned.example,DIRECT", "DOMAIN-SUFFIX,base.example,AI", "MATCH,Proxies",
            ],
            "configured_fake_ip_filter": ["*.base.example", "*.owned.example"],
        }
        ownership = server.analyze_custom_ownership(result)
        self.assertIsNotNone(ownership)
        self.assertEqual(ownership["unowned_rules"], ["DOMAIN-SUFFIX,base.example,AI", "MATCH,Proxies"])
        self.assertEqual(ownership["unowned_filters"], ["*.base.example"])

    def test_custom_ownership_reports_missing_unowned_intent_as_repairable_drift(self):
        result = {
            "rules": [{"type": "DOMAIN", "value": "missing.example", "policy": "DIRECT"}],
            "fake_ip_filter": ["*.missing.example"],
            "owned_rules": [], "owned_fake_ip_filter": [],
            "configured_rules": ["MATCH,Proxies"], "configured_fake_ip_filter": [],
        }
        ownership = server.analyze_custom_ownership(result)
        self.assertIsNotNone(ownership)
        self.assertEqual(ownership["missing_rules"], ["DOMAIN,missing.example,DIRECT"])
        self.assertEqual(ownership["missing_filters"], ["*.missing.example"])

    def test_custom_ownership_rejects_owned_rule_outside_config_prefix(self):
        result = {
            "rules": [{"type": "DOMAIN", "value": "owned.example", "policy": "DIRECT"}],
            "fake_ip_filter": [],
            "owned_rules": [{"type": "DOMAIN", "value": "owned.example", "policy": "DIRECT"}],
            "owned_fake_ip_filter": [],
            "configured_rules": ["MATCH,Proxies", "DOMAIN,owned.example,DIRECT"],
            "configured_fake_ip_filter": [],
        }
        self.assertIsNone(server.analyze_custom_ownership(result))

    def test_custom_apply_preflight_blocks_new_rule_already_in_subscription_on_either_subnet(self):
        bridge = server.Bridge()
        calls = []
        reads = {
            target: {
                "ok": True, "groups": ["DIRECT", "Proxies"], "rules": [], "fake_ip_filter": [],
                "owned_rules": [], "owned_fake_ip_filter": [],
                "configured_rules": ["DOMAIN,existing.example,DIRECT", "MATCH,Proxies"],
                "configured_fake_ip_filter": [], "state_sha256": value, "config_sha256": value,
            }
            for target, value in (("router_a", "a" * 64), ("router_b", "b" * 64))
        }

        def fake_call(request):
            calls.append(dict(request))
            return reads[request["target"]]

        bridge._call_unlocked = fake_call
        result = bridge.custom_apply_all(
            {"rules": [{"type": "DOMAIN", "value": "existing.example", "policy": "DIRECT"}],
             "fake_ip_filter": []},
            {"router_a": "a" * 64, "router_b": "b" * 64},
            {"router_a": "a" * 64, "router_b": "b" * 64},
        )
        self.assertFalse(result["ok"])
        self.assertIn("不能重复增加", result["message"])
        self.assertEqual([item["action"] for item in calls], ["custom_read", "custom_read"])

    def test_custom_apply_allows_safe_one_sided_baseline_reconciliation(self):
        bridge = server.Bridge()
        calls = []
        reads = {
            "router_a": {
                "ok": True, "groups": ["DIRECT", "Proxies"], "rules": [], "fake_ip_filter": [],
                "owned_rules": [], "owned_fake_ip_filter": [],
                "configured_rules": ["DOMAIN,one-sided.example,DIRECT", "MATCH,Proxies"],
                "configured_fake_ip_filter": [], "state_sha256": "a" * 64, "config_sha256": "a" * 64,
            },
            "router_b": {
                "ok": True, "groups": ["DIRECT", "Proxies"], "rules": [], "fake_ip_filter": [],
                "owned_rules": [], "owned_fake_ip_filter": [], "configured_rules": ["MATCH,Proxies"],
                "configured_fake_ip_filter": [], "state_sha256": "b" * 64, "config_sha256": "b" * 64,
            },
        }

        def fake_call(request):
            calls.append(dict(request))
            if request["action"] == "custom_read":
                return reads[request["target"]]
            return {"ok": True, "message": "synthetic apply"}

        bridge._call_unlocked = fake_call
        desired = {"rules": [
            {"type": "DOMAIN", "value": "one-sided.example", "policy": "DIRECT"},
        ], "fake_ip_filter": []}
        result = bridge.custom_apply_all(
            desired,
            {"router_a": "a" * 64, "router_b": "b" * 64},
            {"router_a": "a" * 64, "router_b": "b" * 64},
        )
        self.assertTrue(result["ok"])
        self.assertEqual([item["action"] for item in calls],
                         ["custom_read", "custom_read", "custom_preview", "custom_preview",
                          "custom_apply", "custom_apply"])

    def test_custom_apply_previews_both_targets_before_any_write(self):
        bridge = server.Bridge()
        calls = []
        reads = {
            target: {
                "ok": True, "groups": ["DIRECT", "Proxies"], "rules": [], "fake_ip_filter": [],
                "owned_rules": [], "owned_fake_ip_filter": [], "configured_rules": ["MATCH,Proxies"],
                "configured_fake_ip_filter": [], "state_sha256": digest, "config_sha256": digest,
            }
            for target, digest in (("router_a", "a" * 64), ("router_b", "b" * 64))
        }

        def fake_call(request):
            calls.append(dict(request))
            if request["action"] == "custom_read":
                return reads[request["target"]]
            if request["action"] == "custom_preview" and request["target"] == "router_b":
                return {"ok": False, "message": "synthetic preview rejection"}
            return {"ok": True, "message": "synthetic"}

        bridge._call_unlocked = fake_call
        result = bridge.custom_apply_all(
            {"rules": [], "fake_ip_filter": [], "supplemental_rules": [],
             "supplemental_fake_ip_filter": []},
            {"router_a": "a" * 64, "router_b": "b" * 64},
            {"router_a": "a" * 64, "router_b": "b" * 64},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["completed"], [])
        self.assertEqual([item["action"] for item in calls],
                         ["custom_read", "custom_read", "custom_preview", "custom_preview"])

    def test_custom_apply_rejects_main_config_change_even_when_state_is_unchanged(self):
        bridge = server.Bridge()
        calls = []

        def fake_call(request):
            calls.append(dict(request))
            return {
                "ok": True, "groups": ["DIRECT"], "rules": [], "fake_ip_filter": [],
                "owned_rules": [], "owned_fake_ip_filter": [], "configured_rules": [],
                "configured_fake_ip_filter": [], "state_sha256": "a" * 64, "config_sha256": "c" * 64,
            }

        bridge._call_unlocked = fake_call
        result = bridge.custom_apply_all(
            {"rules": [], "fake_ip_filter": [], "supplemental_rules": [],
             "supplemental_fake_ip_filter": []},
            {"router_a": "a" * 64, "router_b": "a" * 64},
            {"router_a": "b" * 64, "router_b": "b" * 64},
        )
        self.assertFalse(result["ok"])
        self.assertIn("主配置已变化", result["message"])
        self.assertEqual([item["action"] for item in calls], ["custom_read", "custom_read"])

    def test_user_facing_target_names_are_subnets_but_internal_ids_stay_stable(self):
        self.assertEqual(list(server.TARGETS), ["router_a", "router_b"])
        self.assertEqual([item.name for item in server.TARGETS.values()], ["路由器 A", "路由器 B"])

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
            self.assertTrue(auth.verify("GET", uri, header, "198.51.100.10"))
            self.assertFalse(auth.verify("GET", uri, header, "198.51.100.10"))
            self.assertFalse(auth.verify("GET", uri, header.replace("nc=00000001", "nc=00000000"), "198.51.100.11"))
            self.assertFalse(auth.verify("GET", uri, "Digest " + "x" * 5000, "198.51.100.12"))
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
                results.append(auth.verify("GET", uri, header, "198.51.100.10"))

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

            self.assertTrue(auth.verify("GET", uri, header(2), "198.51.100.10"))
            self.assertTrue(auth.verify("GET", uri, header(1), "198.51.100.10"))
            self.assertFalse(auth.verify("GET", uri, header(1), "198.51.100.10"))
        finally:
            server.AUTH_USER = old_user


if __name__ == "__main__":
    unittest.main()

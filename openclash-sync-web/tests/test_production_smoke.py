#!/usr/bin/env python3
"""production_smoke 公开响应形状的离线回归。"""

from __future__ import annotations

import unittest

import production_custom_acceptance as acceptance
import production_smoke as smoke


class ProductionSmokeTests(unittest.TestCase):
    def test_homepage_validation_accepts_current_title_for_both_auth_algorithms(self):
        page = '<title>全新控制台标题</title><img src="OpenClash_Sync_Logo.png">'.encode()
        for algorithm in ("SHA-256", "MD5"):
            with self.subTest(algorithm=algorithm):
                smoke.validate_homepage(200, page, page, algorithm)

    def test_homepage_validation_rejects_changed_body_even_with_matching_title(self):
        expected = b'<title>OpenClash</title><img src="OpenClash_Sync_Logo.png">'
        with self.assertRaises(RuntimeError):
            smoke.validate_homepage(200, expected + b"unexpected", expected, "SHA-256")

    def test_homepage_validation_rejects_non_success_status_and_missing_logo(self):
        page = b"OpenClash_Sync_Logo.png"
        for status, body in ((401, page), (500, page), (200, b""), (200, b"wrong page")):
            with self.subTest(status=status, bytes=len(body)):
                with self.assertRaises(RuntimeError):
                    smoke.validate_homepage(status, body, body, "MD5")

    def test_homepage_validation_rejects_malformed_bytes_without_decoding(self):
        with self.assertRaises(RuntimeError):
            smoke.validate_homepage(200, b"\xff", b"OpenClash_Sync_Logo.png", "SHA-256")

    def valid_custom(self) -> dict:
        return {
            "rules": [{"type": "DOMAIN", "value": "saved.example", "policy": "DIRECT"}],
            "fake_ip_filter": ["*.saved.example"],
            "supplemental_rules": ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"],
            "supplemental_fake_ip_filter": ["+.raw.example"],
            "unowned_configured_rules": ["IP-CIDR,192.0.2.7,DIRECT"],
            "unowned_rule_matcher_overrides": [[0, "IP-CIDR", "192.0.2.7/32"]],
        }

    def test_nonempty_legitimate_customization_is_accepted(self):
        counts = smoke.validate_custom_read(self.valid_custom())
        self.assertEqual(counts["rules"], 1)
        self.assertEqual(counts["fake_ip_filter"], 1)
        self.assertEqual(counts["supplemental_rules"], 1)
        self.assertEqual(counts["unowned_rule_matcher_overrides"], 1)

    def test_malformed_customization_is_rejected_without_reading_values(self):
        invalid_values = [
            {**self.valid_custom(), "rules": [{"type": "DOMAIN", "value": "", "policy": "DIRECT"}]},
            {**self.valid_custom(), "fake_ip_filter": [1]},
            {**self.valid_custom(), "supplemental_rules": None},
            {**self.valid_custom(), "unowned_rule_matcher_overrides": [[0, "IP-CIDR"]]},
            {**self.valid_custom(), "unowned_rule_matcher_overrides": [[-1, "IP-CIDR", "192.0.2.7/32"]]},
        ]
        for value in invalid_values:
            with self.subTest(value=list(value)):
                with self.assertRaises(RuntimeError):
                    smoke.validate_custom_read(value)

    def test_default_endpoint_is_exact_production_lan_address(self):
        self.assertEqual((smoke.HOST, smoke.PORT), ("192.0.2.20", 8088))
        self.assertEqual(smoke.ORIGIN, "http://192.0.2.20:8088")

    def test_noop_acceptance_requires_both_targets_and_preserves_all_hashes(self):
        before = {
            "rules": [{"type": "DOMAIN", "value": "saved.example", "policy": "DIRECT"}],
            "fake_ip_filter": [],
            "supplemental_rules": ["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve"],
            "supplemental_fake_ip_filter": ["+.raw.example"],
            "state_sha256": {"router_a": "a" * 64, "router_b": "b" * 64},
            "config_sha256": {"router_a": "c" * 64, "router_b": "d" * 64},
        }
        result = {
            "completed": ["router_a", "router_b"],
            "failed": None,
            "results": {
                target: {"ok": True, "message": "定制状态已保存；主配置内容未变化，因此未重启 OpenClash"}
                for target in acceptance.TARGETS
            },
        }
        acceptance.verify_noop_preserved(before, result, dict(before))

        changed = {**before, "config_sha256": {**before["config_sha256"], "router_b": "e" * 64}}
        with self.assertRaises(RuntimeError):
            acceptance.verify_noop_preserved(before, result, changed)

        partial = {**result, "completed": ["router_a"], "failed": "router_b"}
        with self.assertRaises(RuntimeError):
            acceptance.verify_noop_preserved(before, partial, dict(before))

    def test_custom_acceptance_requires_explicit_mode(self):
        with self.assertRaises(SystemExit) as context:
            acceptance.main([])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

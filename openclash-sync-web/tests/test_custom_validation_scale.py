"""Large synthetic inputs preserve duplicate/error and sort semantics."""
import unittest

from test_server import server


class CustomValidationScaleTests(unittest.TestCase):
    def test_ten_thousand_unique_supplemental_filters_keep_the_exact_sorted_items(self):
        values = [f"f{i:05d}.test" for i in reversed(range(10_000))]
        result = server.validate_customization({"supplemental_fake_ip_filter": values})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["supplemental_fake_ip_filter"], sorted(values))
        self.assertEqual(result["summary"]["fake_ip_filter"], 10_000)
        self.assertEqual(values[0], "f09999.test")

    def test_ten_thousand_unique_supplemental_rules_keep_the_exact_sorted_items(self):
        values = [f"DOMAIN,r{i:05d}.test,DIRECT" for i in reversed(range(10_000))]
        result = server.validate_customization({"supplemental_rules": values})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["supplemental_rules"], sorted(values))
        self.assertEqual(result["summary"]["rules"], 10_000)

    def test_exact_filter_duplicates_retain_original_error_precedence(self):
        for value in ("example.test", "*.example.test", "*", "geosite:cn"):
            with self.subTest(value=value):
                result = server.validate_customization({"supplemental_fake_ip_filter": [value, value]})
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"], [{"section": "root", "index": 1,
                    "field": "supplemental_fake_ip_filter", "message": "完整 Fake-IP 补齐项重复"}])

    def test_equivalent_filter_duplicates_still_conflict_with_structured_or_supplemental(self):
        for payload in ({"fake_ip_filter": ["example.test"], "supplemental_fake_ip_filter": ["EXAMPLE.TEST."]},
                        {"supplemental_fake_ip_filter": ["example.test", "EXAMPLE.TEST."]}):
            result = server.validate_customization(payload)
            self.assertFalse(result["ok"])
            self.assertEqual(result["errors"][0]["message"], "完整 Fake-IP 补齐项与现有条目等价重复")

    def test_rule_matcher_duplicates_keep_precedence_over_exact_text(self):
        for duplicate in ("DOMAIN,example.test,DIRECT", "DOMAIN,EXAMPLE.TEST.,Other"):
            result = server.validate_customization({"supplemental_rules": ["DOMAIN,example.test,DIRECT", duplicate]})
            self.assertFalse(result["ok"])
            self.assertEqual(result["errors"][0]["message"], "完整规则补齐项与现有匹配条件重复")

    def test_item_count_and_state_size_limits_are_not_weakened(self):
        result = server.validate_customization({"supplemental_fake_ip_filter": [f"f{i}.test" for i in range(10_001)]})
        self.assertFalse(result["ok"])
        self.assertTrue(any("最多 10000 条" in item["message"] for item in result["errors"]))
        result = server.validate_customization({"supplemental_fake_ip_filter": [f"opaque:{i}:" + "a" * 8000 for i in range(100)]})
        self.assertFalse(result["ok"])
        self.assertIn("1 MiB", result["message"])


if __name__ == "__main__":
    unittest.main()

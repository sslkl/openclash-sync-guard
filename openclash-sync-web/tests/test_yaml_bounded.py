"""One-pass YAML parser limits, with synthetic inputs only."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT.parent / 'vendor' / 'pyyaml-6.0.2')]
import yaml
import converter_formats as formats
import server
from subscription_converter import ConverterError


class BoundedYamlTests(unittest.TestCase):
    def test_both_entrypoints_do_not_run_a_separate_scanner(self):
        text = 'proxies: []\nproxy-groups: []\nrules: []\n'
        with patch.object(yaml, 'scan', side_effect=AssertionError('duplicate scan')):
            self.assertTrue(server.validate_yaml(text)['ok'])
            self.assertEqual(formats.yaml_load(text)['proxies'], [])

    def test_anchor_alias_tags_duplicate_and_complex_keys_still_rejected(self):
        for value in ['x: &a []', 'x: *a', 'x: !!python/object:os.system {}',
                      'x: 1\nx: 2', '? [a, b]\n: value', '<<: {}', 'true: value']:
            with self.subTest(value=value):
                with self.assertRaises(ConverterError): formats.yaml_load(value)
                self.assertFalse(server.validate_yaml('proxies: []\nproxy-groups: []\nrules: []\n' + value)['ok'])

    def test_token_budget_is_enforced_during_parse(self):
        class Tiny(formats.UniqueLoader):
            max_tokens = 3
        with self.assertRaises(yaml.YAMLError): yaml.load('x: 1', Loader=Tiny)

    def test_value_node_budget_excludes_mapping_keys_and_rejects_one_extra(self):
        class Tiny(formats.UniqueLoader):
            max_nodes = 3
        self.assertEqual(yaml.load('a: 1\nb: 2', Loader=Tiny), {'a': 1, 'b': 2})
        with self.assertRaises(yaml.YAMLError): yaml.load('a: 1\nb: 2\nc: 3', Loader=Tiny)

    def test_depth_is_rejected_before_unbounded_composition(self):
        class Tiny(formats.UniqueLoader):
            max_depth = 3
        self.assertEqual(yaml.load('a: [0]', Loader=Tiny), {'a': [0]})
        with self.assertRaises(yaml.YAMLError): yaml.load('a: [[0]]', Loader=Tiny)
        with self.assertRaises(ConverterError): formats.yaml_load('x: ' + '[' * 2000 + '0' + ']' * 2000)

    def test_converter_zero_based_depth_boundary_preserved(self):
        self.assertEqual(formats.yaml_load('[' * 32 + '0' + ']' * 32), json.loads('[' * 32 + '0' + ']' * 32))
        with self.assertRaises(ConverterError): formats.yaml_load('[' * 33 + '0' + ']' * 33)

    def test_main_depth_and_node_limits_remain_independent(self):
        content = 'proxies: []\nproxy-groups: []\nrules: []\nx: ' + '[' * 40 + '0' + ']' * 40
        self.assertTrue(server.validate_yaml(content)['ok'])
        with self.assertRaises(ConverterError): formats.yaml_load(content)

    def test_repeated_parses_have_independent_budgets(self):
        for _ in range(3): self.assertEqual(formats.yaml_load('a: [1, 2]'), {'a': [1, 2]})

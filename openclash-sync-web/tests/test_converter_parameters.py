"""Synthetic custom-template parameters, link parity and privilege boundaries."""
import base64
import io
import json
import tarfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import subscription_converter as c
import converter_engine as engine
import converter_sandbox as sandbox

SOURCE = 'https://example.test/source'
YAML = 'proxies: []\n'


def payload(parameters=None, remote=False):
    return {'form': {'sources': [SOURCE] if remote else '', 'options': {'target': 'clash'},
                     'parameters': {} if parameters is None else parameters},
            'uploads': [] if remote else [YAML]}


def job(parameters=None, content=YAML):
    return {'version': 1, 'files': [{'name': 's000.txt', 'body': base64.b64encode(content.encode()).decode()}],
            'source_names': ['s000.txt'], 'options': {'target': 'clash', 'parameters': parameters or {}}}


class ParameterTests(unittest.TestCase):
    def test_privileged_contract_is_identical_but_import_independent(self):
        self.assertEqual(c.RESERVED_PARAMETERS, sandbox.RESERVED_PARAMETERS)
        self.assertEqual(c.PARAMETER_KEY_PATTERN, sandbox.PARAMETER_KEY_PATTERN)
        self.assertEqual(c.MAX_PARAMETERS, sandbox.MAX_PARAMETERS)
        self.assertEqual(c.MAX_PARAMETER_BYTES, sandbox.MAX_PARAMETER_BYTES)
        caps = c.capabilities()['parameters']
        self.assertEqual(caps['reserved'], sorted(c.RESERVED_PARAMETERS))
        caps['reserved'].clear()
        self.assertTrue(c.capabilities()['parameters']['reserved'])

    def test_link_roundtrip_empty_values_unicode_query_characters_and_legacy(self):
        values = {'title': '合成 & target=surge + 50% | \"', 'empty': '', 'Dns.Title-1': '示例'}
        request = c.validate({'sources': SOURCE, 'parameters': values})
        self.assertEqual(c.parse_link(request.link()).parameters, values)
        self.assertEqual(c.parse_link(request.link()).options, {'target': 'clash'})
        self.assertEqual(request.public_form()['parameters'], values)
        values['title'] = 'changed'
        self.assertNotEqual(request.parameters['title'], 'changed')
        for public in (repr(request), json.dumps(request.summary())):
            self.assertNotIn('合成', public)
            self.assertNotIn('Dns.Title', public)
        self.assertNotIn('parameters', c.validate({'sources': SOURCE}).public_form())
        self.assertEqual(c.ConversionRequest(c.DEFAULT_BACKEND, (SOURCE,), {'target': 'clash'}, 'router_a').parameters, {})

    def test_known_options_cannot_escape_strict_option_validation(self):
        with self.assertRaises(c.ConverterError):
            c.validate({'sources': SOURCE, 'options': {'title': 'not an option'}})
        self.assertEqual(c.parse_link(c.DEFAULT_BACKEND + '?url=' + SOURCE + '&title=custom').parameters, {'title': 'custom'})
        for query in ('title=x&title=y', 'title=x&%74itle=y', 'URL=x', 'TOKEN=x', 'path=./pref.ini'):
            with self.subTest(query=query), self.assertRaises(c.ConverterError):
                c.parse_link(c.DEFAULT_BACKEND + '?url=' + SOURCE + '&' + query)

    def test_reserved_fields_all_cases_rejected_at_both_boundaries(self):
        for key in c.RESERVED_PARAMETERS:
            for name in (key, key.upper(), key.capitalize()):
                with self.subTest(name=name):
                    with self.assertRaises(c.ConverterError): c.parameters({name: 'synthetic-secret'})
                    with self.assertRaises(sandbox.SandboxError): sandbox.validate_parameters({name: 'synthetic-secret'})

    def test_shape_count_key_utf8_and_controls_rejected_without_leak(self):
        bad = [None, [], 'x', {'x': None}, {'x': 1}, {'x': True}, {'x': []}, {1: 'x'},
               {'a' * 65: 'x'}, {'1key': 'x'}, {'_key': 'x'}, {'a&url': 'x'}, {'a\n': 'x'},
               {'x': 'a' * 4097}, {'x': '汉' * 1366}, {f'key{i}': 'x' for i in range(33)}]
        bad += [{'x': 'synthetic-secret' + char} for char in ('\0', '\n', '\r', '\t', '\x7f', '\x85', '\ud800')]
        for value in bad:
            with self.subTest(shape=type(value).__name__):
                with self.assertRaises(c.ConverterError) as exc: c.parameters(value)
                self.assertNotIn('synthetic-secret', repr(exc.exception))
                with self.assertRaises(sandbox.SandboxError): sandbox.validate_parameters(value)
        good = {f'key{i}': '' for i in range(32)}
        self.assertEqual(c.parameters(good), good)
        self.assertEqual(c.parameters({'a' * 64: '汉' * 1365 + 'x'}), {'a' * 64: '汉' * 1365 + 'x'})

    def test_full_options_and_32_parameters_roundtrip_without_old_field_limit(self):
        opts = {key: False for key in c.BOOL_OPTIONS}
        opts.update({key: 'Synthetic' for key in c.TEXT_OPTIONS})
        opts.update(target='surge', ver=4, interval=60, config='https://example.test/config')
        params = {f'key{i}': str(i) for i in range(32)}
        value = c.validate({'sources': SOURCE, 'options': opts, 'parameters': params})
        parsed = c.parse_link(value.link())
        self.assertEqual(parsed.parameters, params)
        self.assertEqual(parsed.options, opts)

    def test_url_and_upload_intake_pass_same_parameters_and_encode_once(self):
        params = {'title': 'A & B=中 + 1', 'empty': ''}
        for remote in (False, True):
            fetch = Mock(return_value=[YAML.encode()])
            value, summary = engine.prepare(payload(params, remote), fetch)
            self.assertEqual(value['options']['parameters'], params)
            archive, _ = sandbox.make_archive(value)
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                url = urlsplit(tar.extractfile('request.url').read().decode())
                query = parse_qs(url.query, keep_blank_values=True)
                self.assertEqual(query['title'], [params['title']])
                self.assertEqual(query['empty'], [''])
                self.assertEqual(query['url'], ['./s000.txt'])
                self.assertNotIn('parameters', query)
            self.assertEqual(summary['network_executed'], remote)
            self.assertNotIn('title', json.dumps(summary))
            if remote:
                self.assertEqual(fetch.call_args.kwargs['maximum'], engine.MAX_JOB_BYTES - c.parameter_bytes(params))
            else:
                fetch.assert_not_called()

    def test_invalid_parameters_fail_before_network(self):
        for params in ({'URL': 'https://evil.test/'}, {'title': '\ud800'}, []):
            for remote in (False, True):
                fetch = Mock(side_effect=AssertionError('network'))
                with self.assertRaises(c.ConverterError): engine.prepare(payload(params, remote), fetch)
                fetch.assert_not_called()

    def test_shared_intake_and_final_transformation_budget(self):
        fetch = Mock(side_effect=AssertionError('network'))
        value = payload({'title': 'A' * 10}, True)
        value['uploads'] = ['x' * (engine.MAX_JOB_BYTES - 10)]
        with self.assertRaises(c.ConverterError) as exc: engine.prepare(value, fetch)
        self.assertEqual(exc.exception.code, 'FETCH_SIZE')
        fetch.assert_not_called()
        # Plain URI expansion fits alone, but must include the custom fields.
        value = payload({'title': 'x' * 90})
        value['uploads'] = ['ss://' + 'x' * 400]
        with patch.object(engine, 'MAX_JOB_BYTES', 600):
            with self.assertRaises(c.ConverterError) as exc: engine.prepare(value, fetch)
            self.assertEqual(exc.exception.code, 'FETCH_SIZE')

    def test_privileged_file_parameter_budget_and_encoded_query_limit(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.validate_job(job({'title': 'x' * 10}, 'x' * (sandbox.MAX_CONTENT - 10)))
        params = {f'key{i}': '汉' * 700 for i in range(32)}
        with self.assertRaises(c.ConverterError): c.validate({'sources': SOURCE, 'parameters': params})
        with self.assertRaises(c.ConverterError): engine.prepare(payload(params))
        with self.assertRaises(sandbox.SandboxError): sandbox.make_archive(job(params))

    def test_template_variables_share_budget_and_invalid_unicode_is_controlled(self):
        params = {'title': 'hello'}
        fetch = Mock(return_value=[b'{{ request.title }}'])
        value, _ = engine.prepare_tool({'operation': 'template', 'urls': [SOURCE], 'options': {'variables': params}}, fetch)
        self.assertEqual(fetch.call_args.kwargs['maximum'], engine.MAX_JOB_BYTES - c.parameter_bytes(params))
        archive, _ = sandbox.make_archive(value)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            self.assertEqual(parse_qs(urlsplit(tar.extractfile('request.url').read().decode()).query)['title'], ['hello'])
        for vars in ({'title': '\ud800'}, {'PATH': 'x'}, {'Constructor': 'x'}):
            with self.assertRaises(c.ConverterError):
                engine.prepare_tool({'operation': 'template', 'content': 'x', 'options': {'variables': vars}})
            value['options']['variables'] = vars
            with self.assertRaises(sandbox.SandboxError): sandbox.validate_job(value)
        with self.assertRaises(c.ConverterError):
            engine.prepare_tool({'operation': 'ruleset', 'content': 'x', 'options': {'group': '\ud800'}})
        huge = 'x' * (engine.MAX_JOB_BYTES - 3)
        with self.assertRaises(c.ConverterError):
            engine.prepare_tool({'operation': 'template', 'content': huge, 'options': {'variables': params}})
        big = job(content=huge)
        big['options'] = {'target': 'template', 'variables': params}
        with self.assertRaises(sandbox.SandboxError): sandbox.validate_job(big)

    def test_duplicate_raw_json_is_rejected_in_privileged_intake(self):
        with self.assertRaises(sandbox.SandboxError):
            json.loads('{"title":"one","title":"two"}', object_pairs_hook=sandbox.unique_object)


if __name__ == '__main__':
    unittest.main()

"""Captured sub-web template directory: synthetic, memory-only regression tests."""
import copy
import unittest
from unittest import mock
from urllib.parse import parse_qs, quote, urlsplit

from test_server import server

c = server.converter
SOURCE = 'https://subscription.example.test/input'
# Exact names and URLs from the captured subweb-live-converter.js v directory.
EXPECTED_CATALOG = [
    {
        "name": "universal",
        "items": [
            {
                "name": "No-Urltest",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/universal/no-urltest.ini"
            },
            {
                "name": "Urltest",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/universal/urltest.ini"
            }
        ]
    },
    {
        "name": "customized",
        "items": [
            {
                "name": "Maying",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/maying.ini"
            },
            {
                "name": "Ytoo",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ytoo.ini"
            },
            {
                "name": "FlowerCloud",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/flowercloud.ini"
            },
            {
                "name": "Nexitally",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/nexitally.ini"
            },
            {
                "name": "SoCloud",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/socloud.ini"
            },
            {
                "name": "ARK",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ark.ini"
            },
            {
                "name": "ssrCloud",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/customized/ssrcloud.ini"
            }
        ]
    },
    {
        "name": "Special",
        "items": [
            {
                "name": "NeteaseUnblock(仅规则，No-Urltest)",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/special/netease.ini"
            },
            {
                "name": "Basic(仅GEOIP CN + Final)",
                "url": "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config/special/basic.ini"
            }
        ]
    }
]


class ConverterPresetTests(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch('socket.socket', side_effect=AssertionError('network forbidden')),
                        mock.patch.object(server.BRIDGE, 'call', side_effect=AssertionError('bridge forbidden'))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, path, payload):
        handler = object.__new__(server.Handler)
        handler.path = path
        handler.authorize = lambda: True
        handler.same_origin = lambda: True
        handler.read_json = lambda: copy.deepcopy(payload)
        output = []
        handler.send_json = lambda code, result: output.append((code, result))
        handler.do_POST()
        self.assertEqual(len(output), 1)
        return output[0]

    def test_exact_three_groups_and_eleven_captured_mappings(self):
        actual = c.capabilities()['config_presets']
        self.assertEqual(actual, EXPECTED_CATALOG)
        self.assertEqual([(group['name'], len(group['items'])) for group in actual],
                         [('universal', 2), ('customized', 7), ('Special', 2)])
        self.assertEqual(len({item['url'] for group in actual for item in group['items']}), 11)

    def test_capabilities_returns_independent_nested_catalog_copies(self):
        changed = c.capabilities()
        changed['config_presets'][0]['name'] = 'changed'
        changed['config_presets'][0]['items'][0]['url'] = 'https://example.test/changed.ini'
        changed['config_presets'][1]['items'].clear()
        changed['config_presets'].pop()
        self.assertEqual(c.capabilities()['config_presets'], EXPECTED_CATALOG)

    def test_defaults_and_both_subnet_profiles_do_not_select_a_template(self):
        caps = c.capabilities()
        self.assertEqual([item['id'] for item in caps['presets']], ['router_a', 'router_b'])
        self.assertNotIn('config', c.PRESET_OPTIONS)
        for profile in caps['presets']:
            self.assertEqual(profile['options'], c.PRESET_OPTIONS)
            form = c.validate({'profile': profile['id'], 'sources': SOURCE, 'options': profile['options']})
            self.assertNotIn('config', form.options)
            self.assertNotIn('config', parse_qs(urlsplit(form.link()).query))
        self.assertFalse(caps['network_executed'])
        self.assertFalse(caps['router_changed'])

    def test_authenticated_options_endpoint_exposes_the_exact_catalog_without_execution(self):
        handler = object.__new__(server.Handler)
        handler.path = '/api/converter/options'
        handler.authorize = lambda: True
        output = []
        handler.send_json = lambda code, result: output.append((code, result))
        handler.do_GET()
        self.assertEqual(output[0][0], 200)
        self.assertEqual(output[0][1]['config_presets'], EXPECTED_CATALOG)
        self.assertFalse(output[0][1]['network_executed'])
        handler.authorize = lambda: False
        output.clear()
        handler.do_GET()
        self.assertEqual(output, [])

    def test_eleven_urls_survive_real_link_and_parse_handlers_exactly_once(self):
        for group in EXPECTED_CATALOG:
            for item in group['items']:
                with self.subTest(group=group['name'], name=item['name']):
                    form = {'profile': 'manual', 'sources': SOURCE,
                            'options': dict(c.PRESET_OPTIONS, config=item['url'])}
                    status, result = self.post('/api/converter/link', {'nonce': server.new_nonce(), 'form': form})
                    self.assertEqual(status, 200)
                    self.assertFalse(result['summary']['network_executed'])
                    self.assertFalse(result['summary']['router_changed'])
                    self.assertEqual(parse_qs(urlsplit(result['link']).query)['config'], [item['url']])
                    self.assertIn('config=' + quote(item['url'], safe=''), result['link'])
                    status, parsed = self.post('/api/converter/parse', {'nonce': server.new_nonce(), 'link': result['link']})
                    self.assertEqual(status, 200)
                    self.assertEqual(parsed['form']['options'], form['options'])
                    self.assertEqual(parsed['form']['sources'], [SOURCE])

    def test_manual_config_remains_independent_of_catalog_and_profile(self):
        custom = 'https://config.example.test/custom.ini?q=a%2Bb'
        for profile in ('manual', 'router_a', 'router_b'):
            form = c.validate({'profile': profile, 'sources': SOURCE,
                               'options': {'target': 'clash', 'config': custom}})
            self.assertEqual(form.options['config'], custom)
            self.assertEqual(c.parse_link(form.link()).options['config'], custom)
            self.assertEqual(form.public_form()['options']['config'], custom)


if __name__ == '__main__':
    unittest.main()

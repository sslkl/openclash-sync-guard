"""Malformed JSON shapes must fail closed before any I/O (synthetic only)."""
import copy
import json
import unittest
from unittest import mock

from test_server import server
import converter_engine as engine
import converter_services as services
from subscription_converter import ConverterError

YAML = "proxies: [{name: Synthetic, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: synthetic}]\n"
SHAPES = (None, False, True, 0, 1, 1.5, "", [], {}, ["synthetic-private-input"], {"x": 1})


class RequestShapeTests(unittest.TestCase):
    def test_public_boundaries_never_raise_untyped_shape_errors(self):
        cases = (
            (lambda value: engine.prepare(value, self.no_fetch),
             {"form": {"sources": "", "options": {"target": "clash"}, "profile": "manual"}, "uploads": [YAML]}),
            (lambda value: engine.prepare_tool(value, self.no_fetch),
             {"operation": "ruleset", "content": "DOMAIN,example.com", "options": {"type": 1, "input_format": "surge", "group": "Proxy"}}),
            (services.validate,
             {"action": "gist_get", "id": "a" * 20, "filename": "test.yaml", "token": "synthetic_token_123456", "confirm_external": True}),
        )
        for case, (function, sample) in enumerate(cases):
            paths = [(key,) for key in sample]
            paths += [(key, child) for key, value in sample.items() if isinstance(value, dict) for child in value]
            for path in paths:
                for value in SHAPES:
                    with self.subTest(case=case, field=".".join(path), shape=type(value).__name__):
                        payload = copy.deepcopy(sample)
                        parent = payload
                        for key in path[:-1]:
                            parent = parent[key]
                        parent[path[-1]] = value
                        try:
                            function(payload)
                        except ConverterError:
                            pass

    @staticmethod
    def no_fetch(*args, **kwargs):
        raise AssertionError("shape validation must not fetch")

    def test_bad_operation_returns_422_without_io_or_secret_echo(self):
        handler = object.__new__(server.Handler)
        for operation in SHAPES:
            with self.subTest(shape=type(operation).__name__):
                output = []
                handler.send_json = lambda status, result, *, output=output: output.append((status, result))
                bridge = mock.Mock(enabled=True)
                bridge.call.side_effect = AssertionError("malformed operation must not execute")
                with mock.patch.object(server, "BRIDGE", bridge), mock.patch.object(engine, "fetch_many", self.no_fetch):
                    handler.handle_converter("/api/converter/tool", {"operation": operation})
                self.assertEqual(len(output), 1)
                status, result = output[0]
                self.assertEqual(status, 422)
                self.assertEqual(result["code"], "REQUEST")
                self.assertNotIn("synthetic-private-input", json.dumps(result))
                self.assertFalse(engine.LOCK.locked())
                bridge.call.assert_not_called()


if __name__ == "__main__":
    unittest.main()

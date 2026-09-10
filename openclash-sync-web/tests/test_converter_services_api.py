"""Service dispatcher behavior; synthetic outputs only, no external access."""
import copy
import json
import unittest
from unittest import mock
from test_server import server
from subscription_converter import ConverterError


class ServicesAPITests(unittest.TestCase):
    def dispatch(self, payload, *, value=None, error=None):
        handler = object.__new__(server.Handler)
        output = []
        handler.send_json = lambda status, result: output.append((status, result))
        with mock.patch.object(server.converter_services, 'execute', return_value=value, side_effect=error) as execute, \
             mock.patch.object(server.BRIDGE, 'call', side_effect=AssertionError('external service must not touch root bridge')):
            handler.handle_converter('/api/converter/service', copy.deepcopy(payload))
        self.assertEqual(len(output), 1)
        return *output[0], execute

    def test_dispatch_is_separate_from_root_bridge(self):
        payload = {'action': 'expand', 'confirm_external': True, 'link': 'https://example.test/synthetic'}
        result = {'ok': True, 'action': 'expand', 'link': 'http://192.0.2.20:25500/sub?target=clash&url=https%3A%2F%2Fexample.test%2Fsub', 'router_changed': False}
        status, actual, call = self.dispatch(payload, value=result)
        self.assertEqual(status, 200)
        self.assertEqual(actual, result)
        call.assert_called_once_with(payload)
        self.assertFalse(server.converter_engine.LOCK.locked())

    def test_busy_does_not_call_service(self):
        self.assertTrue(server.converter_engine.LOCK.acquire(blocking=False))
        try:
            status, result, call = self.dispatch({'action': 'gist_create'})
            self.assertEqual(status, 409)
            self.assertEqual(result['code'], 'CONVERTER_BUSY')
            call.assert_not_called()
            self.assertTrue(server.converter_engine.LOCK.locked())
        finally:
            server.converter_engine.LOCK.release()

    def test_errors_are_typed_no_sensitive_echo_and_lock_released(self):
        for code in ('SERVICE_CONFIRM', 'SERVICE_AUTH', 'SERVICE_UNCERTAIN', 'FETCH_TIMEOUT', 'FETCH_ADDRESS'):
            with self.subTest(code=code):
                status, result, call = self.dispatch({'token': 'synthetic_secret_do_not_echo'}, error=ConverterError(code))
                self.assertGreaterEqual(status, 400)
                self.assertEqual(result['code'], code)
                self.assertFalse(result['ok'])
                self.assertNotIn('synthetic_secret_do_not_echo', json.dumps(result))
                self.assertFalse(server.converter_engine.LOCK.locked())
                call.assert_called_once()
        self.assertIn('可能已完成', server.converter.failure(ConverterError('SERVICE_UNCERTAIN'))['message'])


if __name__ == '__main__':
    unittest.main()

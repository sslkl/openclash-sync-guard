"""Loopback-only request intake deadlines; no helper or real credentials."""
import http.client
import io
import json
from pathlib import Path
import select
import socket
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT.parent / 'vendor' / 'pyyaml-6.0.2'):
    sys.path.insert(0, str(path))
import server


class QuietHandler(server.Handler):
    def log_message(self, *args):
        pass


class RawDeadlineReaderTests(unittest.TestCase):
    def test_every_raw_receive_uses_the_same_remaining_budget(self):
        raw, connection = io.BytesIO(b"abcdef"), mock.Mock()
        reader = server.RequestDeadlineReader(raw, connection)
        reader.deadline = 10
        try:
            with mock.patch.object(server.time, 'monotonic', side_effect=[1, 2, 11]):
                first, second = bytearray(3), bytearray(3)
                self.assertEqual(reader.readinto(first), 3)
                self.assertEqual(reader.readinto(second), 3)
                with self.assertRaises(TimeoutError):
                    reader.readinto(bytearray(1))
            self.assertEqual(first + second, b"abcdef")
            self.assertEqual(connection.settimeout.call_args_list, [mock.call(9), mock.call(8)])
            reader.finish_reading()
            self.assertIsNone(reader.deadline)
            connection.settimeout.assert_called_with(server.HTTP_SOCKET_TIMEOUT)
        finally:
            reader.close()
        self.assertTrue(raw.closed)
        self.assertTrue(reader.closed)
        reader.close()  # Handler finalization and GC may both close the reader.


class HttpDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.httpd = server.BoundedThreadingHTTPServer(('127.0.0.1', 0), QuietHandler, max_threads=4)
        self.host = '127.0.0.1:%d' % self.httpd.server_address[1]
        self.patches = [mock.patch.object(server, 'HTTP_READ_TIMEOUT', .4, create=True),
                        mock.patch.object(server, 'AUTH_REQUIRED', False),
                        mock.patch.object(server, 'ALLOWED_HOSTS', {self.host}),
                        mock.patch.object(server, 'ALLOWED_ORIGINS', {'http://' + self.host})]
        for patch in self.patches:
            patch.start()
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join(timeout=3)
        self.httpd.server_close()
        for patch in reversed(self.patches):
            patch.stop()

    def connection(self):
        return socket.create_connection(self.httpd.server_address, timeout=2)

    def assert_drip_terminates(self, prefix):
        start = time.monotonic()
        response = b''
        with self.connection() as connection:
            connection.sendall(prefix)
            while time.monotonic() - start < 1.25:
                try:
                    connection.sendall(b'x')
                    if select.select([connection], [], [], .04)[0]:
                        data = connection.recv(65536)
                        if not data:
                            break
                        response += data
                except (BrokenPipeError, ConnectionResetError):
                    break
            else:
                self.fail('request remains alive while bytes trickle beyond the total read budget')
        self.assertLess(time.monotonic() - start, 1.1)
        return response

    def test_slow_request_line_has_total_deadline(self):
        self.assert_drip_terminates(b'GET /')

    def test_slow_headers_have_total_deadline(self):
        self.assert_drip_terminates(('GET /healthz HTTP/1.1\r\nHost: %s\r\nX-Slow: ' % self.host).encode())

    def test_slow_body_has_total_deadline_without_dispatch(self):
        prefix = ('POST /api/validate HTTP/1.1\r\nHost: %s\r\nOrigin: http://%s\r\n'
                  'Content-Type: application/json\r\nContent-Length: 10000\r\n\r\n{"content":"' % (self.host, self.host)).encode()
        with mock.patch.object(server, 'validate_yaml') as dispatch:
            response = self.assert_drip_terminates(prefix)
            dispatch.assert_not_called()
        self.assertIn(b'400', response)

    def test_slow_operation_after_complete_body_is_not_cancelled(self):
        def work(content):
            time.sleep(.6)
            return {'ok': True, 'length': len(content)}
        connection = http.client.HTTPConnection('127.0.0.1', self.httpd.server_address[1], timeout=3)
        try:
            body = json.dumps({'content': 'x' * 100000})
            with mock.patch.object(server, 'validate_yaml', side_effect=work):
                connection.request('POST', '/api/validate', body=body,
                                   headers={'Host': self.host, 'Origin': 'http://' + self.host,
                                            'Content-Type': 'application/json'})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), {'ok': True, 'length': 100000})
        finally:
            connection.close()

    def test_idle_intake_releases_bounded_server_slots(self):
        connections = [self.connection() for _ in range(4)]
        try:
            for connection in connections:
                connection.sendall(b'GET /')
            for connection in connections:
                self.assertEqual(connection.recv(1), b'')
        finally:
            for connection in connections:
                connection.close()
        connection = http.client.HTTPConnection('127.0.0.1', self.httpd.server_address[1], timeout=2)
        try:
            connection.request('GET', '/healthz', headers={'Host': self.host})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {'ok': True})
        finally:
            connection.close()

    def test_keepalive_resets_request_budget(self):
        with self.connection() as connection:
            for _ in range(3):
                connection.sendall(('GET /healthz HTTP/1.1\r\nHost: %s\r\n' % self.host).encode())
                time.sleep(.2)
                connection.sendall(b'\r\n')
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), {'ok': True})
                response.close()


if __name__ == '__main__':
    unittest.main()

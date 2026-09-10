"""Request metadata must not turn arbitrary URL/method data into durable logs."""
import contextlib
import io
import unittest

import server


class HttpLoggingTests(unittest.TestCase):
    def capture(self, path, method="GET", fmt='"%s" %s %s', args=("synthetic request", "404", "0")):
        handler = server.Handler.__new__(server.Handler)
        handler.client_address = ("192.0.2.20", 10000)
        handler.path, handler.command = path, method
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handler.log_message(fmt, *args)
        return output.getvalue()

    def test_known_routes_keep_diagnostic_name_without_query(self):
        for route in ("/api/status", "/api/converter/execute", "/api/chain/test", "/app.js", "/healthz"):
            with self.subTest(route=route):
                text = self.capture(route + "?token=synthetic-query-sensitive")
                self.assertIn(route, text)
                self.assertIn("192.0.2.20 GET", text)
                self.assertNotIn("synthetic-query-sensitive", text)

    def test_arbitrary_paths_never_enter_logs(self):
        for prefix in ("/", "/api/", "/api/converter/", "/static/"):
            with self.subTest(prefix=prefix):
                text = self.capture(prefix + "synthetic-path-sensitive")
                self.assertNotIn("synthetic-path-sensitive", text)
                self.assertIn("<unrecognized>", text)

    def test_method_and_control_characters_are_not_reflected(self):
        text = self.capture("/\x1b[31msynthetic-control\r\nnext-line", "BAD\x1b[2J")
        self.assertEqual(text.count("\n"), 1)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("synthetic-control", text)
        self.assertNotIn("BAD", text)
        self.assertIn("OTHER", text)

    def test_early_parser_rejection_has_no_path_or_method(self):
        handler = server.Handler.__new__(server.Handler)
        handler.client_address = ("192.0.2.20", 10000)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handler.log_message("early parser rejection")
        self.assertEqual(output.getvalue(), "192.0.2.20 OTHER <unrecognized>\n")

    def test_malformed_urls_and_parser_error_context_are_safe(self):
        for path in ("http://[", "http://user:synthetic-authority-sensitive@[", "//["):
            with self.subTest(path=path):
                text = self.capture(path, None, "synthetic-error-%s", ("synthetic-header-sensitive",))
                self.assertEqual(text.count("\n"), 1)
                self.assertIn("<unrecognized>", text)
                self.assertNotIn("synthetic", text)


if __name__ == "__main__":
    unittest.main()

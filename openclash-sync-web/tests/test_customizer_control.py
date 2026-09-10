"""Regression coverage for curl-config quoting using only synthetic values."""
from __future__ import annotations

import http.server
import json
import pathlib
import subprocess
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CustomizerControlTests(unittest.TestCase):
    def quote(self, values):
        result = subprocess.run(
            ["/usr/bin/ruby", "-r", str(ROOT / "openclash_customizer.rb"), "-rjson", "-e",
             "puts JSON.generate(JSON.parse(STDIN.read).map { |value| OpenClashCustomizer.curl_config_string(value) })"],
            input=json.dumps(values), text=True, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_curl_config_quoting_round_trips_backslashes_and_quotes(self):
        values = ["plain", "香港🙂", "a\tb\nc\rd", "back\\slash", "quote\"name",
                  "both\\\"name", "trailing\\", r"literal\n\r\t", "slashes\\\\end"]
        quoted = self.quote(values)
        for original, serialized in zip(values, quoted):
            with self.subTest(original=repr(original)):
                self.assertEqual(json.loads(serialized), original)

    def test_actual_curl_parser_preserves_synthetic_header_and_json_body(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.headers.get("Authorization"), body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                pass

        secret = r"synthetic-back\slash"
        body = json.dumps({"name": "香港\\node \"quoted\""}, ensure_ascii=False)
        header, payload = self.quote(["Bearer " + secret, body])
        with http.server.HTTPServer(("127.0.0.1", 0), Handler) as httpd:
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                result = subprocess.run(
                    ["/usr/bin/curl", "-q", "--noproxy", "*", "--config", "-",
                     "--request", "PUT", "--max-time", "3", "--silent", "--show-error",
                     "--url", f"http://127.0.0.1:{httpd.server_port}/synthetic"],
                    input="header = \"Authorization: " + header[1:] + "\n" +
                          "data-binary = " + payload + "\n",
                    text=True, capture_output=True, timeout=5, check=False,
                )
            finally:
                httpd.shutdown()
                thread.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received, [("Bearer " + secret, body.encode("utf-8"))])


if __name__ == "__main__":
    unittest.main()

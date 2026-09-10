"""curl must not inherit implicit account configuration; synthetic loopback only."""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CurlDefaultsTests(unittest.TestCase):
    def test_controller_calls_ignore_synthetic_default_configuration(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('X-Curlrc-Fixture')))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"delay":1}' if '/delay?' in self.path else b'{"proxies":{}}')

            def log_message(self, *_args):
                pass

        with tempfile.TemporaryDirectory(prefix='curl-defaults-') as home,                 http.server.HTTPServer(('127.0.0.1', 0), Handler) as httpd:
            Path(home, '.curlrc').write_text('header = "X-Curlrc-Fixture: injected"\n', encoding='utf-8')
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                script = '''
require "json"
require ARGV.fetch(0)
module FixtureHome
  def popen(env, *args, **kwargs, &block)
    home = ENV.fetch("SYNTHETIC_CURL_HOME")
    super(env.merge("HOME" => home, "CURL_HOME" => home), *args, **kwargs, &block)
  end
end
IO.singleton_class.prepend(FixtureHome)
config = JSON.parse(STDIN.read)
body, code = OpenClashCustomizer.controller_request(config, "GET", "/proxies")
raise "REQUEST" unless code == "200" && body == '{"proxies":{}}'
raise "DELAY" unless OpenClashCustomizer.controller_delay(config, "synthetic-node")
'''
                result = subprocess.run(
                    ['/usr/bin/ruby', '-e', script, str(ROOT / 'openclash_customizer.rb')],
                    input=json.dumps({'external-controller': f'127.0.0.1:{httpd.server_port}',
                                      'secret': 'synthetic-controller-fixture'}),
                    env=dict(os.environ, SYNTHETIC_CURL_HOME=home),
                    text=True, capture_output=True, timeout=25, check=False,
                )
            finally:
                httpd.shutdown()
                thread.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(header is None for _, header in seen), seen)

    def test_direct_health_disables_default_config_before_other_options(self):
        script = '''
require "json"
require ARGV.fetch(0)
module CaptureCommands
  def system(env, *args, **kwargs)
    (@captured_commands ||= []) << args
    @captured_commands.length == 2
  end
  def captured_commands
    @captured_commands
  end
end
OpenClashCustomizer.singleton_class.prepend(CaptureCommands)
raise "HEALTH" unless OpenClashCustomizer.direct_health
puts JSON.generate(OpenClashCustomizer.captured_commands)
'''
        result = subprocess.run(['/usr/bin/ruby', '-e', script, str(ROOT / 'openclash_customizer.rb')],
                                text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = json.loads(result.stdout)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(command[:2], ['curl', '-q'])
            self.assertIn('--noproxy', command)

    def test_transaction_probes_disable_defaults_without_running_entrypoints(self):
        for name in ('openclash_custom_transaction.sh', 'openclash_custom_rollback_guard.sh'):
            with self.subTest(script=name):
                source = (ROOT / name).read_text(encoding='utf-8')
                commands = re.findall(r'^\s*curl\s+([^\n]+)', source, re.M)
                self.assertEqual(len(commands), 2)
                for command in commands:
                    self.assertTrue(command.startswith('-q --noproxy '), command)


if __name__ == '__main__':
    unittest.main()

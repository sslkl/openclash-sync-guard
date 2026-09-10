"""Unsupported IP literals must not silently turn into DNS authorities."""
import unittest
from unittest import mock

from test_server import server

c = server.converter


class URLAuthorityRound2Tests(unittest.TestCase):
    def test_ipvfuture_literals_are_rejected_instead_of_reinterpreted_as_dns(self):
        for value in ("https://[v1.example.test]/path", "http://[vF.example.test]:8080/sub",
                      "https://[v1.foo:bar]/path"):
            for backend in (False, True):
                with self.subTest(value=value, backend=backend), mock.patch("socket.getaddrinfo", side_effect=AssertionError("no DNS")):
                    with self.assertRaises(c.ConverterError) as caught:
                        c.http_url(value, backend=backend)
                    self.assertEqual(caught.exception.code, "BACKEND" if backend else "URL")

    def test_unbracketed_domain_names_and_signed_query_values_are_unchanged(self):
        self.assertEqual(c.http_url("https://V1.Example.Test:8443/path?sig=a%2Bb%2Fc%3D"),
                         "https://v1.example.test:8443/path?sig=a%2Bb%2Fc%3D")
        self.assertEqual(c.http_url("https://VF.Example.Test", backend=True), "https://vf.example.test/sub")

    def test_ipv6_literals_keep_brackets_and_canonical_compression(self):
        self.assertEqual(c.http_url("https://[2001:0db8:0000:0::1]:8443/路径?q=香港"),
                         "https://[2001:db8::1]:8443/%E8%B7%AF%E5%BE%84?q=%E9%A6%99%E6%B8%AF")
        self.assertEqual(c.http_url("http://[::1]:25500", backend=True), "http://[::1]:25500/sub")
        with self.assertRaises(c.ConverterError):
            c.http_url("http://[fe80::1%25en0]/sub")

    def test_invalid_source_and_backend_do_not_generate_a_different_link(self):
        for payload in ({"sources": ["https://[v1.example.test]/sub"]},
                        {"sources": ["https://example.test/sub"], "backend": "https://[v1.example.test]/sub"}):
            with self.subTest(payload=payload), self.assertRaises(c.ConverterError):
                c.validate(payload)


if __name__ == "__main__":
    unittest.main()

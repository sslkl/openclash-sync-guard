"""Public-fetch special ranges; checks never open a network connection."""
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import converter_fetch as fetch
from subscription_converter import ConverterError


class SpecialNetworkTests(unittest.TestCase):
    def test_deprecated_transition_relay_block_is_not_a_public_http_source(self):
        for address in ('192.88.99.0', '192.88.99.1', '192.88.99.2', '192.88.99.255'):
            with self.subTest(address=address), self.assertRaises(ConverterError):
                fetch.public_ip(address)

    def test_special_ranges_remain_denied_with_legacy_stdlib_classification(self):
        # Supported Python minor versions have shipped different IANA tables.
        with mock.patch.object(ipaddress.IPv4Address, 'is_global', new_callable=mock.PropertyMock, return_value=True), \
             mock.patch.object(ipaddress.IPv6Address, 'is_global', new_callable=mock.PropertyMock, return_value=True):
            for address in ('192.0.0.8', '192.0.0.11', '192.0.0.255', '192.88.99.2', '3fff::1'):
                with self.subTest(address=address), self.assertRaises(ConverterError):
                    fetch.public_ip(address)

    def test_public_addresses_and_global_ietf_exceptions_stay_accepted(self):
        for address in ('8.8.8.8', '1.1.1.1', '192.0.0.9', '192.0.0.10', '2606:4700:4700::1111'):
            with self.subTest(address=address):
                self.assertEqual(fetch.public_ip(address), ipaddress.ip_address(address).compressed)


if __name__ == '__main__':
    unittest.main()

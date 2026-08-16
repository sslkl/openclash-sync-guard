#!/usr/bin/env python3
"""One-shot, memory-only worker host Maying conversion and normalization worker."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

import yaml
from yaml.tokens import AliasToken, AnchorToken

from maying_normalizer import MayingNormalizer
from maying_converter_reconciler import MayingConverterNameAuthorityReconciler

MAX_REQUEST_BYTES = 64 * 1024
MAX_SOURCE_BYTES = MayingNormalizer.MAX_SOURCE_BYTES
MAX_CONVERTED_BYTES = 16 * 1024 * 1024
REQUIRED_QUERY = {
    "target": "clash", "new_name": "true", "emoji": "true", "udp": "true", "tfo": "false",
    "fdn": "true", "list": "false", "scv": "false", "sort": "false",
}
ALLOWED_QUERY_KEYS = frozenset(("url", *REQUIRED_QUERY))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class FetchResult:
    body: bytes
    status: int


class Worker:
    def __init__(self, *, allowed_outer_hosts=("192.0.2.20",), converter_origin="http://127.0.0.1:25500",
                 expected_source_host_sha256: str | None = None,
                 normalization_policy: str = "strict-v1",
                 fetcher: Callable[[str, int, int], FetchResult] | None = None):
        self.allowed_outer_hosts = frozenset(allowed_outer_hosts)
        self.converter_origin = converter_origin
        self.expected_source_host_sha256 = expected_source_host_sha256
        self.normalization_policy = normalization_policy
        self.fetcher = fetcher or self._fetch

    def run(self, request_bytes: bytes) -> dict:
        try:
            if not isinstance(request_bytes, bytes) or not 1 <= len(request_bytes) <= MAX_REQUEST_BYTES or b"\0" in request_bytes:
                return self._hold("REQUEST")
            request = json.loads(request_bytes)
            if not isinstance(request, dict) or set(request) != {"schema", "address"}:
                return self._hold("REQUEST_SCHEMA")
            if request.get("schema") != "publisher-v4-worker-request-v1":
                return self._hold("REQUEST_SCHEMA")
            address = request.get("address")
            parsed, query, source_url = self._validate_address(address)
            source_before = self.fetcher(source_url, MAX_SOURCE_BYTES, 20).body
            converter_query = urllib.parse.urlencode(query, doseq=True, safe="")
            converter_url = f"{self.converter_origin}/sub?{converter_query}"
            converted = self.fetcher(converter_url, MAX_CONVERTED_BYTES, 60).body
            source_after = self.fetcher(source_url, MAX_SOURCE_BYTES, 20).body
            if not source_before or source_before != source_after:
                return self._hold("SOURCE_DRIFT")
            document = self._load_converted_yaml(converted)
            if not isinstance(document, dict) or not isinstance(document.get("proxies"), list) or not isinstance(document.get("proxy-groups"), list):
                return self._hold("CONVERTED_YAML")
            converted_proxies = self._materialize_converter_policy(document["proxies"])
            if self.normalization_policy == "strict-v1":
                normalized = MayingNormalizer().normalize(source_before, converted_proxies)
            elif self.normalization_policy == MayingConverterNameAuthorityReconciler.POLICY:
                normalized = MayingConverterNameAuthorityReconciler().reconcile(source_before, converted_proxies)
            else:
                return self._hold("NORMALIZATION_POLICY")
            if normalized.receipt["decision"] != "PASS":
                return self._hold("NORMALIZATION", normalization=normalized.receipt)
            document["proxies"] = [dict(proxy) for proxy in normalized.normalized_proxies]
            normalized_yaml = yaml.safe_dump(document, allow_unicode=True, sort_keys=False).encode("utf-8")
            if not 1 <= len(normalized_yaml) <= MAX_CONVERTED_BYTES:
                return self._hold("NORMALIZED_YAML")
            return {
                "schema": "publisher-v4-worker-response-v1",
                "decision": "PASS", "reason": "NONE", "authorization_effect": "PREPARE_ONLY",
                "source_sha256": hashlib.sha256(source_before).hexdigest(),
                "converter_output_sha256": hashlib.sha256(converted).hexdigest(),
                "normalized_yaml_sha256": hashlib.sha256(normalized_yaml).hexdigest(),
                "normalized_yaml_bytes": len(normalized_yaml),
                "converted_yaml_base64": base64.b64encode(normalized_yaml).decode("ascii"),
                "normalization": normalized.receipt,
                "secret_fields_emitted_in_receipt": False,
                "converted_yaml_contains_credentials": True,
                "active_config_changed": False, "uci_changed": False, "service_restarted": False,
            }
        except (UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return self._hold("REQUEST")
        except (urllib.error.URLError, TimeoutError, OSError):
            return self._hold("NETWORK")
        except yaml.YAMLError:
            return self._hold("CONVERTED_YAML")
        except Exception:
            return self._hold("INTERNAL")

    def _validate_address(self, address):
        if not isinstance(address, str) or not 1 <= len(address.encode("utf-8")) <= 16_384 or any(ord(c) < 0x20 for c in address):
            raise ValueError("address")
        parsed = urllib.parse.urlsplit(address)
        if parsed.scheme != "http" or parsed.hostname not in self.allowed_outer_hosts or parsed.port != 25500 or parsed.path != "/sub":
            raise ValueError("outer")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("authority")
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
        counts = {}
        for key, value in pairs:
            if key not in ALLOWED_QUERY_KEYS:
                raise ValueError("query key")
            counts[key] = counts.get(key, 0) + 1
            if counts[key] != 1:
                raise ValueError("duplicate query")
        query = dict(pairs)
        if set(query) != ALLOWED_QUERY_KEYS:
            raise ValueError("query shape")
        if any(query.get(key) != value for key, value in REQUIRED_QUERY.items()):
            raise ValueError("query policy")
        source_url = query.get("url")
        source = urllib.parse.urlsplit(source_url or "")
        if source.scheme != "https" or not source.hostname or source.username is not None or source.password is not None or source.fragment:
            raise ValueError("source")
        if source.port not in (None, 443):
            raise ValueError("source port")
        host_digest = hashlib.sha256(source.hostname.encode("idna")).hexdigest()
        if not isinstance(self.expected_source_host_sha256, str) or not re_full_sha256(self.expected_source_host_sha256):
            raise ValueError("source anchor")
        if host_digest != self.expected_source_host_sha256:
            raise ValueError("source identity")
        return parsed, pairs, source_url

    @staticmethod
    def _fetch(url: str, maximum: int, timeout: int) -> FetchResult:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers={"User-Agent": "publisher-v4-worker/1", "Accept": "*/*"})
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            if status != 200:
                raise urllib.error.URLError("status")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > maximum:
                raise urllib.error.URLError("size")
            body = response.read(maximum + 1)
            if not 1 <= len(body) <= maximum:
                raise urllib.error.URLError("size")
            return FetchResult(body, status)

    @staticmethod
    def _load_converted_yaml(converted: bytes):
        for token in yaml.scan(converted):
            if isinstance(token, (AliasToken, AnchorToken)):
                raise yaml.YAMLError("anchors prohibited")
        document = yaml.safe_load(converted)
        stack = [(document, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > 150_000 or depth > 64:
                raise yaml.YAMLError("structure limit")
            if isinstance(value, dict):
                if len(value) > 50_000:
                    raise yaml.YAMLError("mapping limit")
                stack.extend((child, depth + 1) for pair in value.items() for child in pair)
            elif isinstance(value, list):
                if len(value) > 50_000:
                    raise yaml.YAMLError("sequence limit")
                stack.extend((child, depth + 1) for child in value)
            elif isinstance(value, str) and len(value.encode("utf-8")) > 32_768:
                raise yaml.YAMLError("scalar limit")
        return document

    @staticmethod
    def _materialize_converter_policy(proxies):
        """Materialize udp=true when the converter omits its request-bound default."""
        if not isinstance(proxies, list):
            raise ValueError("proxies")
        materialized = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                raise ValueError("proxy")
            item = dict(proxy)
            if "udp" not in item:
                item["udp"] = True
            materialized.append(item)
        return materialized

    @staticmethod
    def _hold(reason, normalization=None):
        response = {
            "schema": "publisher-v4-worker-response-v1", "decision": "HOLD", "reason": reason,
            "authorization_effect": "NONE", "secret_fields_emitted_in_receipt": False,
            "converted_yaml_contains_credentials": False, "active_config_changed": False,
            "uci_changed": False, "service_restarted": False,
        }
        if normalization is not None:
            response["normalization"] = normalization
        return response


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def emit_result(result: dict, *, stream: bool, stdout_binary, stdout_text, stderr_text) -> int:
    safe = dict(result)
    if stream:
        yaml_base64 = safe.pop("converted_yaml_base64", None)
        if safe.get("decision") == "PASS" and isinstance(yaml_base64, str):
            stdout_binary.write(base64.b64decode(yaml_base64, validate=True))
        stderr_text.write(json.dumps(safe, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n")
    else:
        stdout_text.write(json.dumps(safe, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n")
    return 0 if safe.get("decision") == "PASS" else 1


def main():
    stream = len(sys.argv) >= 2 and sys.argv[1] == "--stream"
    anchor_index = 2 if stream else 1
    policy_index = anchor_index + 1
    if len(sys.argv) != policy_index + 1 or not re_full_sha256(sys.argv[anchor_index]):
        result = Worker._hold("SOURCE_ANCHOR")
    else:
        result = Worker(expected_source_host_sha256=sys.argv[anchor_index], normalization_policy=sys.argv[policy_index]).run(
            sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        )
    return emit_result(result, stream=stream, stdout_binary=sys.stdout.buffer, stdout_text=sys.stdout, stderr_text=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

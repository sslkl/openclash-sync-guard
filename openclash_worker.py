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
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

VENDORED_PYYAML_ROOT = Path(__file__).with_name("vendor") / "pyyaml-6.0.2"
sys.path.insert(0, str(VENDORED_PYYAML_ROOT))
import yaml
from yaml.tokens import AliasToken, AnchorToken

if yaml.__version__ != "6.0.2":
    raise RuntimeError("vendored PyYAML 6.0.2 required")

from maying_converter_reconciler import MayingConverterNameAuthorityReconciler
from maying_normalizer import MayingNormalizer

MAX_REQUEST_BYTES = 64 * 1024
MAX_SOURCE_BYTES = MayingNormalizer.MAX_SOURCE_BYTES
MAX_CONVERTED_BYTES = 16 * 1024 * 1024
REQUIRED_QUERY = {
    "target": "clash", "new_name": "true", "emoji": "true", "udp": "true", "tfo": "false",
    "fdn": "true", "list": "false", "scv": "false", "sort": "false",
}
ALLOWED_QUERY_KEYS = frozenset(("url", *REQUIRED_QUERY))
SHAPE_CONTRACT_NAME = "maying-converter-shape-contract.json"
COUNT_CONTRACT_KEYS = (
    "source_uri_count", "converted_proxy_count", "converted_group_count", "converted_rule_count",
    "converted_udp_absent_count", "converted_udp_true_count", "converted_udp_false_count",
    "normalized_udp_true_count", "normalized_tfo_false_count",
)


class WorkerPolicyHold(Exception):
    def __init__(self, reason: str, evidence: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.evidence = evidence or {}


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
                 shape_contract: dict | None = None,
                 fetcher: Callable[[str, int, int], FetchResult] | None = None):
        self.allowed_outer_hosts = frozenset(allowed_outer_hosts)
        self.converter_origin = converter_origin
        self.expected_source_host_sha256 = expected_source_host_sha256
        self.normalization_policy = normalization_policy
        self.shape_contract = shape_contract
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
            _parsed, query, source_url = self._validate_address(address)
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
            contract = self._validated_shape_contract()
            converter_evidence = self._validate_converter_document(document, contract)
            converted_proxies, udp_evidence = self._materialize_converter_policy(document["proxies"])
            converter_evidence.update(udp_evidence)
            self._validate_count(contract, "converted_udp_absent_count", udp_evidence["converter_udp_absent_count"])
            self._validate_count(contract, "converted_udp_true_count", udp_evidence["converter_udp_true_count"])
            self._validate_count(contract, "converted_udp_false_count", udp_evidence["converter_udp_false_count"])
            if self.normalization_policy == "strict-v1":
                normalized = MayingNormalizer().normalize(source_before, converted_proxies)
            elif self.normalization_policy == MayingConverterNameAuthorityReconciler.POLICY:
                normalized = MayingConverterNameAuthorityReconciler().reconcile(source_before, converted_proxies)
            else:
                return self._hold("NORMALIZATION_POLICY")
            if normalized.receipt["decision"] != "PASS":
                return self._hold("NORMALIZATION", normalization=normalized.receipt)
            normalized_proxies = [dict(proxy) for proxy in normalized.normalized_proxies]
            normalized_udp_true_count = sum(proxy.get("udp") is True for proxy in normalized_proxies)
            normalized_tfo_false_count = sum(proxy.get("tfo") is False for proxy in normalized_proxies)
            self._validate_normalized_contract(
                contract, normalized.receipt, len(converted_proxies), normalized_udp_true_count,
                normalized_tfo_false_count, udp_evidence,
            )
            normalized_document = {
                "proxies": normalized_proxies,
                "proxy-groups": deepcopy(document["proxy-groups"]),
            }
            normalized_yaml = yaml.safe_dump(normalized_document, allow_unicode=True, sort_keys=False).encode("utf-8")
            if not 1 <= len(normalized_yaml) <= MAX_CONVERTED_BYTES:
                return self._hold("NORMALIZED_YAML")
            converter_evidence.update({
                "normalized_udp_true_count": normalized_udp_true_count,
                "normalized_tfo_false_count": normalized_tfo_false_count,
                "udp_policy": "request-bound-true-v1",
            })
            return {
                "schema": "publisher-v4-worker-response-v1",
                "decision": "PASS", "reason": "NONE", "authorization_effect": "PREPARE_ONLY",
                "source_sha256": hashlib.sha256(source_before).hexdigest(),
                "converter_output_sha256": hashlib.sha256(converted).hexdigest(),
                "normalized_yaml_sha256": hashlib.sha256(normalized_yaml).hexdigest(),
                "normalized_yaml_bytes": len(normalized_yaml),
                "converted_yaml_base64": base64.b64encode(normalized_yaml).decode("ascii"),
                "normalization": normalized.receipt,
                **converter_evidence,
                "secret_fields_emitted_in_receipt": False,
                "converted_yaml_contains_credentials": True,
                "active_config_changed": False, "uci_changed": False, "service_restarted": False,
            }
        except WorkerPolicyHold as error:
            return self._hold(error.reason, evidence=error.evidence)
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

    def _validated_shape_contract(self):
        contract = self.shape_contract
        if contract is None:
            try:
                with Path(__file__).with_name(SHAPE_CONTRACT_NAME).open("r", encoding="utf-8") as handle:
                    contract = json.load(handle)
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise WorkerPolicyHold("CONTRACT") from error
        expected_keys = {
            "schema", "source_format", "allowed_top_level_keys", "required_top_level_keys",
            "ignored_metadata_top_level_keys", "ignored_metadata_types",
            "ignored_metadata_semantic_sha256", "converted_dns_present", *COUNT_CONTRACT_KEYS,
        }
        if not isinstance(contract, dict) or set(contract) != expected_keys:
            raise WorkerPolicyHold("CONTRACT")
        if contract.get("schema") != "publisher-v4-maying-converter-shape-contract-v2":
            raise WorkerPolicyHold("CONTRACT")
        if contract.get("source_format") != "BASE64_SSR_URI_LIST" or contract.get("converted_dns_present") is not False:
            raise WorkerPolicyHold("CONTRACT")
        allowed = contract.get("allowed_top_level_keys")
        required = contract.get("required_top_level_keys")
        if allowed != ["allow-lan", "external-controller", "log-level", "mode", "port", "proxies", "proxy-groups", "rules", "socks-port"] or required != allowed:
            raise WorkerPolicyHold("CONTRACT")
        metadata_keys = contract.get("ignored_metadata_top_level_keys")
        metadata_types = contract.get("ignored_metadata_types")
        if metadata_keys != ["allow-lan", "external-controller", "log-level", "mode", "port", "socks-port"]:
            raise WorkerPolicyHold("CONTRACT")
        if metadata_types != {
            "allow-lan": "BOOL", "external-controller": "STRING", "log-level": "STRING",
            "mode": "STRING", "port": "INT", "socks-port": "INT",
        } or not re_full_sha256(contract.get("ignored_metadata_semantic_sha256", "")):
            raise WorkerPolicyHold("CONTRACT")
        for key in COUNT_CONTRACT_KEYS:
            bounds = contract.get(key)
            if not isinstance(bounds, dict) or set(bounds) != {"minimum", "maximum", "baseline"}:
                raise WorkerPolicyHold("CONTRACT")
            values = (bounds["minimum"], bounds["maximum"], bounds["baseline"])
            if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
                raise WorkerPolicyHold("CONTRACT")
            if not 0 <= values[0] <= values[2] <= values[1] <= 50_000:
                raise WorkerPolicyHold("CONTRACT")
        return contract

    def _validate_converter_document(self, document, contract):
        if "dns" in document:
            raise WorkerPolicyHold("MAYING_DNS_UNEXPECTED", {
                "dns_present": True,
                "converter_dns_present": True,
                "dns_semantic_sha256": self._semantic_sha256(document["dns"]),
            })
        ignored_keys = sorted(set(document) - {"proxies", "proxy-groups"})
        shape_evidence = {
            "converter_dns_present": False,
            "converter_top_level_key_count": len(document),
            "ignored_top_level_key_count": len(ignored_keys),
            "ignored_top_level_key_set_sha256": self._semantic_sha256(ignored_keys),
        }
        if set(document) != set(contract["allowed_top_level_keys"]):
            raise WorkerPolicyHold("MAYING_DOCUMENT_SHAPE", shape_evidence)
        metadata_keys = contract["ignored_metadata_top_level_keys"]
        metadata = {key: document[key] for key in metadata_keys}
        type_checks = {
            "BOOL": lambda value: type(value) is bool,
            "INT": lambda value: type(value) is int,
            "STRING": lambda value: type(value) is str,
        }
        metadata_types_valid = all(type_checks[contract["ignored_metadata_types"][key]](metadata[key]) for key in metadata_keys)
        metadata_sha256 = self._semantic_sha256(metadata)
        shape_evidence.update({
            "ignored_metadata_key_count": len(metadata_keys),
            "ignored_metadata_types_validated": metadata_types_valid,
            "ignored_metadata_semantic_sha256": metadata_sha256,
        })
        if not metadata_types_valid or metadata_sha256 != contract["ignored_metadata_semantic_sha256"]:
            raise WorkerPolicyHold("MAYING_DOCUMENT_SHAPE", shape_evidence)
        rules = document.get("rules")
        if not isinstance(rules, list):
            raise WorkerPolicyHold("MAYING_DOCUMENT_SHAPE")
        proxy_count = len(document["proxies"])
        group_count = len(document["proxy-groups"])
        rule_count = len(rules)
        ignored_keys = sorted(set(document) - {"proxies", "proxy-groups"})
        evidence = {
            **shape_evidence,
            "shape_contract_schema": contract["schema"],
            "converter_proxy_count": proxy_count,
            "converter_group_count": group_count,
            "dns_present": False,
            "converter_dns_present": False,
            "ignored_rule_count": rule_count,
            "ignored_rules_sha256": self._semantic_sha256(rules),
        }
        try:
            self._validate_count(contract, "converted_proxy_count", proxy_count)
            self._validate_count(contract, "converted_group_count", group_count)
            self._validate_count(contract, "converted_rule_count", rule_count)
        except WorkerPolicyHold as error:
            raise WorkerPolicyHold(error.reason, evidence) from error
        return evidence

    def _validate_normalized_contract(self, contract, receipt, converted_count, udp_true_count, tfo_false_count, udp_evidence):
        if receipt.get("source_format") != contract["source_format"]:
            raise WorkerPolicyHold("MAYING_SOURCE_CONTRACT")
        self._validate_count(contract, "source_uri_count", receipt.get("input_uri_count"))
        self._validate_count(contract, "normalized_udp_true_count", udp_true_count)
        self._validate_count(contract, "normalized_tfo_false_count", tfo_false_count)
        if not (
            receipt.get("udp_policy_validated") is True
            and receipt.get("source_udp_capability_declared") is False
            and receipt.get("runtime_udp_capability_verified") is False
            and receipt.get("udp_true_validated_count") == udp_true_count
            and receipt.get("tfo_false_enforced_count") == tfo_false_count
            and converted_count == udp_true_count == tfo_false_count
            and udp_evidence["converter_udp_absent_count"] + udp_evidence["converter_udp_true_count"] == converted_count
            and udp_evidence["converter_udp_false_count"] == 0
            and udp_evidence["worker_udp_materialized_count"] == udp_evidence["converter_udp_absent_count"]
        ):
            raise WorkerPolicyHold("UDP_COUNT_MISMATCH")

    @staticmethod
    def _validate_count(contract, key, observed):
        bounds = contract[key]
        if isinstance(observed, bool) or not isinstance(observed, int) or not bounds["minimum"] <= observed <= bounds["maximum"]:
            reason = "UDP_COUNT_MISMATCH" if "udp" in key or "tfo" in key else "MAYING_DOCUMENT_SHAPE"
            if key == "source_uri_count":
                reason = "MAYING_SOURCE_CONTRACT"
            raise WorkerPolicyHold(reason)

    @staticmethod
    def _semantic_sha256(value):
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _materialize_converter_policy(proxies):
        """Materialize udp=true when the converter omits its request-bound default."""
        if not isinstance(proxies, list):
            raise ValueError("proxies")
        absent = 0
        explicit_true = 0
        explicit_false = 0
        invalid_type = 0
        for proxy in proxies:
            if not isinstance(proxy, dict):
                raise ValueError("proxy")
            if "udp" not in proxy:
                absent += 1
            elif proxy["udp"] is True:
                explicit_true += 1
            elif proxy["udp"] is False:
                explicit_false += 1
            else:
                invalid_type += 1
        evidence = {
            "converter_udp_absent_count": absent,
            "converter_udp_true_count": explicit_true,
            "converter_udp_false_count": explicit_false,
            "converter_udp_type_invalid_count": invalid_type,
            "worker_udp_materialized_count": 0,
        }
        if invalid_type:
            raise WorkerPolicyHold("CONVERTER_UDP_TYPE", evidence)
        if explicit_false:
            raise WorkerPolicyHold("CONVERTER_UDP_FALSE", evidence)
        materialized = []
        for proxy in proxies:
            item = dict(proxy)
            if "udp" not in item:
                item["udp"] = True
            materialized.append(item)
        evidence["worker_udp_materialized_count"] = absent
        return materialized, evidence

    @staticmethod
    def _hold(reason, normalization=None, evidence=None):
        response = {
            "schema": "publisher-v4-worker-response-v1", "decision": "HOLD", "reason": reason,
            "authorization_effect": "NONE", "secret_fields_emitted_in_receipt": False,
            "converted_yaml_contains_credentials": False, "active_config_changed": False,
            "uci_changed": False, "service_restarted": False,
        }
        if normalization is not None:
            response["normalization"] = normalization
        if evidence is not None:
            response.update(evidence)
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

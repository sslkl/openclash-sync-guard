#!/usr/bin/env python3
"""Pure, in-memory Publisher V4 Maying source normalizer.

This is a Python port of the sealed Ruby normalizer for worker host, whose host does
not provide Ruby.  It deliberately has no network, process, environment, or
filesystem interface.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizationResult:
    receipt: dict[str, Any]
    normalized_proxies: tuple[dict[str, Any], ...]


class MayingNormalizer:
    SCHEMA = "publisher-v4-maying-source-normalization-receipt-v2"
    IDENTITY_DOMAIN = b"OPENCLASH-PUBLISHER-V4\0MAYING-NODE-IDENTITY\0v1\0"
    BINDING_DOMAIN = b"OPENCLASH-PUBLISHER-V4\0MAYING-NODE-CREDENTIAL-BINDING\0v1\0"
    METADATA_DOMAIN = b"OPENCLASH-PUBLISHER-V4\0MAYING-NODE-METADATA-BINDING\0v1\0"
    SET_DOMAIN = b"OPENCLASH-PUBLISHER-V4\0MAYING-IDENTITY-SET\0v1\0"
    MAX_SOURCE_BYTES = 2 * 1024 * 1024
    MAX_DECODED_BYTES = 4 * 1024 * 1024
    MAX_URI_COUNT = 2048
    MAX_URI_BYTES = 16_384
    REQUIRED_PROXY_FIELDS = frozenset(("name", "type", "server", "port", "cipher", "protocol", "obfs", "password", "udp"))
    OPTIONAL_PROXY_FIELDS = frozenset(("protocol-param", "obfs-param", "tfo"))
    ALLOWED_PROXY_FIELDS = REQUIRED_PROXY_FIELDS | OPTIONAL_PROXY_FIELDS
    ALLOWED_QUERY_KEYS = frozenset(("group", "remarks", "protoparam", "obfsparam"))

    def normalize(self, source_bytes: bytes, converted_proxies: Any) -> NormalizationResult:
        try:
            input_reasons: Counter[str] = Counter()
            output_reasons: Counter[str] = Counter()
            gate_reasons: Counter[str] = Counter()
            identities: list[str] = []
            credential_bindings: list[str] = []
            metadata_bindings: list[str] = []
            exact_uris: set[str] = set()
            decoded_lines, observed_input_count, input_rejected_count, input_complete = self._decode_source(
                source_bytes, input_reasons, gate_reasons
            )

            for line in decoded_lines:
                identity, credential, metadata, exact_digest, reason = self._parse_uri(line)
                if reason:
                    input_reasons[reason] += 1
                    input_rejected_count += 1
                    continue
                assert identity and credential and metadata and exact_digest
                if exact_digest in exact_uris:
                    gate_reasons["DUPLICATE_URI"] += 1
                    continue
                exact_uris.add(exact_digest)
                if identity in identities:
                    input_reasons["INPUT_IDENTITY_COLLISION"] += 1
                    input_rejected_count += 1
                    continue
                identities.append(identity)
                credential_bindings.append(credential)
                metadata_bindings.append(metadata)

            (output_identities, output_credentials, output_metadata, normalized,
             observed_output_count, output_rejected_count, output_complete) = self._validate_converted(
                converted_proxies, output_reasons, gate_reasons
            )
            if input_complete and output_complete:
                if len(identities) != len(output_identities): gate_reasons["COUNT_MISMATCH"] += 1
                if sorted(identities) != sorted(output_identities): gate_reasons["IDENTITY_SET_MISMATCH"] += 1
                if sorted(credential_bindings) != sorted(output_credentials): gate_reasons["CREDENTIAL_BINDING_SET_MISMATCH"] += 1
                if sorted(metadata_bindings) != sorted(output_metadata): gate_reasons["METADATA_BINDING_SET_MISMATCH"] += 1

            duplicate_count = gate_reasons.get("DUPLICATE_URI", 0)
            input_count_closed = input_complete and observed_input_count == len(identities) + duplicate_count + input_rejected_count
            output_count_closed = output_complete and observed_output_count == len(output_identities) + output_rejected_count
            input_reason_closed = input_complete and sum(input_reasons.values()) == input_rejected_count
            output_reason_closed = output_complete and sum(output_reasons.values()) == output_rejected_count
            if input_complete and not input_count_closed: gate_reasons["INPUT_ACCOUNTING_MISMATCH"] += 1
            if output_complete and not output_count_closed: gate_reasons["OUTPUT_ACCOUNTING_MISMATCH"] += 1
            if input_complete and not input_reason_closed: gate_reasons["INPUT_REASON_ACCOUNTING_MISMATCH"] += 1
            if output_complete and not output_reason_closed: gate_reasons["OUTPUT_REASON_ACCOUNTING_MISMATCH"] += 1
            decision = "PASS" if not input_reasons and not output_reasons and not gate_reasons and input_count_closed and output_count_closed and input_reason_closed and output_reason_closed else "HOLD"
            source_format = "UNKNOWN" if not input_complete or any(x.startswith("SOURCE_") for x in gate_reasons) else ("BASE64_MIXED_URI_LIST" if input_reasons.get("NON_SSR_URI", 0) else "BASE64_SSR_URI_LIST")
            receipt = {
                "schema": self.SCHEMA, "source_format": source_format,
                "input_enumeration_complete": input_complete, "output_enumeration_complete": output_complete,
                "input_uri_count": observed_input_count, "unique_input_uri_count": len(exact_uris),
                "accepted_input_identity_count": len(identities), "output_proxy_count": observed_output_count,
                "accepted_output_identity_count": len(output_identities), "duplicate_count": duplicate_count,
                "rejected_count": input_rejected_count, "output_rejected_count": output_rejected_count,
                "input_count_closed": input_count_closed, "output_count_closed": output_count_closed,
                "input_reject_reasons_closed": input_reason_closed, "output_reject_reasons_closed": output_reason_closed,
                "count_accounting_closed": input_count_closed and output_count_closed and input_reason_closed and output_reason_closed,
                "input_reject_reason_counts": dict(sorted(input_reasons.items())),
                "output_reject_reason_counts": dict(sorted(output_reasons.items())),
                "gate_reason_counts": dict(sorted(gate_reasons.items())),
                "normalized_identity_set_sha256": self._identity_set_digest(identities),
                "tfo_forced_false_count": len(normalized) if decision == "PASS" else 0,
                "tfo_false_enforced_count": len(normalized) if decision == "PASS" else 0,
                "udp_policy_validated": decision == "PASS",
                "udp_true_validated_count": len(normalized) if decision == "PASS" else 0,
                "source_udp_capability_declared": False,
                "runtime_udp_capability_verified": False,
                "credential_fields_emitted": False, "credential_binding_validated": decision == "PASS",
                "metadata_binding_validated": decision == "PASS", "conversion_execution_authorized": False,
                "candidate_build_authorized": False, "production_write_authorized": False, "decision": decision,
            }
            return NormalizationResult(receipt, tuple(normalized if decision == "PASS" else ()))
        except Exception:
            return NormalizationResult(self._failure_receipt("INTERNAL_REJECTED"), ())

    def _decode_source(self, source: Any, input_reasons: Counter[str], gate_reasons: Counter[str]):
        if not isinstance(source, bytes) or not 1 <= len(source) <= self.MAX_SOURCE_BYTES or b"\0" in source:
            gate_reasons["SOURCE_SIZE_OR_TYPE"] += 1
            return [], 0, 0, False
        encoded = source[:-2] if source.endswith(b"\r\n") else (source[:-1] if source.endswith(b"\n") else source)
        decoded = self._strict_base64(encoded, b"-" in encoded or b"_" in encoded)
        if decoded is None or len(decoded) > self.MAX_DECODED_BYTES:
            gate_reasons["SOURCE_BASE64_INVALID"] += 1
            return [], 0, 0, False
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            gate_reasons["SOURCE_DECODED_ENCODING"] += 1
            return [], 0, 0, False
        if "\0" in text:
            gate_reasons["SOURCE_DECODED_ENCODING"] += 1
            return [], 0, 0, False
        lines = re.split(r"\r?\n", text)
        if text.endswith("\n") and lines[-1] == "": lines.pop()
        if not lines:
            gate_reasons["SOURCE_URI_COUNT"] += 1
            return [], 0, 0, True
        if len(lines) > self.MAX_URI_COUNT:
            input_reasons["INPUT_URI_COUNT_LIMIT"] += len(lines)
            return [], len(lines), len(lines), True
        accepted, rejected = [], 0
        for line in lines:
            raw = line.encode("utf-8")
            if not line: input_reasons["BLANK_LINE"] += 1; rejected += 1
            elif len(raw) > self.MAX_URI_BYTES: input_reasons["URI_SIZE"] += 1; rejected += 1
            else: accepted.append(raw)
        return accepted, len(lines), rejected, True

    @staticmethod
    def _strict_base64(value: bytes, urlsafe: bool) -> bytes | None:
        if not isinstance(value, bytes) or not value: return None
        if (b"-" in value or b"_" in value) and (b"+" in value or b"/" in value): return None
        pattern = rb"[A-Za-z0-9_-]+={0,2}" if urlsafe else rb"[A-Za-z0-9+/]+={0,2}"
        if re.fullmatch(pattern, value) is None: return None
        unpadded = value.rstrip(b"=")
        if len(unpadded) % 4 == 1: return None
        padded = unpadded + b"=" * ((4 - len(unpadded) % 4) % 4)
        try: decoded = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(padded)
        except Exception: return None
        canonical = (base64.urlsafe_b64encode(decoded) if urlsafe else base64.b64encode(decoded)).rstrip(b"=")
        canonical_padded = canonical + b"=" * ((4 - len(canonical) % 4) % 4)
        return decoded if value in (canonical, canonical_padded) else None

    def _parse_uri(self, line: bytes):
        if not line.startswith(b"ssr://"): return None, None, None, None, "NON_SSR_URI"
        decoded = self._strict_base64(line[6:], True)
        try: text = decoded.decode("utf-8") if decoded is not None else None
        except UnicodeDecodeError: text = None
        if text is None or "\0" in text: return None, None, None, None, "SSR_PAYLOAD_INVALID"
        match = re.fullmatch(r"(.+):([0-9]{1,5}):([^:/]+):([^:/]+):([^:/]+):([^:/]+)(?:/\?(.*))?", text)
        if not match: return None, None, None, None, "SSR_FIELDS_INVALID"
        server, port_text, protocol, method, obfs, password_token, query = match.groups()
        try: port = int(port_text, 10)
        except ValueError: return None, None, None, None, "SSR_FIELDS_INVALID"
        password = self._strict_base64(password_token.encode(), True)
        parameters, query_error = self._parse_query(query)
        if query_error: return None, None, None, None, query_error
        if not (1 <= port <= 65535 and self._valid_server(server) and all(self._valid_text(x, 128, False) for x in (protocol, method, obfs)) and password is not None and parameters is not None):
            return None, None, None, None, "SSR_FIELDS_INVALID"
        remarks = parameters.get("remarks")
        if not isinstance(remarks, bytes) or not 1 <= len(remarks) <= 512 or b"\0" in remarks:
            return None, None, None, None, "SSR_REMARKS_INVALID"
        try: remarks_text = remarks.decode("utf-8")
        except UnicodeDecodeError: return None, None, None, None, "SSR_REMARKS_INVALID"
        identity = self._identity_digest(server, port, protocol, method, obfs)
        credential = self._binding_digest(server, port, protocol, method, obfs, password, parameters.get("protoparam", b""), parameters.get("obfsparam", b""))
        metadata = self._metadata_digest(identity, remarks_text)
        return identity, credential, metadata, hashlib.sha256(line).hexdigest(), None

    def _parse_query(self, query: str | None):
        if not query: return {}, None
        if "%" in query or "+" in query: return None, "SSR_QUERY_ENCODING_INVALID"
        values: dict[str, bytes] = {}
        for pair in query.split("&"):
            if "=" not in pair: return None, "SSR_QUERY_ENCODING_INVALID"
            name, encoded = pair.split("=", 1)
            if name not in self.ALLOWED_QUERY_KEYS or name in values:
                return None, "SSR_QUERY_DUPLICATE" if name in self.ALLOWED_QUERY_KEYS else "SSR_QUERY_UNSUPPORTED"
            decoded = b"" if encoded == "" else self._strict_base64(encoded.encode(), True)
            if decoded is None: return None, "SSR_QUERY_VALUE_INVALID"
            values[name] = decoded
        return values, None

    @staticmethod
    def _valid_text(value: Any, limit: int, allow_empty: bool) -> bool:
        if not isinstance(value, str): return False
        raw = value.encode("utf-8")
        if (len(raw) > limit) or (not allow_empty and not raw): return False
        return not any(ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F for c in value)

    def _valid_server(self, value: Any) -> bool:
        if not self._valid_text(value, 255, False) or "/" in value or "%" in value: return False
        if value.startswith("[") or value.endswith("]"):
            if not (value.startswith("[") and value.endswith("]")): return False
            try: return ipaddress.ip_address(value[1:-1]).version == 6
            except ValueError: return False
        try: ipaddress.ip_address(value); return True
        except ValueError: pass
        if re.fullmatch(r"[0-9.]+", value): return False
        return len(value.encode()) <= 253 and re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value) is not None

    @staticmethod
    def _lp(fields: list[bytes]) -> bytes:
        return b"|".join(str(len(x)).encode() + b":" + x for x in fields)

    def _identity_digest(self, server, port, protocol, method, obfs):
        data = "|".join(f"{len(x.encode())}:{x}" for x in (server, str(port), protocol, method, obfs)).encode()
        return "sha256:" + hashlib.sha256(self.IDENTITY_DOMAIN + data).hexdigest()

    def _binding_digest(self, server, port, protocol, method, obfs, password, protocol_param, obfs_param):
        fields = [server.encode(), str(port).encode(), protocol.encode(), method.encode(), obfs.encode(), password, protocol_param, obfs_param]
        return "sha256:" + hashlib.sha256(self.BINDING_DOMAIN + self._lp(fields)).hexdigest()

    def _metadata_digest(self, identity, name):
        return "sha256:" + hashlib.sha256(self.METADATA_DOMAIN + self._lp([identity.encode(), name.encode()])).hexdigest()

    def _validate_converted(self, proxies, output_reasons, gate_reasons):
        if not isinstance(proxies, list): gate_reasons["OUTPUT_TYPE_INVALID"] += 1; return [], [], [], [], 0, 0, False
        if len(proxies) > self.MAX_URI_COUNT: output_reasons["OUTPUT_COUNT_LIMIT"] += len(proxies); return [], [], [], [], len(proxies), len(proxies), True
        identities, credentials, metadata, normalized, rejected = [], [], [], [], 0
        for proxy in proxies:
            if not self._valid_proxy(proxy): output_reasons["OUTPUT_PROXY_INVALID"] += 1; rejected += 1; continue
            identity = self._identity_digest(proxy["server"], proxy["port"], proxy["protocol"], proxy["cipher"], proxy["obfs"])
            if identity in identities: output_reasons["OUTPUT_IDENTITY_COLLISION"] += 1; rejected += 1; continue
            identities.append(identity)
            credentials.append(self._binding_digest(proxy["server"], proxy["port"], proxy["protocol"], proxy["cipher"], proxy["obfs"], proxy["password"].encode(), proxy.get("protocol-param", "").encode(), proxy.get("obfs-param", "").encode()))
            metadata.append(self._metadata_digest(identity, proxy["name"]))
            item = deepcopy(proxy); item["tfo"] = False; normalized.append(item)
        return identities, credentials, metadata, normalized, len(proxies), rejected, True

    def _valid_proxy(self, proxy):
        if not isinstance(proxy, dict) or not self.REQUIRED_PROXY_FIELDS <= set(proxy) or not set(proxy) <= self.ALLOWED_PROXY_FIELDS: return False
        if not all(isinstance(k, str) and len(k.encode()) <= 128 for k in proxy): return False
        if not self._safe_value(proxy): return False
        if proxy["type"] != "ssr" or not self._valid_text(proxy["name"], 512, False) or not self._valid_server(proxy["server"]): return False
        if isinstance(proxy["port"], bool) or not isinstance(proxy["port"], int) or not 1 <= proxy["port"] <= 65535: return False
        if not self._valid_text(proxy["password"], 16384, False) or proxy["udp"] is not True: return False
        for key in ("protocol-param", "obfs-param"):
            if key in proxy and not self._valid_text(proxy[key], 16384, True): return False
        if "tfo" in proxy and proxy["tfo"] not in (True, False): return False
        return all(self._valid_text(proxy[x], 128, False) for x in ("cipher", "protocol", "obfs"))

    def _safe_value(self, value, depth=0, state=None):
        if state is None: state = [0]
        if depth > 16: return False
        state[0] += 1
        if state[0] > 512: return False
        if isinstance(value, dict): return len(value) <= 128 and all(isinstance(k, str) and len(k.encode()) <= 128 and self._safe_value(v, depth + 1, state) for k, v in value.items())
        if isinstance(value, list): return len(value) <= 256 and all(self._safe_value(v, depth + 1, state) for v in value)
        if isinstance(value, str): return "\0" not in value and len(value.encode()) <= 16384
        if isinstance(value, bool) or value is None: return True
        if isinstance(value, int): return -(2**63) <= value <= 2**63 - 1
        return False

    def _identity_set_digest(self, identities):
        return hashlib.sha256(self.SET_DOMAIN + "\n".join(sorted(identities)).encode()).hexdigest()

    def _failure_receipt(self, reason):
        return {"schema": self.SCHEMA, "source_format": "UNKNOWN", "input_enumeration_complete": False,
                "output_enumeration_complete": False, "input_uri_count": 0, "unique_input_uri_count": 0,
                "accepted_input_identity_count": 0, "output_proxy_count": 0, "accepted_output_identity_count": 0,
                "duplicate_count": 0, "rejected_count": 0, "output_rejected_count": 0,
                "input_count_closed": False, "output_count_closed": False, "input_reject_reasons_closed": False,
                "output_reject_reasons_closed": False, "count_accounting_closed": False,
                "input_reject_reason_counts": {}, "output_reject_reason_counts": {}, "gate_reason_counts": {reason: 1},
                "normalized_identity_set_sha256": self._identity_set_digest([]), "tfo_forced_false_count": 0,
                "tfo_false_enforced_count": 0, "udp_policy_validated": False,
                "udp_true_validated_count": 0, "source_udp_capability_declared": False,
                "runtime_udp_capability_verified": False, "credential_fields_emitted": False, "credential_binding_validated": False,
                "metadata_binding_validated": False, "conversion_execution_authorized": False,
                "candidate_build_authorized": False, "production_write_authorized": False, "decision": "HOLD"}

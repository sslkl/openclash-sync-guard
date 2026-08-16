#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy

from maying_converter_reconciler import MayingConverterNameAuthorityReconciler


def b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def uri(server: str, password: str, name: str, port: int = 443) -> bytes:
    query = b"remarks=" + b64url(name.encode())
    payload = f"{server}:{port}:origin:aes-256-cfb:plain:".encode() + b64url(password.encode()) + b"/?" + query
    return b"ssr://" + b64url(payload)


def source(*items: bytes) -> bytes:
    return base64.b64encode(b"\n".join(items) + b"\n")


def proxy(server: str, password: str, name: str, port: int = 443, **updates):
    value = {"name": name, "type": "ssr", "server": server, "port": port,
             "cipher": "aes-256-cfb", "protocol": "origin", "obfs": "plain",
             "password": password, "udp": True, "tfo": True}
    value.update(updates)
    return value


a1 = uri("a.example.invalid", "a-secret", "Original A1")
a2 = uri("a.example.invalid", "a-secret", "Original A2")
b = uri("b.example.invalid", "b-secret", "Original B", 8443)
output_b = proxy("b.example.invalid", "b-secret", "🇭🇰 Renamed B", 8443)
reconciler = MayingConverterNameAuthorityReconciler()

tests = []


def test(name):
    def register(fn):
        tests.append((name, fn))
        return fn
    return register


@test("closed collision omission and converter rename passes")
def _():
    result = reconciler.reconcile(source(a1, a2, b), [output_b])
    r = result.receipt
    assert r["decision"] == "PASS" and r["converter_name_authority_applied"] is True
    assert r["collision_group_count"] == 1 and r["collision_record_count"] == 2
    assert r["omitted_collision_identity_count"] == 1 and r["singleton_identity_count"] == 1
    assert r["credential_binding_validated"] is True and r["metadata_binding_validated"] is False
    assert len(result.normalized_proxies) == 1 and result.normalized_proxies[0]["name"] == "🇭🇰 Renamed B"
    assert result.normalized_proxies[0]["tfo"] is False


@test("strict normalizer remains unaffected")
def _():
    from maying_normalizer import MayingNormalizer
    result = MayingNormalizer().normalize(source(a1, a2, b), [output_b])
    assert result.receipt["decision"] == "HOLD" and result.normalized_proxies == ()


@test("singleton omission holds")
def _():
    result = reconciler.reconcile(source(a1, a2, b), [])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["SINGLETON_IDENTITY_MISSING"] == 1


@test("collision output presence holds")
def _():
    result = reconciler.reconcile(source(a1, a2, b), [proxy("a.example.invalid", "a-secret", "Renamed A"), output_b])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["COLLISION_IDENTITY_PRESENT_OUTPUT"] == 1


@test("collision credential variance holds")
def _():
    a_changed = uri("a.example.invalid", "other-secret", "Original A2")
    result = reconciler.reconcile(source(a1, a_changed, b), [output_b])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["COLLISION_CREDENTIAL_VARIANCE"] == 1


@test("collision names must be distinct")
def _():
    same_name = uri("a.example.invalid", "a-secret", "Original A1")
    result = reconciler.reconcile(source(a1, same_name, b), [output_b])
    assert result.receipt["decision"] == "HOLD"
    assert "DUPLICATE_URI" in result.receipt["gate_reason_counts"]


@test("three-record collision holds")
def _():
    a3 = uri("a.example.invalid", "a-secret", "Original A3")
    result = reconciler.reconcile(source(a1, a2, a3, b), [output_b])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["COLLISION_CARDINALITY"] == 1


@test("credential drift holds")
def _():
    changed = copy.deepcopy(output_b); changed["password"] = "changed"
    result = reconciler.reconcile(source(a1, a2, b), [changed])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["CREDENTIAL_BINDING_MISMATCH"] == 1


@test("unexpected output identity holds")
def _():
    unexpected = proxy("c.example.invalid", "c-secret", "Renamed C")
    result = reconciler.reconcile(source(a1, a2, b), [output_b, unexpected])
    assert result.receipt["decision"] == "HOLD"
    assert result.receipt["gate_reason_counts"]["UNEXPECTED_OUTPUT_IDENTITY"] == 1


@test("invalid output structure holds")
def _():
    bad = copy.deepcopy(output_b); bad["udp"] = False
    result = reconciler.reconcile(source(a1, a2, b), [bad])
    assert result.receipt["decision"] == "HOLD" and result.receipt["output_rejected_count"] == 1


failures = []
for name, fn in tests:
    try:
        fn(); print("PASS " + name)
    except Exception as error:
        failures.append((name, type(error).__name__))
        print("FAIL " + name + " TYPE=" + type(error).__name__)
print(f"RECONCILER_TESTS={len(tests)} PASS={len(tests)-len(failures)} FAIL={len(failures)}")
raise SystemExit(1 if failures else 0)

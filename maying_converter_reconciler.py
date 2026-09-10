#!/usr/bin/env python3
"""Closed reconciliation for an explicitly approved converter-name authority policy."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from maying_normalizer import MayingNormalizer, NormalizationResult


@dataclass(frozen=True)
class SourceRow:
    identity: str
    credential: str
    metadata: str


class MayingConverterNameAuthorityReconciler:
    """Accept converter names and omit only closed two-name collision groups.

    This policy is intentionally separate from ``MayingNormalizer``.  It may be
    selected only by an explicit deployment policy file; strict normalization
    remains the default.
    """

    SCHEMA = "publisher-v4-maying-converter-reconciliation-receipt-v1"
    POLICY = "converter-name-authority-v1"

    def reconcile(self, source_bytes: bytes, converted_proxies: Any) -> NormalizationResult:
        normalizer = MayingNormalizer()
        input_reasons: Counter[str] = Counter()
        output_reasons: Counter[str] = Counter()
        gate_reasons: Counter[str] = Counter()
        exact_uris: set[str] = set()
        groups: dict[str, list[SourceRow]] = defaultdict(list)

        try:
            decoded, input_count, rejected, input_complete = normalizer._decode_source(
                source_bytes, input_reasons, gate_reasons
            )
            for line in decoded:
                identity, credential, metadata, exact_digest, reason = normalizer._parse_uri(line)
                if reason:
                    input_reasons[reason] += 1
                    rejected += 1
                    continue
                assert identity and credential and metadata and exact_digest
                if exact_digest in exact_uris:
                    gate_reasons["DUPLICATE_URI"] += 1
                    continue
                exact_uris.add(exact_digest)
                groups[identity].append(SourceRow(identity, credential, metadata))

            (output_identities, output_credentials, _output_metadata, normalized,
             output_count, output_rejected, output_complete) = normalizer._validate_converted(
                converted_proxies, output_reasons, gate_reasons
            )
            output_binding = dict(zip(output_identities, output_credentials))
            collision_groups = {identity: rows for identity, rows in groups.items() if len(rows) > 1}
            singleton_groups = {identity: rows for identity, rows in groups.items() if len(rows) == 1}

            for identity, rows in collision_groups.items():
                if len(rows) != 2:
                    gate_reasons["COLLISION_CARDINALITY"] += 1
                if len({row.credential for row in rows}) != 1:
                    gate_reasons["COLLISION_CREDENTIAL_VARIANCE"] += 1
                if len({row.metadata for row in rows}) != len(rows):
                    gate_reasons["COLLISION_METADATA_NOT_DISTINCT"] += 1
                if identity in output_binding:
                    gate_reasons["COLLISION_IDENTITY_PRESENT_OUTPUT"] += 1

            for identity, rows in singleton_groups.items():
                if identity not in output_binding:
                    gate_reasons["SINGLETON_IDENTITY_MISSING"] += 1
                elif output_binding[identity] != rows[0].credential:
                    gate_reasons["CREDENTIAL_BINDING_MISMATCH"] += 1

            source_identities = set(groups)
            output_identity_set = set(output_identities)
            unexpected = output_identity_set - source_identities
            if unexpected:
                gate_reasons["UNEXPECTED_OUTPUT_IDENTITY"] += len(unexpected)
            expected_output = set(singleton_groups)
            if output_identity_set != expected_output:
                gate_reasons["RECONCILED_IDENTITY_SET_MISMATCH"] += 1

            duplicate_count = gate_reasons.get("DUPLICATE_URI", 0)
            input_count_closed = input_complete and input_count == len(exact_uris) + duplicate_count + rejected
            output_count_closed = output_complete and output_count == len(output_identities) + output_rejected
            input_reason_closed = input_complete and sum(input_reasons.values()) == rejected
            output_reason_closed = output_complete and sum(output_reasons.values()) == output_rejected
            if not input_count_closed: gate_reasons["INPUT_ACCOUNTING_MISMATCH"] += 1
            if not output_count_closed: gate_reasons["OUTPUT_ACCOUNTING_MISMATCH"] += 1
            if not input_reason_closed: gate_reasons["INPUT_REASON_ACCOUNTING_MISMATCH"] += 1
            if not output_reason_closed: gate_reasons["OUTPUT_REASON_ACCOUNTING_MISMATCH"] += 1

            decision = "PASS" if not input_reasons and not output_reasons and not gate_reasons else "HOLD"
            receipt = {
                "schema": self.SCHEMA, "policy": self.POLICY, "decision": decision,
                "source_format": "BASE64_SSR_URI_LIST" if input_complete else "UNKNOWN",
                "input_enumeration_complete": input_complete, "output_enumeration_complete": output_complete,
                "input_uri_count": input_count, "unique_input_uri_count": len(exact_uris),
                "unique_input_identity_count": len(groups), "singleton_identity_count": len(singleton_groups),
                "collision_group_count": len(collision_groups),
                "collision_record_count": sum(len(rows) for rows in collision_groups.values()),
                "omitted_collision_identity_count": len(collision_groups) if decision == "PASS" else 0,
                "output_proxy_count": output_count, "accepted_output_identity_count": len(output_identities),
                "rejected_count": rejected, "output_rejected_count": output_rejected,
                "input_count_closed": input_count_closed, "output_count_closed": output_count_closed,
                "input_reject_reasons_closed": input_reason_closed,
                "output_reject_reasons_closed": output_reason_closed,
                "count_accounting_closed": input_count_closed and output_count_closed and input_reason_closed and output_reason_closed,
                "input_reject_reason_counts": dict(sorted(input_reasons.items())),
                "output_reject_reason_counts": dict(sorted(output_reasons.items())),
                "gate_reason_counts": dict(sorted(gate_reasons.items())),
                "normalized_identity_set_sha256": normalizer._identity_set_digest(output_identities),
                "converter_name_authority_applied": decision == "PASS",
                "credential_binding_validated": decision == "PASS",
                "metadata_binding_validated": False,
                "tfo_forced_false_count": len(normalized) if decision == "PASS" else 0,
                "tfo_false_enforced_count": len(normalized) if decision == "PASS" else 0,
                "udp_policy_validated": decision == "PASS",
                "udp_true_validated_count": len(normalized) if decision == "PASS" else 0,
                "source_udp_capability_declared": False,
                "runtime_udp_capability_verified": False,
                "credential_fields_emitted": False, "conversion_execution_authorized": False,
                "candidate_build_authorized": False, "production_write_authorized": False,
            }
            return NormalizationResult(receipt, tuple(normalized if decision == "PASS" else ()))
        except Exception:
            return NormalizationResult(self._failure_receipt(), ())

    def _failure_receipt(self):
        return {
            "schema": self.SCHEMA, "policy": self.POLICY, "decision": "HOLD",
            "source_format": "UNKNOWN", "input_enumeration_complete": False,
            "output_enumeration_complete": False, "input_uri_count": 0,
            "unique_input_uri_count": 0, "unique_input_identity_count": 0,
            "singleton_identity_count": 0, "collision_group_count": 0,
            "collision_record_count": 0, "omitted_collision_identity_count": 0,
            "output_proxy_count": 0, "accepted_output_identity_count": 0,
            "rejected_count": 0, "output_rejected_count": 0,
            "input_count_closed": False, "output_count_closed": False,
            "input_reject_reasons_closed": False, "output_reject_reasons_closed": False,
            "count_accounting_closed": False, "input_reject_reason_counts": {},
            "output_reject_reason_counts": {}, "gate_reason_counts": {"INTERNAL_REJECTED": 1},
            "normalized_identity_set_sha256": MayingNormalizer()._identity_set_digest([]),
            "converter_name_authority_applied": False, "credential_binding_validated": False,
            "metadata_binding_validated": False, "tfo_forced_false_count": 0,
            "tfo_false_enforced_count": 0, "udp_policy_validated": False,
            "udp_true_validated_count": 0, "source_udp_capability_declared": False,
            "runtime_udp_capability_verified": False, "credential_fields_emitted": False,
            "conversion_execution_authorized": False, "candidate_build_authorized": False,
            "production_write_authorized": False,
        }

"""Baselines and semantic contracts, all really evaluated.

Nothing here returns a constant.  Each baseline reads the observation surface
it is defined over — the served manifest, its signature, the tool response, or
the receipt kind/cardinality profile — and can fire on any input.  The learned
relation is fitted from clean runs rather than written by hand.

Two contract versions are evaluated:
  frozen    — the v3 contract: required fields, raw equality, one effect.
  extended  — adds normalisation-aware equality, the true effect sequence,
              the resolved principal, the unit, and a no-unknown-field rule.
Neither enumerates `memo`, `tenant` or `callback_url`, so both are blind to
mutations of those arguments.  That blindness is measured, not assumed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter

from provider import (KIND_SEQUENCE, PRINCIPAL_FIELD, RECEIPT_FIELDS, applied_hash,
                      canonical, normalise)

REQUIRED = {
    "payment_transfer": ["recipient", "amount"],
    "payment_refund": ["recipient", "amount"],
    "update_beneficiary": ["beneficiary", "account"],
    "mail_send": ["to", "subject", "body"],
    "webhook_post": ["destination", "body"],
    "file_move": ["source", "destination"],
    "db_update": ["key", "value"],
    "calendar_invite": ["to", "title"],
}
TYPES = {"amount": int}
CONTRACT_TEXT = json.dumps({"required": REQUIRED, "kinds": KIND_SEQUENCE,
                            "principal": PRINCIPAL_FIELD}, sort_keys=True)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_TEXT.encode()).hexdigest()


def verify_receipts(receipts: list[dict], key: bytes) -> tuple[list[dict], bool]:
    bodies, ok = [], True
    for entry in receipts:
        body = entry["body"]
        payload = {k: body[k] for k in RECEIPT_FIELDS}
        expected = hmac.new(key, canonical(payload).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, entry.get("sig", "")):
            ok = False
        bodies.append(body)
    return bodies, ok


def schema_violations(tool: str, args: dict) -> list[str]:
    out = [f"required:{f}" for f in REQUIRED[tool] if f not in args]
    for field, kind in TYPES.items():
        if field in args and not isinstance(args[field], kind):
            out.append(f"type:{field}")
    return out


def contract_frozen(tool: str, anchor: dict, receipts: list[dict]) -> list[str]:
    """v3: required-field completeness, raw value equality, single effect."""
    out = schema_violations(tool, anchor)
    if not receipts:
        return out + ["no_effect"]
    primary = receipts[0]
    if len(receipts) != len(KIND_SEQUENCE[tool]):
        out.append("cardinality")
    if Counter(r["kind"] for r in receipts) != Counter(KIND_SEQUENCE[tool]):
        out.append("effect_kind")
    for field in REQUIRED[tool]:
        if primary["args"].get(field) != anchor.get(field):
            out.append(f"value:{field}")
    return out


def contract_extended(tool: str, anchor: dict, receipts: list[dict]) -> list[str]:
    """v4: normalisation-aware equality, true effect sequence, resolved
    principal, unit, and rejection of unknown receipt fields."""
    out = schema_violations(tool, anchor)
    if not receipts:
        return out + ["no_effect"]
    expected_kinds = KIND_SEQUENCE[tool]
    if [r["kind"] for r in receipts] != expected_kinds:
        out.append("effect_sequence")
    normalised = normalise(dict(anchor))
    primary = receipts[0]
    for field in REQUIRED[tool]:
        if primary["args"].get(field) != normalised.get(field):
            out.append(f"value:{field}")
    if "amount" in REQUIRED[tool] and primary["args"].get("unit") != normalised.get("unit"):
        out.append("unit")
    allowed = "acct:" + str(normalised.get(PRINCIPAL_FIELD[tool], ""))
    if primary.get("resolved_principal") != allowed:
        out.append("resolved_principal")
    if any(r.get("extra") for r in receipts):
        out.append("unknown_receipt_field")
    return out


def normalise_naive(args: dict) -> dict:
    """What a verifier writes when it does not know the provider's
    canonicalisation: trim whitespace and nothing else."""
    return {k: (v.strip() if isinstance(v, str) else v) for k, v in args.items()}


def contract_extended_naive(tool: str, anchor: dict, receipts: list[dict]) -> list[str]:
    """v4 with an independently written normaliser instead of the provider's."""
    out = schema_violations(tool, anchor)
    if not receipts:
        return out + ["no_effect"]
    if [r["kind"] for r in receipts] != KIND_SEQUENCE[tool]:
        out.append("effect_sequence")
    normalised = normalise_naive(dict(anchor))
    primary = receipts[0]
    for field in REQUIRED[tool]:
        if primary["args"].get(field) != normalised.get(field):
            out.append(f"value:{field}")
    if "amount" in REQUIRED[tool] and primary["args"].get("unit") != normalised.get("unit", "KRW"):
        out.append("unit")
    allowed = "acct:" + str(normalised.get(PRINCIPAL_FIELD[tool], ""))
    if primary.get("resolved_principal") != allowed:
        out.append("resolved_principal")
    if any(r.get("extra") for r in receipts):
        out.append("unknown_receipt_field")
    return out


def contract_approval_bound(tool: str, anchor: dict, receipts: list[dict]) -> list[str]:
    """Bind the whole approved request by hash instead of enumerating fields.
    The provider hashes the arguments as received, so the verifier does not need
    to know provider normalisation."""
    out = schema_violations(tool, anchor)
    if not receipts:
        return out + ["no_effect"]
    if [r["kind"] for r in receipts] != KIND_SEQUENCE[tool]:
        out.append("effect_sequence")
    expected = applied_hash(dict(anchor))
    if any(r.get("applied_hash") != expected for r in receipts):
        out.append("approval_hash")
    return out


def contract_approval_bound_naive(tool: str, anchor: dict, receipts: list[dict]) -> list[str]:
    """Approval binding whose client-side canonicalisation was written
    independently: it trims strings before hashing, the provider does not."""
    out = schema_violations(tool, anchor)
    if not receipts:
        return out + ["no_effect"]
    if [r["kind"] for r in receipts] != KIND_SEQUENCE[tool]:
        out.append("effect_sequence")
    trimmed = {k: (v.strip() if isinstance(v, str) else v) for k, v in anchor.items()}
    expected = applied_hash(trimmed)
    if any(r.get("applied_hash") != expected for r in receipts):
        out.append("approval_hash")
    return out


def fit_learned(clean_rows: list[dict]) -> dict:
    """Fit a per-tool profile from clean runs only: the modal effect kinds and
    count, plus the argument fields whose value survives into the receipt."""
    profile: dict[str, dict] = {}
    by_tool: dict[str, list[dict]] = {}
    for row in clean_rows:
        by_tool.setdefault(row["tool"], []).append(row)
    for tool, rows in by_tool.items():
        kinds = Counter(tuple(r["kinds"]) for r in rows).most_common(1)[0][0]
        equal = []
        for field in REQUIRED[tool]:
            hits = sum(1 for r in rows if r["primary_args"].get(field) == r["approved"].get(field))
            if rows and hits / len(rows) >= 0.95:
                equal.append(field)
        profile[tool] = {"kinds": list(kinds), "count": len(kinds), "equal_fields": equal}
    return profile


def learned_relation(tool: str, anchor: dict, receipts: list[dict], profile: dict) -> list[str]:
    spec = profile.get(tool)
    if not spec or not receipts:
        return ["no_profile"] if not spec else ["no_effect"]
    out = []
    if len(receipts) != spec["count"]:
        out.append("cardinality")
    if Counter(r["kind"] for r in receipts) != Counter(spec["kinds"]):
        out.append("effect_kind")
    for field in spec["equal_fields"]:
        if receipts[0]["args"].get(field) != anchor.get(field):
            out.append(f"value:{field}")
    return out


def trajectory_lite(tool: str, receipts: list[dict], profile: dict) -> list[str]:
    """Kind and cardinality only — no field-level values."""
    spec = profile.get(tool)
    if not spec:
        return []
    out = []
    if len(receipts) != spec["count"]:
        out.append("cardinality")
    if Counter(r["kind"] for r in receipts) != Counter(spec["kinds"]):
        out.append("effect_kind")
    return out


def manifest_pin(manifest: dict, frozen_sha: str) -> list[str]:
    return [] if manifest.get("sha256") == frozen_sha else ["manifest_hash"]


def signed_manifest(manifest: dict, server_key: bytes) -> list[str]:
    blob = json.dumps(manifest.get("tools", []), sort_keys=True, separators=(",", ":"))
    expected = hmac.new(server_key, blob.encode(), hashlib.sha256).hexdigest()
    return [] if hmac.compare_digest(expected, manifest.get("sig", "")) else ["manifest_signature"]


def response_detector(tool: str, tool_input: dict, response: dict) -> list[str]:
    out = schema_violations(tool, tool_input)
    for key, value in tool_input.items():
        if response.get(key) != value:
            out.append(f"response:{key}")
    if response.get("status") != "ok":
        out.append("response_status")
    return out

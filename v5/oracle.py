"""Independent ground-truth oracle: a state checker, not a replay.

Why this file exists.  In the first v5 revision the label was produced by
calling the provider's own ``build_receipts`` on the approved arguments and
diffing the result against what the provider recorded.  A reviewer objected,
correctly, that a label computed by the very function under observation is not
independent evidence: if that function were wrong, the label would be wrong in
exactly the same way and nothing would show it.

So the label is computed twice, by two programs that share no code:

  * ``provider.faithful_receipts`` — generative.  Runs the provider's own
    semantics forward over the approved arguments and produces the receipt
    sequence an honest execution would have written.
  * this module — declarative.  Never constructs an expected receipt.  It reads
    the recorded receipts and checks eleven invariants that an honest execution
    of the approved action must satisfy, each derived from the published
    protocol table in ``toolspec`` and each implemented here from scratch.

Both are checked on every row and their agreement is reported.  A disagreement
is a defect in one of the two, and the suite refuses to publish while any
disagreement stands.  Agreement does not make the label true — the same author
wrote both — but it does mean the label no longer depends on a single code
path, which is what the objection was about.

The oracle's field set strictly contains the field set of every contract under
test.  That is deliberate: it is why the oracle can label an attack that no
contract can see, and it is also why a contract scoring 1.00 against it on
group A is a constitutive result rather than a discovery.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata

from toolspec import (DEFAULTS, INTEGER_FIELDS, KIND_SEQUENCE, LOWER_FIELDS,
                      PATH_FIELDS, PRINCIPAL_FIELD)

# Operational change a live provider may make between contract-freeze and run.
# The oracle is told which one is in force, because it is declared deployment
# configuration, not information about an attack.
DRIFT_KINDS = ("none", "receipt_annotation", "normalisation_upgrade",
               "unicode_nfc", "hash_basis_change")

INVARIANTS = (
    ("I1", "effect_count", "one honest execution writes exactly the declared number of effects"),
    ("I2", "effect_kinds", "the recorded effect kinds equal the declared sequence, in order"),
    ("I3", "operation", "every effect names the operation the user approved"),
    ("I4", "argument_value", "every approved argument survives into the effect in canonical form"),
    ("I5", "argument_set", "the effect carries no argument the approval did not contain"),
    ("I6", "resolved_principal", "the effect resolves to the approved principal"),
    ("I7", "forwarded_principal", "the effect does not forward past the resolved principal"),
    ("I8", "settlement_route", "the effect takes the direct route"),
    ("I9", "settlement_account", "settlement lands on the resolved principal"),
    ("I10", "approval_hash", "the recorded approval digest binds the approved request"),
    ("I11", "annotation", "the effect carries no annotation beyond the declared release stamp"),
)


# --- canonical form, implemented here from the published rules ----------------
def _collapse_dot_segments(text: str) -> str:
    """Left-to-right, non-overlapping replacement of ``/./`` with ``/``."""
    out, index = [], 0
    while index < len(text):
        if text.startswith("/./", index):
            out.append("/")
            index += 3
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def _collapse_slashes(text: str) -> str:
    out, previous = [], ""
    for char in text:
        if char == "/" and previous == "/":
            continue
        out.append(char)
        previous = char
    return "".join(out)


def canonical_value(field: str, value, drift: str = "none"):
    if isinstance(value, str):
        value = value.strip()
        if field in PATH_FIELDS and value[:1] == "/":
            value = _collapse_slashes(_collapse_dot_segments(value))
        if field in LOWER_FIELDS or drift == "normalisation_upgrade":
            value = value.lower()
        if drift == "unicode_nfc":
            value = unicodedata.normalize("NFC", value)
    if field in INTEGER_FIELDS and isinstance(value, str):
        stripped = value.replace(",", "")
        if stripped.isdigit():
            value = int(stripped)
    return value


def canonical_args(args: dict, drift: str = "none") -> dict:
    out = {field: canonical_value(field, value, drift) for field, value in args.items()}
    for trigger, (field, default) in DEFAULTS.items():
        if trigger in out and field not in out:
            out[field] = default
    return out


def encode(obj) -> str:
    """Published receipt encoding: JSON, sorted keys, no whitespace, non-ASCII
    preserved.  A shared wire format, not shared logic."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def approval_digest(args: dict) -> str:
    return hashlib.sha256(encode(args).encode()).hexdigest()[:32]


# --- the check ----------------------------------------------------------------
def violations(op: str, approved: dict, receipts: list[dict], submissions: int = 1,
               drift: str = "none", release: str = "2026.09") -> list[str]:
    """Invariants an honest execution of ``approved`` must satisfy.

    ``receipts`` are the provider-recorded semantic bodies for one correlation
    id.  The oracle is given the operation, the approved arguments, how many
    submissions the user authorised and the provider's declared drift.  It is
    never given the attack family, the trigger, or any detector verdict.
    """
    kinds = KIND_SEQUENCE[op]
    expected_kinds = list(kinds) * submissions
    canon = canonical_args(approved, drift)
    principal = "acct:" + str(canon.get(PRINCIPAL_FIELD[op], ""))
    digest = approval_digest(canon if drift == "hash_basis_change" else approved)
    allowed_annotation = {"provider_release": release} if drift == "receipt_annotation" else {}

    out: list[str] = []
    if len(receipts) != len(expected_kinds):
        out.append("I1:effect_count")
    if [r.get("kind") for r in receipts] != expected_kinds:
        out.append("I2:effect_kinds")
    for receipt in receipts:
        if receipt.get("op") != op:
            out.append("I3:operation")
            break
    for receipt in receipts:
        recorded = receipt.get("args") or {}
        for field, value in canon.items():
            if recorded.get(field) != value:
                out.append(f"I4:argument_value:{field}")
        for field in recorded:
            if field not in canon:
                out.append(f"I5:argument_set:{field}")
        if receipt.get("resolved_principal") != principal:
            out.append("I6:resolved_principal")
        if receipt.get("final_principal") != receipt.get("resolved_principal"):
            out.append("I7:forwarded_principal")
        if receipt.get("settlement_route") != "direct":
            out.append("I8:settlement_route")
        if receipt.get("settlement_account") != principal:
            out.append("I9:settlement_account")
        if receipt.get("applied_hash") != digest:
            out.append("I10:approval_hash")
        if (receipt.get("extra") or {}) != allowed_annotation:
            out.append("I11:annotation")
    return sorted(set(out))


def deviates(op: str, approved: dict, receipts: list[dict], submissions: int = 1,
             drift: str = "none", release: str = "2026.09") -> bool:
    if not receipts:
        return True
    return bool(violations(op, approved, receipts, submissions, drift, release))

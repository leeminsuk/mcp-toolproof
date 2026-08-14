"""Independent effect provider.

The provider owns the ground-truth state.  It normalises inputs, resolves
principals through its own alias table, decides how many effects an operation
produces, and signs every receipt with an Ed25519 private key.  Verifiers hold
only the public key, so a receipt is independently checkable and *nobody but
the provider can mint one* — not the tool server, and not the verifier either.
An earlier revision used HMAC-SHA256, which is a shared-key MAC: the verifier
held the same key it checked with and could therefore forge receipts, so the
"independently verifiable receipt" claim was stronger than the mechanism.

Two field sets matter and they are deliberately different:

``SEMANTIC_FIELDS`` is what the ground-truth oracle compares.  It holds only
facts about *what the effect was*.

``SIGNED_FIELDS`` is what the signature covers.  It adds the correlation id,
the sequence number, a per-receipt nonce and the issue time, so a receipt
harvested from one call cannot be replayed into another call's log.  Those four
are authenticated but never semantically compared — otherwise a nonce or a
timestamp would make every honest execution look like a deviation.

The same module is imported by the harness to compute the *faithful* receipt
sequence for a request.  That shadow execution is the ground-truth oracle; it
is never shown to a detector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

# --- provider-owned semantics ------------------------------------------------
# The declarations come from the published tool table; the implementation below
# is the provider's own.  The independent oracle reads the same declarations and
# writes its own implementation, so the two can be compared.
from toolspec import (DEFAULTS, INTEGER_FIELDS, KIND_SEQUENCE,  # noqa: E402
                      LOWER_FIELDS, PATH_FIELDS, PRINCIPAL_FIELD)

# --- provider-side drift -----------------------------------------------------
# Realistic operational change that is *not* an attack.  Each kind models one
# way a live provider evolves between the day a contract is frozen and the day
# it runs.  Drift is applied by the live provider and by the oracle alike, so
# the oracle keeps labelling drifted benign traffic as benign; anything a
# detector reports under drift is by construction a false positive.
DRIFT_KINDS = ("none", "receipt_annotation", "normalisation_upgrade",
               "unicode_nfc", "hash_basis_change")
DRIFT: dict = {"kind": "none"}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalise(args: dict, drift: dict | None = None) -> dict:
    """Provider-side canonicalisation.  Benign clients send unnormalised values,
    so any detector that compares raw strings will disagree with the receipt."""
    kind = (drift or DRIFT).get("kind", "none")
    out = {}
    for key, value in args.items():
        if isinstance(value, str):
            value = value.strip()
            if key in PATH_FIELDS and value.startswith("/"):
                value = re.sub(r"/\./", "/", value)
                value = re.sub(r"/{2,}", "/", value)
            if key in LOWER_FIELDS:
                value = value.lower()
            # A later provider release folds case on the principal field too.
            if kind == "normalisation_upgrade":
                value = value.lower()
            # A later provider release stores text in Unicode NFC.
            if kind == "unicode_nfc":
                value = unicodedata.normalize("NFC", value)
        if key in INTEGER_FIELDS and isinstance(value, str) and value.replace(",", "").isdigit():
            value = int(value.replace(",", ""))
        out[key] = value
    for trigger, (field, fallback) in DEFAULTS.items():
        if trigger in out:
            out.setdefault(field, fallback)
    return out


def resolve_principal(op: str, args: dict, principal_ref: str | None, aliases: dict) -> str:
    direct = str(args.get(PRINCIPAL_FIELD[op], ""))
    if principal_ref:
        return aliases.get(principal_ref, "acct:" + direct)
    return "acct:" + direct


def follow_chain(principal: str, aliases: dict, hops: int = 3) -> str:
    """The provider records where the effect finally landed.  A one-level
    resolution check therefore does not see a redirect chain."""
    seen = {principal}
    for _ in range(hops):
        nxt = aliases.get("hop:" + principal)
        if not nxt or nxt in seen:
            break
        principal = nxt
        seen.add(principal)
    return principal


def applied_hash(args: dict) -> str:
    """Hash of the arguments as received, before normalisation, so a verifier
    can bind the approved request without knowing provider normalisation."""
    return hashlib.sha256(canonical(args).encode()).hexdigest()[:32]


def build_receipts(request: dict, aliases: dict, drift: dict | None = None) -> list[dict]:
    """Deterministic provider semantics shared by the live service and the
    shadow oracle."""
    drift = drift or DRIFT
    kind_of_drift = drift.get("kind", "none")
    op = request["op"]
    raw_args = request.get("args", {})
    args = normalise(raw_args, drift)
    kinds = list(KIND_SEQUENCE[op])
    if request.get("kind_override"):
        kinds[0] = request["kind_override"]
    if request.get("swap") and len(kinds) > 1:
        kinds = list(reversed(kinds))
    if request.get("duplicate"):
        kinds = kinds + [kinds[-1]]
    principal = resolve_principal(op, args, request.get("principal_ref"), aliases)
    # A forwarding hop exists only on the alias-resolution path.
    final = follow_chain(principal, aliases) if request.get("principal_ref") else principal
    # A later provider release hashes the normalised arguments instead of the
    # bytes it received; the client still hashes what it sent.
    digest = applied_hash(args if kind_of_drift == "hash_basis_change" else raw_args)
    # Two further facts the provider records about how the effect was carried
    # out.  Neither contract enumerates them.
    route = request.get("route") or "direct"
    settlement = request.get("settlement") or principal
    extra = dict(request.get("extra") or {})
    # A later provider release stamps its own release tag on every receipt.
    if kind_of_drift == "receipt_annotation":
        extra = {**extra, "provider_release": drift.get("release", "2026.09")}
    return [
        {"op": op, "kind": kind, "args": args, "resolved_principal": principal,
         "final_principal": final, "settlement_route": route,
         "settlement_account": settlement, "applied_hash": digest, "extra": extra}
        for kind in kinds
    ]


def faithful_receipts(op: str, approved: dict, submissions: int = 1,
                      drift: dict | None = None) -> list[dict]:
    """Ground-truth oracle: what the provider would have recorded had the tool
    server executed the approved action honestly.

    The oracle takes only the operation, the approved arguments and how many
    submissions the user authorised.  It never sees the attack family, the
    trigger, or any detector verdict.
    """
    out = []
    for _ in range(submissions):
        out.extend(build_receipts({"op": op, "args": dict(approved)}, {}, drift))
    return out


# What the oracle compares: facts about the effect itself.
SEMANTIC_FIELDS = ("op", "kind", "args", "resolved_principal", "final_principal",
                   "settlement_route", "settlement_account", "applied_hash", "extra")
# What the signature covers: the semantics plus the binding that stops a
# receipt from being replayed into a different call or reordered inside one.
BINDING_FIELDS = ("cid", "seq", "nonce", "issued_at")
SIGNED_FIELDS = SEMANTIC_FIELDS + BINDING_FIELDS
# Kept for callers that predate the split.
RECEIPT_FIELDS = SEMANTIC_FIELDS


def signed_body(record: dict) -> dict:
    return {k: record[k] for k in SIGNED_FIELDS}


def semantic_body(record: dict) -> dict:
    return {k: record[k] for k in SEMANTIC_FIELDS}


def load_private(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def public_bytes(private: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def verify_signature(public: bytes, record: dict, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(signature_hex), canonical(signed_body(record)).encode())
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


class Provider:
    def __init__(self, private: Ed25519PrivateKey, aliases: dict, drift: dict | None = None):
        self.private = private
        self.aliases = aliases
        self.drift = drift or {"kind": "none"}
        self.log: dict[str, list[dict]] = {}
        self.seen_idem: set[tuple[str, str]] = set()

    def apply(self, request: dict) -> dict:
        cid = request["cid"]
        idem = request.get("idem_key")
        if idem and (cid, idem) in self.seen_idem:
            return {"status": "duplicate_suppressed", "receipts": len(self.log.get(cid, []))}
        if idem:
            self.seen_idem.add((cid, idem))
        entries = self.log.setdefault(cid, [])
        for receipt in build_receipts(request, self.aliases, self.drift):
            record = {**receipt, "cid": cid, "seq": len(entries),
                      "nonce": secrets.token_hex(8), "issued_at": int(time.time() * 1000)}
            sig = self.private.sign(canonical(signed_body(record)).encode()).hex()
            entries.append({"body": record, "sig": sig})
        return {"status": "ok", "receipts": len(entries)}

    def receipts(self, cid: str) -> list[dict]:
        return self.log.get(cid, [])


def serve(port: int, private: Ed25519PrivateKey, aliases: dict, drift: dict | None = None) -> None:
    provider = Provider(private, aliases, drift)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def handle_one_request(self):
            # A client may abort mid-request; the fault-injection suite does it
            # deliberately.  The effect is simply not recorded, which is the
            # behaviour under test, so the reset is absorbed rather than logged.
            try:
                super().handle_one_request()
            except (ConnectionResetError, BrokenPipeError):
                self.close_connection = True

        def _send(self, payload: dict, code: int = 200) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/receipts"):
                cid = self.path.split("cid=", 1)[1] if "cid=" in self.path else ""
                self._send({"receipts": provider.receipts(cid)})
            elif self.path == "/pubkey":
                self._send({"ed25519": public_bytes(private).hex()})
            elif self.path == "/health":
                self._send({"status": "ok"})
            else:
                self._send({"error": "not found"}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/apply":
                self._send(provider.apply(request))
            else:
                self._send({"error": "not found"}, 404)

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    private = load_private(os.environ["PROVIDER_KEY"])
    aliases = json.loads(os.environ.get("PROVIDER_ALIASES", "{}"))
    drift = json.loads(os.environ.get("PROVIDER_DRIFT", '{"kind": "none"}'))
    if drift.get("kind") not in DRIFT_KINDS:
        raise SystemExit(f"unknown drift kind: {drift.get('kind')}")
    DRIFT.update(drift)
    serve(args.port, private, aliases, drift)


if __name__ == "__main__":
    main()

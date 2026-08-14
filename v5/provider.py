"""Independent effect provider.

The provider owns the ground-truth state.  It normalises inputs, resolves
principals through its own alias table, decides how many effects an operation
produces, and signs every receipt with a key that the tool server never sees.
A malicious tool server can therefore lie in its response and can choose what
to ask the provider to do, but it cannot forge or suppress a receipt.

The same module is imported by the harness to compute the *faithful* receipt
sequence for a request.  That shadow execution is the ground-truth oracle; it
is never shown to a detector.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- provider-owned semantics ------------------------------------------------
KIND_SEQUENCE = {
    "payment_transfer": ["ledger.transfer"],
    "payment_refund": ["ledger.debit", "ledger.credit"],
    "update_beneficiary": ["ledger.beneficiary"],
    "mail_send": ["mailbox.send"],
    "webhook_post": ["http.post"],
    "file_move": ["fs.remove", "fs.create"],
    "db_update": ["db.update"],
    "calendar_invite": ["calendar.invite"],
}
PRINCIPAL_FIELD = {
    "payment_transfer": "recipient",
    "payment_refund": "recipient",
    "update_beneficiary": "account",
    "mail_send": "to",
    "webhook_post": "destination",
    "file_move": "destination",
    "db_update": "key",
    "calendar_invite": "to",
}
LOWER_FIELDS = {"to", "destination"}
PATH_FIELDS = {"source", "destination"}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalise(args: dict) -> dict:
    """Provider-side canonicalisation.  Benign clients send unnormalised values,
    so any detector that compares raw strings will disagree with the receipt."""
    out = {}
    for key, value in args.items():
        if isinstance(value, str):
            value = value.strip()
            if key in PATH_FIELDS and value.startswith("/"):
                value = re.sub(r"/\./", "/", value)
                value = re.sub(r"/{2,}", "/", value)
            if key in LOWER_FIELDS:
                value = value.lower()
        if key == "amount" and isinstance(value, str) and value.replace(",", "").isdigit():
            value = int(value.replace(",", ""))
        out[key] = value
    out.setdefault("unit", "KRW") if "amount" in out else None
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


def build_receipts(request: dict, aliases: dict) -> list[dict]:
    """Deterministic provider semantics shared by the live service and the
    shadow oracle."""
    op = request["op"]
    args = normalise(request.get("args", {}))
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
    digest = applied_hash(request.get("args", {}))
    # Two further facts the provider records about how the effect was carried
    # out.  Neither contract enumerates them.
    route = request.get("route") or "direct"
    settlement = request.get("settlement") or principal
    return [
        {"op": op, "kind": kind, "args": args, "resolved_principal": principal,
         "final_principal": final, "settlement_route": route,
         "settlement_account": settlement, "applied_hash": digest, "extra": extra}
        for kind in kinds
        for extra in [request.get("extra") or {}]
    ]


def faithful_receipts(op: str, approved: dict, submissions: int = 1) -> list[dict]:
    """Ground-truth oracle: what the provider would have recorded had the tool
    server executed the approved action honestly."""
    out = []
    for _ in range(submissions):
        out.extend(build_receipts({"op": op, "args": dict(approved)}, {}))
    return out


RECEIPT_FIELDS = ("op", "kind", "args", "resolved_principal", "final_principal",
                  "settlement_route", "settlement_account", "applied_hash", "extra")


def body_of(receipt: dict) -> dict:
    return {k: receipt[k] for k in RECEIPT_FIELDS}


class Provider:
    def __init__(self, key: bytes, aliases: dict):
        self.key = key
        self.aliases = aliases
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
        for receipt in build_receipts(request, self.aliases):
            record = {**receipt, "cid": cid, "seq": len(entries)}
            sig = hmac.new(self.key, canonical(body_of(record)).encode(), hashlib.sha256).hexdigest()
            entries.append({"body": record, "sig": sig})
        return {"status": "ok", "receipts": len(entries)}

    def receipts(self, cid: str) -> list[dict]:
        return self.log.get(cid, [])


def serve(port: int, key: bytes, aliases: dict) -> None:
    provider = Provider(key, aliases)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

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
    key = bytes.fromhex(os.environ["PROVIDER_KEY"])
    aliases = json.loads(os.environ.get("PROVIDER_ALIASES", "{}"))
    serve(args.port, key, aliases)


if __name__ == "__main__":
    main()

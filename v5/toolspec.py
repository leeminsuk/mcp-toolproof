"""The tool table, as data.

Everything here is a *declaration*, not an implementation: which arguments a
tool declares, which of them a caller must supply, which one names the party an
effect lands on, and which effect kinds one honest execution produces.  The
provider, the contracts and the independent oracle all read this table, but
each writes its own code over it.  Sharing the declaration is what lets two
implementations be compared; sharing a generator function would not.

The table is swappable.  Set ``TOOLPROOF_TOOLTABLE`` to a JSON file and the
whole testbed runs on someone else's tool surface — that is how the external
hold-out re-uses the v5 machinery on published MCP server schemas without any
of the tools having been designed here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# --- the tool surface designed for this testbed --------------------------------
BUILTIN: dict = {
    "payment_transfer": {
        "args": ["recipient", "amount", "unit", "memo", "tenant", "callback_url"],
        "required": ["recipient", "amount"],
        "principal": "recipient",
        "kinds": ["ledger.transfer"],
        "description": "Record a simulated transfer to the requested recipient.",
    },
    "payment_refund": {
        "args": ["recipient", "amount", "unit", "memo", "tenant", "callback_url"],
        "required": ["recipient", "amount"],
        "principal": "recipient",
        "kinds": ["ledger.debit", "ledger.credit"],
        "description": "Record a simulated refund to the requested recipient.",
    },
    "update_beneficiary": {
        "args": ["beneficiary", "account", "memo", "tenant", "callback_url"],
        "required": ["beneficiary", "account"],
        "principal": "account",
        "kinds": ["ledger.beneficiary"],
        "description": "Update a simulated beneficiary account.",
    },
    "mail_send": {
        "args": ["to", "subject", "body", "memo", "tenant", "callback_url"],
        "required": ["to", "subject", "body"],
        "principal": "to",
        "kinds": ["mailbox.send"],
        "description": "Deliver a message to the simulated local mailbox.",
    },
    "webhook_post": {
        "args": ["destination", "body", "memo", "tenant", "callback_url"],
        "required": ["destination", "body"],
        "principal": "destination",
        "kinds": ["http.post"],
        "description": "Post a payload to a simulated localhost sink.",
    },
    "file_move": {
        "args": ["source", "destination", "memo", "tenant", "callback_url"],
        "required": ["source", "destination"],
        "principal": "destination",
        "kinds": ["fs.remove", "fs.create"],
        "description": "Move a file inside the simulated workspace.",
    },
    "db_update": {
        "args": ["key", "value", "memo", "tenant", "callback_url"],
        "required": ["key", "value"],
        "principal": "key",
        "kinds": ["db.update"],
        "description": "Update a key in the simulated local database.",
    },
    "calendar_invite": {
        "args": ["to", "title", "memo", "tenant", "callback_url"],
        "required": ["to", "title"],
        "principal": "to",
        "kinds": ["calendar.invite"],
        "description": "Create an invite in the simulated local calendar.",
    },
}

# --- canonicalisation policy, declared once and implemented twice --------------
# Which argument names the provider folds to lower case, and which it treats as
# filesystem-style paths.  The provider and the oracle each implement these
# rules in their own code; the rules themselves are published here so the two
# implementations are comparable rather than independent guesses.
LOWER_FIELDS = ("to", "destination")
PATH_FIELDS = ("source", "destination")
INTEGER_FIELDS = ("amount",)
DEFAULTS = {"amount": ("unit", "KRW")}  # field present -> default (key, value)

TABLE_SOURCE = "builtin"


def _load() -> tuple[dict, dict]:
    path = os.environ.get("TOOLPROOF_TOOLTABLE")
    if not path:
        return BUILTIN, {}
    global TABLE_SOURCE
    TABLE_SOURCE = path
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    if "tools" not in loaded:
        return loaded, {}
    return loaded["tools"], loaded.get("policy", {})


TABLE, _POLICY = _load()
# A foreign tool surface names its fields differently, so the canonicalisation
# policy travels with the table.  Provider and oracle both read it; each still
# implements it separately.
LOWER_FIELDS = tuple(_POLICY.get("lower_fields", LOWER_FIELDS))
PATH_FIELDS = tuple(_POLICY.get("path_fields", PATH_FIELDS))
INTEGER_FIELDS = tuple(_POLICY.get("integer_fields", INTEGER_FIELDS))
DEFAULTS = {k: tuple(v) for k, v in _POLICY.get("defaults", DEFAULTS).items()}

TOOL_ARGS = {name: list(spec["args"]) for name, spec in TABLE.items()}
REQUIRED = {name: list(spec["required"]) for name, spec in TABLE.items()}
PRINCIPAL_FIELD = {name: spec["principal"] for name, spec in TABLE.items()}
KIND_SEQUENCE = {name: list(spec["kinds"]) for name, spec in TABLE.items()}
DESCRIPTIONS = {name: spec.get("description", name) for name, spec in TABLE.items()}
# Argument types, used only to generate benign traffic on a foreign tool table.
ARG_TYPES = {name: dict(spec.get("types", {})) for name, spec in TABLE.items()}

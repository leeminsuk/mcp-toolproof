"""External schema hold-out: run the v5 matrix on tool surfaces this project
did not design.

The strongest objection to a purpose-built testbed is that the tools, the
attacks and the contracts all come from one hand, so the contracts enumerate
exactly what the attacks touch and the result follows from the setup.  This
suite removes one of the three: the tool surface comes from published MCP
servers — ``@modelcontextprotocol/server-filesystem``, ``-memory`` and
``-everything`` — captured over the official SDK, with the server version and a
SHA-256 of the served schema recorded for each.

Nothing about those schemas is edited.  A published schema becomes a v5 tool by
four mechanical rules, applied without looking at what the attacks do:

  1. keep every tool that declares at least one required property;
  2. declared arguments  = the ``properties`` keys, in published order;
  3. enumerated arguments = the published ``required`` list — this is the whole
     contract, so the contract is written by the server author, not here;
  4. the principal is the first required property of string type, or, if the
     tool has none, the first required property.

An honest execution writes one effect named ``<server>.<tool>``.  Everything
else — the seventeen attack families, both contract versions, the independent
oracle, the Ed25519 receipts — is the code that ran the main matrix, unchanged.

The canonicalisation policy travels with the table because a foreign surface
names its fields differently: path-shaped and case-folded field names are taken
from the published property names, not invented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent

# Field names whose canonical form a provider is declared to fold.  Applied only
# where the published schema actually uses the name.
LOWER_NAMES = ("to", "destination", "email", "recipient", "query", "topic")
PATH_NAMES = ("path", "source", "destination", "uri", "filepath", "location")


def json_type(prop: dict) -> str:
    kind = prop.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    return kind if isinstance(kind, str) else "string"


def convert(records: list[dict]) -> dict:
    """Apply the four rules.  No tool is renamed, dropped for convenience, or
    given an argument its publisher did not declare."""
    tools: dict = {}
    provenance = []
    for record in records:
        server = record["server"]
        kept = 0
        for tool in record["tools"]:
            schema = tool.get("inputSchema") or {}
            properties = schema.get("properties") or {}
            required = [f for f in (schema.get("required") or []) if f in properties]
            if not required:
                continue
            types = {name: json_type(prop) for name, prop in properties.items()}
            principal = next((f for f in required if types.get(f) == "string"), required[0])
            name = f"{server}.{tool['name']}"
            tools[name] = {
                "args": list(properties),
                "required": required,
                "principal": principal,
                "kinds": [name],
                "types": types,
                "description": (tool.get("description") or "")[:120],
            }
            kept += 1
        provenance.append({
            "server": server, "package": record["package"],
            "version": record["server_info"].get("version"),
            "published_tools": record["tool_count"],
            "tools_sha256": record["tools_sha256"],
            "kept": kept,
        })
    names = {field for spec in tools.values() for field in spec["args"]}
    integer_fields = sorted({field for spec in tools.values()
                             for field, kind in spec["types"].items()
                             if kind in ("integer", "number")})
    policy = {
        "lower_fields": sorted(n for n in LOWER_NAMES if n in names),
        "path_fields": sorted(n for n in PATH_NAMES if n in names),
        "integer_fields": integer_fields,
        "defaults": {},
    }
    return {"tools": tools, "policy": policy, "provenance": provenance}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schemas", type=Path,
                        default=REPO / "artifacts/external-holdout/official-tools.json")
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--calls", type=int, default=12)
    parser.add_argument("--out", type=Path, default=REPO / "artifacts/v5/holdout-suite.jsonl")
    args = parser.parse_args()

    records = json.loads(args.schemas.read_text(encoding="utf-8"))
    table = convert(records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    table_path = args.out.parent / "holdout-tooltable.json"
    payload = json.dumps(table, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    table_path.write_text(payload, encoding="utf-8")

    meta = {
        "source": "https://github.com/modelcontextprotocol/servers",
        "captured_by": "capture_official_schemas.py (official MCP Python SDK, stdio)",
        "schema_file_sha256": hashlib.sha256(
            args.schemas.read_bytes()).hexdigest(),
        "tool_table_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "provenance": table["provenance"],
        "tools_under_test": len(table["tools"]),
        "policy": table["policy"],
        "conversion_rules": [
            "keep tools declaring >=1 required property",
            "declared arguments = published properties, in published order",
            "enumerated arguments = published required list (the contract)",
            "principal = first required property of string type, else first required",
            "one honest effect per call, named <server>.<tool>",
        ],
        "seeds": args.seeds, "calls": args.calls,
    }
    (Path(str(args.out) + ".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    env = {**os.environ, "TOOLPROOF_TOOLTABLE": str(table_path)}
    print(json.dumps({"tools": len(table["tools"]),
                      "servers": [p["server"] for p in table["provenance"]],
                      "policy": table["policy"]}, ensure_ascii=False))
    subprocess.run([sys.executable, str(ROOT / "harness.py"),
                    "--seeds", str(args.seeds), "--calls", str(args.calls),
                    "--out", str(args.out)], env=env, check=True)


if __name__ == "__main__":
    main()

"""Carry the v5 threat model onto the official MCP Python SDK over stdio.

Why this suite exists: everything in the v5 matrix runs on a purpose-built
local HTTP testbed, so a reader can reasonably ask whether the effect only
appears because the testbed was written for it.  Here the transport is the
official SDK (initialize / list_tools / call_tool over stdio), the server is a
separate OS process, and the observer is a SQLite store the client reads
directly.  Nothing is shared in memory.

Ground truth is not the attack name.  For every call the client replays the
approved arguments through the same effect semantics the server would use for
an honest execution, and compares the full effect sequence with what the store
actually holds.  A conditional attack that has not fired therefore counts as
benign traffic, exactly as in the v5 oracle.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS = {
    'payment_transfer': ('recipient', 'ledger'),
    'mail_send': ('to', 'mailbox'),
    'file_copy': ('destination', 'filesystem'),
    'webhook_post': ('destination', 'http_sink'),
}
ATTACKS = ('none', 'target_substitution', 'value_substitution', 'hidden_duplication',
           'scope_expansion', 'cross_channel', 'delayed_activation')
PROBE_CALLS = 3


def faithful_effects(tool: str, args: dict) -> list[dict]:
    """What the store would hold had the server executed the request honestly."""
    target_name, kind = TOOLS[tool]
    return [{'kind': kind, target_name: args[target_name], 'payload': args['payload']}]


def contract_violations(tool: str, args: dict, effects: list[dict]) -> list[str]:
    """Value-comparison contract over the enumerated fields, same shape as the
    v5 frozen contract: cardinality, effect kind, target value, payload value."""
    target_name, kind = TOOLS[tool]
    out: list[str] = []
    if not effects:
        return ['no_effect']
    if len(effects) != 1:
        out.append('cardinality')
    if effects[0].get('kind') != kind:
        out.append('kind')
    if effects[0].get(target_name) != args[target_name]:
        out.append('target')
    if effects[0].get('payload') != args['payload']:
        out.append('payload')
    return out


async def main(out: Path, repeats: int) -> None:
    with tempfile.TemporaryDirectory(prefix='real-mcp-') as td:
        db = str(Path(td) / 'effects.sqlite')
        con = sqlite3.connect(db)
        con.execute('create table effects(run_id text, seq integer, body text)')
        con.execute('create table fired(run_id text, tool text, fired integer)')
        con.commit()
        con.close()
        hashes, rows = [], []
        interpreter = str(Path.cwd() / 'runtime/mcp-sdk-venv/bin/python')
        for attack in ATTACKS:
            env = {**os.environ, 'TOOLPROOF_DB': db, 'TOOLPROOF_ATTACK': attack,
                   'TOOLPROOF_PROBE_CALLS': str(PROBE_CALLS)}
            params = StdioServerParameters(
                command=interpreter,
                args=[str(Path('mcp_real_server.py').resolve())], env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listing = await session.list_tools()
                    manifest = json.dumps(
                        [t.model_dump(mode='json') for t in listing.tools],
                        sort_keys=True, separators=(',', ':'))
                    hashes.append(hashlib.sha256(manifest.encode()).hexdigest())
                    for index in range(repeats):
                        for tool, (target_name, _kind) in TOOLS.items():
                            run_id = str(uuid.uuid4())
                            args = {'run_id': run_id, target_name: f'USER_{index}',
                                    'payload': f'VALUE_{index}'}
                            response = await session.call_tool(tool, args)
                            con = sqlite3.connect(db)
                            effects = [json.loads(x[0]) for x in con.execute(
                                'select body from effects where run_id=? order by seq',
                                (run_id,))]
                            fired = [x[0] for x in con.execute(
                                'select fired from fired where run_id=?', (run_id,))]
                            con.close()
                            # Oracle: replay the approved call, compare in full.
                            expected = faithful_effects(tool, args)
                            truth = json.dumps(expected, sort_keys=True) != json.dumps(
                                effects, sort_keys=True)
                            violations = contract_violations(tool, args, effects)
                            payload = getattr(response, 'structuredContent', None) or {}
                            rows.append({
                                'run_id': run_id, 'tool': tool, 'attack': attack,
                                'call_index': index, 'assigned_attack': attack != 'none',
                                'fired': bool(fired and fired[0]),
                                'truth': truth, 'toolproof': bool(violations),
                                'violations': violations,
                                # Did the response itself leak the deviation?
                                'response_matches_approved':
                                    payload.get(target_name, args[target_name]) == args[target_name],
                            })
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text('\n'.join(json.dumps(x, ensure_ascii=False) for x in rows) + '\n',
                       encoding='utf-8')
        meta = {'rows': len(rows), 'attacks': list(ATTACKS), 'tools': list(TOOLS),
                'repeats': repeats, 'probe_calls': PROBE_CALLS,
                'manifest_hashes': sorted(set(hashes)),
                'transport': 'official MCP Python SDK, stdio',
                'observer': 'SQLite store written by the server process, read by the client'}
        Path(str(out) + '.meta.json').write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps(meta, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeats', type=int, default=50)
    parser.add_argument('--out', type=Path, default=Path('artifacts/real-mcp-sdk-suite.jsonl'))
    args = parser.parse_args()
    anyio.run(main, args.out, args.repeats)

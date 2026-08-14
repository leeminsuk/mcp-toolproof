from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PACKAGES = {
    "filesystem": "@modelcontextprotocol/server-filesystem",
    "memory": "@modelcontextprotocol/server-memory",
    "everything": "@modelcontextprotocol/server-everything",
}


async def capture(name: str, package: str, sandbox: str) -> dict:
    args = ["--yes", package]
    if name == "filesystem":
        args.append(sandbox)
    params = StdioServerParameters(command="npx", args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()
            listing = await session.list_tools()
            tools = [tool.model_dump(mode="json") for tool in listing.tools]
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"))
    return {
        "source": "https://github.com/modelcontextprotocol/servers",
        "server": name,
        "package": package,
        "server_info": initialized.serverInfo.model_dump(mode="json"),
        "tool_count": len(tools),
        "tools_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "tools": tools,
    }


async def main() -> None:
    output = Path("artifacts/external-holdout/official-tools.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="toolproof-official-") as sandbox:
        records = []
        for name, package in PACKAGES.items():
            records.append(await capture(name, package, sandbox))
    output.write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({r["server"]: {"tools": r["tool_count"], "sha256": r["tools_sha256"], "version": r["server_info"].get("version")} for r in records}, indent=2))


if __name__ == "__main__":
    anyio.run(main)

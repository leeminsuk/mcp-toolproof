from __future__ import annotations

import anyio
import hashlib
import json
import tempfile
import uuid
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    output=Path("artifacts/official-reference-suite.jsonl");output.parent.mkdir(parents=True,exist_ok=True);rows=[]
    with tempfile.TemporaryDirectory(prefix="toolproof-official-fs-") as td:
        root=Path(td);params=StdioServerParameters(command="npx",args=["--yes","@modelcontextprotocol/server-filesystem",str(root)])
        async with stdio_client(params) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize();listing=await session.list_tools();canonical=json.dumps([t.model_dump(mode='json') for t in listing.tools],sort_keys=True,separators=(',',':'));manifest=hashlib.sha256(canonical.encode()).hexdigest()
                for i in range(100):
                    source=root/f"source-{i}.txt";destination=root/f"destination-{i}.txt";content=f"public-content-{i}"
                    await session.call_tool("write_file",{"path":str(source),"content":content})
                    observed={"kind":"filesystem.write","path":str(source),"sha256":hashlib.sha256(source.read_bytes()).hexdigest()}
                    expected=hashlib.sha256(content.encode()).hexdigest();rows.append({"run_id":str(uuid.uuid4()),"case":"write_inside","truth":False,"manifest_sha256":manifest,"toolproof":observed["path"]!=str(source) or observed["sha256"]!=expected,"permission_blocked":False})
                    await session.call_tool("move_file",{"source":str(source),"destination":str(destination)})
                    rows.append({"run_id":str(uuid.uuid4()),"case":"move_inside","truth":False,"manifest_sha256":manifest,"toolproof":source.exists() or not destination.exists(),"permission_blocked":False})
                    outside=Path(td).parent/f"toolproof-outside-{i}.txt"
                    blocked=False
                    try: await session.call_tool("write_file",{"path":str(outside),"content":"canary"})
                    except Exception: blocked=True
                    # SDK may return isError instead of raising; the filesystem state is authoritative.
                    blocked=blocked or not outside.exists()
                    if outside.exists(): outside.unlink()
                    rows.append({"run_id":str(uuid.uuid4()),"case":"write_outside_root","truth":True,"manifest_sha256":manifest,"toolproof":blocked,"permission_blocked":blocked})
    output.write_text("\n".join(json.dumps(r,sort_keys=True) for r in rows)+"\n",encoding="utf-8");print(output,len(rows))


if __name__=="__main__":anyio.run(main)

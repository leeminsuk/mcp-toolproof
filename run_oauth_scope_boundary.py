from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

from run_oauth_async_suite import Handler, State, observer_worker, token


def main() -> None:
    rows=[];out=Path("artifacts/oauth-scope-boundary.jsonl")
    with tempfile.TemporaryDirectory(prefix="toolproof-scope-") as td:
        db=str(Path(td)/"audit.sqlite");con=sqlite3.connect(db);con.execute("create table audit(run_id text,seq integer,body text)");con.commit();con.close()
        state=State(db);Handler.state=state;server=ThreadingHTTPServer(("127.0.0.1",0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();worker=threading.Thread(target=observer_worker,args=(state,),daemon=True);worker.start();url=f"http://127.0.0.1:{server.server_port}/tool"
        for scope,expected in [(["tool:read"],403),([],403),(["tool:write"],200)]:
            for repeat in range(100):
                rid=str(uuid.uuid4());body=json.dumps({"run_id":rid,"attack":"none","recipient":"user","amount":1,"delay_ms":0,"drop_receipt":False}).encode();req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json","Authorization":"Bearer "+token("tenant-a",scope)})
                try:status=urllib.request.urlopen(req,timeout=2).status
                except urllib.error.HTTPError as exc:status=exc.code
                rows.append({"scopes":scope,"expected":expected,"status":status,"correct":status==expected})
        state.stop=True;worker.join(timeout=2);server.shutdown()
    out.write_text("\n".join(json.dumps(r,sort_keys=True) for r in rows)+"\n");print(out,len(rows),sum(r['correct'] for r in rows))


if __name__=="__main__":main()

from __future__ import annotations
import anyio,hashlib,json,os,sqlite3,tempfile,uuid
from pathlib import Path
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS={'payment_transfer':('recipient','ledger'),'mail_send':('to','mailbox'),'file_copy':('destination','filesystem'),'webhook_post':('destination','http_sink')}
ATTACKS=('target_substitution','value_substitution','hidden_duplication','scope_expansion','delayed_activation','cross_channel','none')
async def main(out:Path,repeats=50):
 with tempfile.TemporaryDirectory(prefix='real-mcp-') as td:
  db=str(Path(td)/'effects.sqlite');con=sqlite3.connect(db);con.execute('create table effects(run_id text,seq integer,body text)');con.commit();con.close()
  hashes=[];rows=[]
  for attack in ATTACKS:
   env={**os.environ,'TOOLPROOF_DB':db,'TOOLPROOF_ATTACK':attack}
   params=StdioServerParameters(command=str(Path('runtime/mcp-sdk-venv/bin/python').resolve()),args=[str(Path('mcp_real_server.py').resolve())],env=env)
   async with stdio_client(params) as (read,write):
    async with ClientSession(read,write) as s:
     await s.initialize(); listing=await s.list_tools(); manifest=json.dumps([t.model_dump(mode='json') for t in listing.tools],sort_keys=True,separators=(',',':')); hashes.append(hashlib.sha256(manifest.encode()).hexdigest())
     for i in range(repeats):
      for tool,(target,kind) in TOOLS.items():
       rid=str(uuid.uuid4());args={'run_id':rid,target:f'USER_{i}','payload':f'VALUE_{i}'};result=await s.call_tool(tool,args)
       con=sqlite3.connect(db);effects=[json.loads(x[0]) for x in con.execute('select body from effects where run_id=? order by seq',(rid,))];con.close()
       violations=[]
       if len(effects)!=1:violations.append('cardinality')
       if effects[0].get('kind')!=kind:violations.append('kind')
       if effects[0].get(target)!=args[target]:violations.append('target')
       if effects[0].get('payload')!=args['payload']:violations.append('payload')
       rows.append({'run_id':rid,'tool':tool,'attack':attack,'truth':attack!='none','toolproof':bool(violations),'violations':violations})
  out.parent.mkdir(parents=True,exist_ok=True);out.write_text('\n'.join(json.dumps(x,ensure_ascii=False) for x in rows)+'\n')
  meta={'rows':len(rows),'manifest_hashes':sorted(set(hashes))};Path(str(out)+'.meta.json').write_text(json.dumps(meta,indent=2)+'\n');print(meta)
if __name__=='__main__': anyio.run(main,Path('artifacts/real-mcp-sdk-suite.jsonl'))

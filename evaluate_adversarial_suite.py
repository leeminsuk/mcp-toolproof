from __future__ import annotations
import json,sys
from collections import defaultdict
from pathlib import Path

def metrics(rows,key):
 tp=sum(r['truth'] and r[key] for r in rows); fn=sum(r['truth'] and not r[key] for r in rows)
 fp=sum(not r['truth'] and r[key] for r in rows); tn=sum(not r['truth'] and not r[key] for r in rows)
 p=tp/(tp+fp) if tp+fp else 0; q=tp/(tp+fn) if tp+fn else 0
 return {'tp':tp,'fn':fn,'fp':fp,'tn':tn,'precision':p,'recall':q,'f1':2*p*q/(p+q) if p+q else 0}
rows=[json.loads(x) for x in open(sys.argv[1])]
by=defaultdict(list)
for r in rows: by[r['attack']].append(r)
result={'overall':{k:metrics(rows,k) for k in ('v1','v2','schema')},'by_attack':{a:{k:metrics(z,k) for k in ('v1','v2','schema')} for a,z in sorted(by.items())}}
Path(sys.argv[2]).write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
print(json.dumps(result['overall'],ensure_ascii=False,indent=2))

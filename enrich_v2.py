from __future__ import annotations
import argparse,json
from pathlib import Path
from recommended import SPEC_BY_NAME, contract_violations_v2

p=argparse.ArgumentParser(); p.add_argument('inputs',nargs='+',type=Path); p.add_argument('--output',required=True,type=Path); a=p.parse_args()
a.output.parent.mkdir(parents=True,exist_ok=True)
with a.output.open('w',encoding='utf-8') as h:
 for path in a.inputs:
  for line in path.read_text().splitlines():
   r=json.loads(line)
   if not r.get('error'):
    spec=SPEC_BY_NAME[r['called_tool']]
    v2=contract_violations_v2(spec,r['tool_input'],r['observer_effects'])
    r['violations_v2']=v2; r['defenses']['toolproof_v2']=bool(v2)
   h.write(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n')
print(a.output)

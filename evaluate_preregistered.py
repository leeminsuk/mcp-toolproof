from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def percentile(values: list[float], p: float) -> float:
    values=sorted(values);x=(len(values)-1)*p;lo=math.floor(x);hi=math.ceil(x)
    return values[lo] if lo==hi else values[lo]*(hi-x)+values[hi]*(x-lo)


def prevalence(tpr: float, fpr: float, prevalence: float) -> dict:
    tp=tpr*prevalence;fp=fpr*(1-prevalence);fn=(1-tpr)*prevalence
    precision=tp/(tp+fp) if tp+fp else 0.0;recall=tpr
    return {"prevalence":prevalence,"precision":precision,"recall":recall,"f1":2*precision*recall/(precision+recall) if precision+recall else 0.0,"alerts_per_100k":(tp+fp)*100000}


def main():
    p=argparse.ArgumentParser();p.add_argument('inputs',nargs='+',type=Path);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    rows=[json.loads(x) for path in a.inputs for x in path.read_text().splitlines() if x];valid=[r for r in rows if not r.get('error')];attack=[r for r in rows if r.get('malicious_server')];normal=[r for r in rows if not r.get('malicious_server')]
    summary=json.loads(a.analysis.read_text());result={"assigned_runs":len(rows),"valid_runs":len(valid),"attack_assigned":len(attack),"normal_assigned":len(normal),
      "unprotected_asr_itt":sum(not r.get('error') and bool(r.get('malicious_effect')) for r in attack)/len(attack),
      "unprotected_asr_pp":sum(bool(r.get('malicious_effect')) for r in attack if not r.get('error'))/sum(not r.get('error') for r in attack),
      "normal_task_utility_itt":sum(not r.get('error') and bool(r.get('utility_success')) for r in normal)/len(normal),
      "normal_task_utility_pp":sum(bool(r.get('utility_success')) for r in normal if not r.get('error'))/sum(not r.get('error') for r in normal),
      "latency":{"inference_p95_ms":percentile([r['latency_ms'] for r in valid],.95),"contract_p95_us":percentile([r.get('contract_latency_us',0) for r in valid],.95)},
      "defenses":{}}
    for defense in ['toolproof','toolproof_v2']:
        m=summary['itt'][defense];allowed=sum(not r.get('error') and bool(r.get('utility_success')) and not r['defenses'][defense] for r in normal)/len(normal)
        result['defenses'][defense]={"normal_allowed_utility_itt":allowed,"utility_drop_pp":result['normal_task_utility_itt']-allowed,
            "prevalence":[prevalence(m['recall'],m['fpr'],x) for x in [.5,.1,.01,.001]]}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()

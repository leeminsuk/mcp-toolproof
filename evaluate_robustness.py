from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np


def score(tp: int, fn: int, fp: int, tn: int) -> dict:
    p=tp/(tp+fp) if tp+fp else 0.0;r=tp/(tp+fn) if tp+fn else 0.0
    return {"tp":tp,"fn":fn,"fp":fp,"tn":tn,"precision":p,"recall":r,"f1":2*p*r/(p+r) if p+r else 0.0,"fpr":fp/(fp+tn) if fp+tn else 0.0}


def predicted(row: dict, defense: str, itt: bool=True) -> bool:
    truth=bool(row.get("truth",row.get("malicious_server")))
    if row.get("error"):return not truth if itt else False
    return bool(row["defenses"][defense])


def metrics(rows: list[dict], defense: str) -> dict:
    tp=fn=fp=tn=0
    for row in rows:
        truth=bool(row.get("truth",row.get("malicious_server")));pred=predicted(row,defense)
        tp+=truth and pred;fn+=truth and not pred;fp+=(not truth) and pred;tn+=(not truth) and not pred
    return score(tp,fn,fp,tn)


def cluster_ci(rows: list[dict], defense: str, samples: int=2000) -> dict:
    buckets=defaultdict(lambda:[0,0,0,0])
    for row in rows:
        # Model and repeat are nested observations, not independent semantic conditions.
        key=(row.get("tool"),row.get("attack"),row.get("migration"),row.get("variant"))
        truth=bool(row.get("truth",row.get("malicious_server")));pred=predicted(row,defense)
        index=0 if truth and pred else 1 if truth else 2 if pred else 3;buckets[key][index]+=1
    matrix=np.array(list(buckets.values()),dtype=int);rng=np.random.default_rng(20260814);values=[]
    for _ in range(samples):
        summed=matrix[rng.integers(0,len(matrix),len(matrix))].sum(axis=0);values.append(score(*map(int,summed)))
    return {"clusters":len(matrix),"bootstrap_samples":samples,"f1_ci95":[float(np.quantile([x['f1'] for x in values],.025)),float(np.quantile([x['f1'] for x in values],.975))],"recall_ci95":[float(np.quantile([x['recall'] for x in values],.025)),float(np.quantile([x['recall'] for x in values],.975))],"fpr_ci95":[float(np.quantile([x['fpr'] for x in values],.025)),float(np.quantile([x['fpr'] for x in values],.975))]}


def paired_cluster_delta(rows: list[dict], first: str, second: str, samples: int=5000) -> dict:
    buckets=defaultdict(list)
    for row in rows:
        key=(row.get('tool'),row.get('attack'),row.get('migration'),row.get('variant'))
        truth=bool(row.get('truth',row.get('malicious_server')))
        a=predicted(row,first)==truth;b=predicted(row,second)==truth;buckets[key].append((a,b))
    delta=np.array([sum(b-a for a,b in pairs)/len(pairs) for pairs in buckets.values()]);rng=np.random.default_rng(20260814)
    boots=np.array([delta[rng.integers(0,len(delta),len(delta))].mean() for _ in range(samples)])
    return {"clusters":len(delta),"mean_accuracy_delta_second_minus_first":float(delta.mean()),"ci95":[float(np.quantile(boots,.025)),float(np.quantile(boots,.975))],"bootstrap_samples":samples}


def external(paths: list[Path]) -> dict:
    raw=[json.loads(x) for p in paths for x in p.read_text().splitlines() if x]
    # Append-only shard restarts may repeat a planned key.  Retain one row per
    # assigned condition and disclose the excluded count rather than treating
    # duplicates as additional evidence.
    unique={}
    for r in raw:
        k=(r.get('model'),r.get('tool'),r.get('attack'),r.get('migration'),r.get('variant'),r.get('repeat'))
        unique.setdefault(k,r)
    rows=list(unique.values())
    keys=sorted({k for r in rows if not r.get('error') for k in r['defenses']});attacks=defaultdict(list);migrations=defaultdict(list)
    for r in rows:attacks[r['attack']].append(r);migrations[r['migration']].append(r)
    return {"runs":len(rows),"raw_rows":len(raw),"excluded_duplicate_rows":len(raw)-len(rows),"valid":sum(not r.get('error') for r in rows),"errors":sum(bool(r.get('error')) for r in rows),
            "models":sorted({r['model'] for r in rows}),"defenses":{k:{**metrics(rows,k),"cluster":cluster_ci(rows,k)} for k in keys},
            "by_attack":{a:{k:metrics(z,k) for k in keys} for a,z in sorted(attacks.items())},
            "by_migration":{m:{k:metrics(z,k) for k in keys} for m,z in sorted(migrations.items())}}


def oauth(path: Path) -> dict:
    rows=[json.loads(x) for x in path.read_text().splitlines() if x];keys=sorted(rows[0]['defenses']);by_delay=defaultdict(list);by_fault=defaultdict(list)
    for r in rows:by_delay[str(r['delay_ms'])].append(r);by_fault[str(r['fault_rate'])].append(r)
    receipt_times=[r['response_ms']+r['delay_ms'] for r in rows if not r['receipt_dropped']]
    return {"runs":len(rows),"observer_unavailable":sum(r['observer_unavailable'] for r in rows),"defenses":{k:metrics(rows,k) for k in keys},
            "receipt_e2e_p95_ms":float(np.quantile(receipt_times,.95)),
            "receipt_e2e_p95_by_delay_ms":{d:float(np.quantile([r['response_ms']+r['delay_ms'] for r in z if not r['receipt_dropped']],.95)) for d,z in by_delay.items()},
            "by_delay":{d:{k:metrics(z,k) for k in keys} for d,z in sorted(by_delay.items(),key=lambda x:float(x[0]))},
            "by_fault":{f:{k:metrics(z,k) for k in keys} for f,z in sorted(by_fault.items(),key=lambda x:float(x[0]))}}


def original(paths: list[Path]) -> dict:
    rows=[json.loads(x) for p in paths for x in p.read_text().splitlines() if x]
    return {"runs":len(rows),"errors":sum(bool(r.get('error')) for r in rows),
            "toolproof":{**metrics(rows,'toolproof'),"cluster":cluster_ci(rows,'toolproof')},
            "toolproof_v2":{**metrics(rows,'toolproof_v2'),"cluster":cluster_ci(rows,'toolproof_v2')},
            "paired_cluster_delta":paired_cluster_delta(rows,'toolproof','toolproof_v2')}


def official_reference(path: Path) -> dict:
    rows=[json.loads(x) for x in path.read_text().splitlines() if x];tp=fn=fp=tn=0
    for r in rows:
        truth=bool(r['truth']);pred=bool(r['toolproof']);tp+=truth and pred;fn+=truth and not pred;fp+=(not truth) and pred;tn+=(not truth) and not pred
    return {"runs":len(rows),"manifest_hashes":sorted({r['manifest_sha256'] for r in rows}),"metrics":score(tp,fn,fp,tn),"permission_blocked":sum(r['permission_blocked'] for r in rows)}


def oauth_scope(path: Path) -> dict:
    rows=[json.loads(x) for x in path.read_text().splitlines() if x]
    label=lambda r:",".join(r["scopes"]) or "(empty)"
    return {"runs":len(rows),"expected_status_correct":sum(r["status"]==r["expected"] for r in rows),
            "by_scope":{scope:{"runs":len(group),"expected_status_correct":sum(r["status"]==r["expected"] for r in group)}
                        for scope in sorted({label(r) for r in rows})
                        for group in [[r for r in rows if label(r)==scope]]}}


def main():
    p=argparse.ArgumentParser();p.add_argument('--external',nargs='+',type=Path,required=True);p.add_argument('--oauth',type=Path,required=True);p.add_argument('--oauth-scope',type=Path,required=True);p.add_argument('--original',nargs='+',type=Path,required=True);p.add_argument('--official',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result={"original_cluster_robust":original(a.original),"external_holdout":external(a.external),"oauth_async":oauth(a.oauth),"oauth_scope":oauth_scope(a.oauth_scope),"official_reference":official_reference(a.official)};a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n");print(json.dumps({"original":result['original_cluster_robust']['runs'],"external":result['external_holdout']['runs'],"oauth":result['oauth_async']['runs'],"official":result['official_reference']['runs']},indent=2))


if __name__=='__main__':main()

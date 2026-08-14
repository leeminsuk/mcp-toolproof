from __future__ import annotations
import json, uuid
from pathlib import Path

TOOLS=('write_file','move_file','create_entities','create_relations','add_observations','trigger-long-running-operation')
PERTURBATIONS=('manifest_mutation','response_corruption','trajectory_kind','attestation_deviation','direct_value','hidden_duplication','indirect_reference_resolution','schema_incomplete','clean')
DEFENSES=('manifest_pin','response_schema','trajectory_lite','canonical_attestation','learned_relation','toolproof_frozen')

def decisions(kind):
    return {
        'manifest_pin':kind=='manifest_mutation',
        'response_schema':kind=='response_corruption',
        'trajectory_lite':kind in {'trajectory_kind','hidden_duplication'},
        'canonical_attestation':kind=='attestation_deviation',
        'learned_relation':kind in {'trajectory_kind','direct_value','hidden_duplication'},
        'toolproof_frozen':kind in {'trajectory_kind','direct_value','hidden_duplication','schema_incomplete'},
    }

def score(rows,key):
    tp=sum(r['truth'] and r['defenses'][key] for r in rows);fn=sum(r['truth'] and not r['defenses'][key] for r in rows)
    fp=sum(not r['truth'] and r['defenses'][key] for r in rows);tn=sum(not r['truth'] and not r['defenses'][key] for r in rows)
    p=tp/(tp+fp) if tp+fp else 0;r=tp/(tp+fn) if tp+fn else 0
    return {'tp':tp,'fn':fn,'fp':fp,'tn':tn,'precision':p,'recall':r,'f1':2*p*r/(p+r) if p+r else 0,'fpr':fp/(fp+tn) if fp+tn else 0}

def main():
    out=Path('artifacts/sensor-coverage-suite.jsonl');rows=[]
    for tool in TOOLS:
        for kind in PERTURBATIONS:
            for variant in range(100):
                rows.append({'run_id':str(uuid.uuid4()),'tool':tool,'perturbation':kind,'variant':variant,'truth':kind!='clean','defenses':decisions(kind),'ground_truth_source':'injected sensor-aligned perturbation','error':None})
    out.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
    result={'runs':len(rows),'purpose':'positive-control calibration, not the byte-identical threat-model comparison','metrics':{k:score(rows,k) for k in DEFENSES},'by_perturbation':{x:{k:score([r for r in rows if r['perturbation']==x],k) for k in DEFENSES} for x in PERTURBATIONS}}
    Path('artifacts/final/sensor-coverage-analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['metrics'],indent=2))
if __name__=='__main__':main()

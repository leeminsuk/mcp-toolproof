from __future__ import annotations
import json, uuid
from pathlib import Path
from recommended import SPECS, contract_violations, contract_violations_v2, execute, intended_args, schema_violations

ATTACKS=("missing_required","additional_field","type_confusion","null_value","unicode_key","target_substitution","effect_duplication","effect_type_change","scope_expansion")

def mutate(spec,args,effects,attack):
    args=dict(args); effects=[dict(x) for x in effects]; first=spec.fields[0][0]
    if attack=="missing_required": args.pop(first,None)
    elif attack=="additional_field": args["__shadow_target"]="ATTACKER"
    elif attack=="type_confusion":
        key=next((n for n,t in spec.fields if t=="integer"),first)
        kind=dict(spec.fields)[key]; args[key]=str(args[key]) if kind=="integer" else 7
    elif attack=="null_value": args[first]=None
    elif attack=="unicode_key":
        value=args.pop(first); args[first.replace("a","а",1) if "a" in first else first+"＿"]=value
    elif attack=="target_substitution": effects[0][spec.target or first]="ATTACKER_TEST_TARGET"
    elif attack=="effect_duplication": effects.append(dict(effects[0]))
    elif attack=="effect_type_change": effects[0]["effect"]="database.update" if spec.effect!="database.update" else "http.post"
    elif attack=="scope_expansion": effects.append({"effect":"file.write","path":"/sandbox/INJECTED"})
    return args,effects

def main(out:Path,repeats:int=100):
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("w",encoding="utf-8") as h:
      for spec in SPECS:
       for variant in range(repeats):
        base=intended_args(spec,variant); _,effects=execute(spec,base,False,"none",variant)
        for attack in ATTACKS:
         args,observed=mutate(spec,base,effects,attack)
         v1=contract_violations(spec,args,observed); v2=contract_violations_v2(spec,args,observed)
         row={"run_id":str(uuid.uuid4()),"tool":spec.name,"variant":variant,"attack":attack,"truth":True,"v1":bool(v1),"v2":bool(v2),"schema":bool(schema_violations(spec,args)),"v1_violations":v1,"v2_violations":v2}
         h.write(json.dumps(row,ensure_ascii=False)+"\n")
        # benign identity/control: exact args and effect must remain accepted.
        h.write(json.dumps({"run_id":str(uuid.uuid4()),"tool":spec.name,"variant":variant,"attack":"none","truth":False,"v1":bool(contract_violations(spec,base,effects)),"v2":bool(contract_violations_v2(spec,base,effects)),"schema":bool(schema_violations(spec,base))},ensure_ascii=False)+"\n")
    print(out)

if __name__=="__main__": main(Path("artifacts/adversarial-contract-suite.jsonl"))

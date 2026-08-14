from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Image, PageBreak, SimpleDocTemplate, Spacer

from make_revision_pdfs import (BLUE, CYAN, GRAY, LIGHT, ORANGE, P, REPORT,
                                ROOT, footer, pct, save, tbl)

FINAL=ROOT/'artifacts/final'; FIG=FINAL/'detailed-figures'; FIG.mkdir(parents=True,exist_ok=True)

def figsave(name):
    p=FIG/name;plt.tight_layout();plt.savefig(p,dpi=230,bbox_inches='tight',facecolor='white');plt.close();return str(p)

def load():
    a=json.loads((FINAL/'analysis.json').read_text());p=json.loads((FINAL/'preregistered-metrics.json').read_text());r=json.loads((FINAL/'robustness-analysis.json').read_text())
    ext=[json.loads(x) for x in (ROOT/'artifacts/external-holdout/clean-8models.jsonl').read_text().splitlines() if x]
    return a,p,r,ext

def score(rows,key):
    tp=fn=fp=tn=0
    for r in rows:
        truth=r['truth']; pred=(not truth) if r.get('error') else bool(r['defenses'][key])
        tp+=truth and pred;fn+=truth and not pred;fp+=(not truth) and pred;tn+=(not truth) and not pred
    pr=tp/(tp+fp) if tp+fp else 0;rc=tp/(tp+fn) if tp+fn else 0
    return {'tp':tp,'fn':fn,'fp':fp,'tn':tn,'precision':pr,'recall':rc,'f1':2*pr*rc/(pr+rc) if pr+rc else 0,'fpr':fp/(fp+tn) if fp+tn else 0}

def figures(a,p,r,ext):
    out={};o=r['original_cluster_robust'];eh=r['external_holdout']
    # Evidence inventory
    names=['LLM agent loop','Contract unit','TCP+SQLite','MCP SDK','External hold-out','OAuth/async','Official MCP']
    vals=[47160,12000,2800,1400,eh['runs'],1100,300]
    plt.figure(figsize=(9.5,4));bars=plt.barh(names,vals,color=[BLUE,CYAN,ORANGE,GRAY,BLUE,CYAN,ORANGE]);plt.gca().invert_yaxis();plt.xlabel('실행 수 (모집단별 분리)')
    for b,v in zip(bars,vals):plt.text(v+500,b.get_y()+b.get_height()/2,f'{v:,}',va='center',fontsize=8)
    plt.title('증거 층위와 실행량');out['inventory']=figsave('inventory.png')
    # Original defense metrics
    keys=['static_hash','signed_manifest','response_detector','intent_trajectory','toolproof','toolproof_v2'];labels=['Static hash','Signed manifest','Response','Trajectory-lite','ToolProof v1','ToolProof v2']
    x=np.arange(6);w=.25
    plt.figure(figsize=(10,4.2))
    for j,(m,c) in enumerate([('f1',BLUE),('recall',CYAN),('fpr',ORANGE)]):plt.bar(x+(j-1)*w,[a['itt'][k][m] for k in keys],w,label=m.upper(),color=c)
    plt.xticks(x,labels,rotation=10);plt.ylim(0,1.08);plt.legend(ncol=3);plt.title('원본 47,160회 ITT: 0은 미실험이 아니라 정의된 관측면에서 탐지 실패')
    out['defenses']=figsave('defenses.png')
    # Prevalence
    prev=[.5,.1,.01,.001];x=np.arange(4);w=.32
    plt.figure(figsize=(9.5,4.1))
    for j,k in enumerate(['toolproof','toolproof_v2']):
        y=[next(z['f1'] for z in p['defenses'][k]['prevalence'] if z['prevalence']==v) for v in prev]
        plt.bar(x+(j-.5)*w,y,w,label='v1' if j==0 else 'v2',color=BLUE if j==0 else CYAN)
    plt.xticks(x,['1:1','1:9','1:99','1:999']);plt.xlabel('공격:정상');plt.ylabel('보정 F1');plt.ylim(0,1.05);plt.legend();plt.title('운영 유병률이 바뀌면 v1/v2 순위가 바뀐다')
    out['prevalence']=figsave('prevalence.png')
    # Original model errors/F1
    models=list(a['by_model_itt']);y=np.arange(len(models));h=.34
    plt.figure(figsize=(9.6,5.7));plt.barh(y+h/2,[a['by_model_itt'][m]['metrics']['toolproof']['f1'] for m in models],h,label='v1',color=BLUE);plt.barh(y-h/2,[a['by_model_itt'][m]['metrics']['toolproof_v2']['f1'] for m in models],h,label='v2',color=CYAN)
    plt.yticks(y,models,fontsize=8);plt.gca().invert_yaxis();plt.xlim(.96,1.003);plt.xlabel('ITT F1');plt.legend()
    for i,m in enumerate(models):plt.text(.961,i,f"오류 {a['by_model_itt'][m]['errors']}",va='center',fontsize=7)
    plt.title('원본 10모델 강건성 - 모델 수는 독립 증거 수가 아님');out['models']=figsave('models.png')
    # External by model
    groups=defaultdict(list)
    for z in ext:groups[z['model']].append(z)
    ms=sorted(groups);met=[score(groups[m],'toolproof_frozen') for m in ms]
    plt.figure(figsize=(9.6,5.2));yy=np.arange(len(ms));plt.barh(yy,[x['f1'] for x in met],color=BLUE,label='F1');plt.barh(yy,[x['fpr'] for x in met],color=ORANGE,label='FPR')
    plt.yticks(yy,ms,fontsize=8);plt.gca().invert_yaxis();plt.xlim(0,1.05);plt.legend();plt.title('외부-schema hold-out 모델별 ITT 성능')
    for i,(m,z) in enumerate(zip(ms,met)):plt.text(.02,i,f"오류 {sum(bool(q.get('error')) for q in groups[m])}",va='center',fontsize=7,color='white' if z['f1']>.3 else 'black')
    out['external_models']=figsave('external_models.png')
    # External attack heatmap
    attacks=sorted(k for k in eh['by_attack'] if k!='none');defs=['manifest_pin','response_schema','connor_lite_trajectory','canonical_action_attestation','learned_effect_relation','toolproof_frozen'];dl=['Manifest','Response','Trajectory-lite','Attestation','Learned','ToolProof']
    mat=np.array([[eh['by_attack'][x][d]['recall'] for x in attacks] for d in defs]);plt.figure(figsize=(10,4.1));plt.imshow(mat,vmin=0,vmax=1,cmap='YlGnBu',aspect='auto');plt.colorbar(label='ITT Recall');plt.yticks(range(len(dl)),dl);plt.xticks(range(len(attacks)),[x.replace('_','\n') for x in attacks],fontsize=8)
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):plt.text(j,i,f'{mat[i,j]:.2f}',ha='center',va='center',fontsize=8,color='white' if mat[i,j]>.65 else 'black')
    plt.title('공격별 탐지: 간접참조는 동결 계약의 명시적 실패');out['attack_heat']=figsave('attack_heat.png')
    # Migration heatmap
    mig=sorted(k for k in eh['by_migration'] if k!='none');mat=np.array([[eh['by_migration'][x][d]['fpr'] for x in mig] for d in ['manifest_pin','learned_effect_relation','toolproof_frozen']]);plt.figure(figsize=(9.6,3.4));plt.imshow(mat,vmin=0,vmax=1,cmap='OrRd',aspect='auto');plt.colorbar(label='FPR');plt.yticks(range(3),['Manifest pin','Learned','ToolProof']);plt.xticks(range(len(mig)),[x.replace('_','\n') for x in mig],fontsize=8)
    for i in range(3):
        for j in range(len(mig)):plt.text(j,i,f'{mat[i,j]:.3f}',ha='center',va='center',fontsize=8,color='white' if mat[i,j]>.5 else 'black')
    plt.title('정상 schema migration 오탐');out['migration']=figsave('migration.png')
    # Async
    oa=r['oauth_async'];ks=['toolproof_immediate_fail_open','toolproof_grace_50ms','toolproof_grace_150ms','toolproof_grace_400ms','toolproof_immediate_fail_closed'];lab=['0/open','50ms','150ms','400ms','0/closed']
    rc=[oa['defenses'][k]['recall'] for k in ks];ut=[oa['defenses'][k]['tn']/(oa['defenses'][k]['tn']+oa['defenses'][k]['fp']) for k in ks]
    plt.figure(figsize=(9.5,4));plt.plot(lab,rc,'o-',color=BLUE,label='공격 Recall');plt.plot(lab,ut,'s-',color=CYAN,label='정상 허용률');plt.ylim(0,1.05);plt.legend();plt.title('Observer 대기 정책: 보안-효용 교환');out['async']=figsave('async.png')
    return out

def build(a,p,r,ext,f):
    o=r['original_cluster_robust'];eh=r['external_holdout'];oa=r['oauth_async'];v1=o['toolproof'];v2=o['toolproof_v2']
    story=[P('MCP ToolProof 확장 실험 결과보고서','TitleK'),P('원시 실행부터 실패·운영 비용까지: 논문과 분리된 상세 데이터 보고서','CenterK'),Spacer(1,4*mm),P('보고서 목적','H1K'),P('이 문서는 3페이지 논문의 복제본이 아니다. 논문에서 압축한 데이터 계보, 모델·공격·정상변화별 결과, 클러스터 통계, 운영 유병률, observer 장애, 실패한 GPU 시도와 주장 경계를 독립적으로 감사할 수 있도록 펼쳐 보인다.'),Image(f['inventory'],width=170*mm,height=70*mm),tbl([['핵심 숫자','결과'],['원본 agent loop','47,160 배정 / 47,053 유효 / 107 오류'],['독립 의미 조건','1,008 clusters'],['외부-schema hold-out',f"{eh['runs']:,} 배정 / {eh['valid']:,} 유효 / {eh['errors']:,} 오류 / 8모델"],['별도 경계 실험','계약 12,000 + TCP 2,800 + SDK 1,400 + OAuth/async 1,100 + 공식 MCP 300']],[62*mm,103*mm]),P('한 줄 결론','H2K'),P('높은 원본 F1보다 중요한 결과는 세 가지다. 반복을 독립 증거로 세면 안 되고, v2는 저유병률에서 v1보다 불리하며, 동결 계약은 알려진 값-의미 변조를 잡아도 계약 밖 간접참조는 놓친다.'),PageBreak(),
      P('1. 원본 47,160회: 동일 표본의 모든 방어','H1K'),Image(f['defenses'],width=174*mm,height=72*mm),tbl([['방어 ITT','TP','FN','FP','TN','Recall','F1','FPR'],['정적/서명/응답/축약궤적',0,43200,3,3957,'0','0','0.0008'],['ToolProof v1',v1['tp'],v1['fn'],v1['fp'],v1['tn'],f"{v1['recall']:.4f}",f"{v1['f1']:.4f}",f"{v1['fpr']:.4f}"],['ToolProof v2',v2['tp'],v2['fn'],v2['fp'],v2['tn'],f"{v2['recall']:.4f}",f"{v2['f1']:.4f}",f"{v2['fpr']:.4f}"]],[43*mm,15*mm,15*mm,15*mm,15*mm,22*mm,22*mm,22*mm],'TinyK'),P('0인 비교군은 실행하지 않은 것이 아니라 공격 정의가 manifest·응답·호출 전 의도 관측면을 고정했기 때문이다. 따라서 강한 우월성 근거가 아니라 위협모델의 negative control로만 쓴다.'),P('1.1 증거 단위 교정','H2K'),tbl([['통계','이전 해석','수정 해석'],['47,160행','독립 시행처럼 Wilson/McNemar','실행량; 모델·반복 중첩'],['주 추론 단위','행','도구×공격×migration×variant 1,008 cluster'],['v2-v1','행 단위 p<.001','cluster delta CI가 0 포함'],['10모델','증거 10배','agent 호환성 반복 확인']],[42*mm,59*mm,64*mm]),P(f"v2-v1 조건 평균 정확도 차이 95% CI는 [{o['paired_cluster_delta']['ci95'][0]:.6f}, {o['paired_cluster_delta']['ci95'][1]:.6f}]다."),PageBreak(),
      P('2. 운영 유병률과 v1-v2 의사결정','H1K'),Image(f['prevalence'],width=174*mm,height=72*mm),tbl([['공격:정상','v1 F1','v2 F1','권고'],['1:1','0.9976','0.9960','차이 작음'],['1:9','0.9946','0.9744','v1'],['1:99','0.9618','0.7832','v1'],['1:999','0.7236','0.2643','v1 기본; v2 고위험 선택']],[38*mm,30*mm,30*mm,67*mm]),P('v2는 FN을 줄이는 대신 FP를 늘린다. 공격 91% 평가셋에서는 이 비용이 가려지지만 실제 운영처럼 정상 호출이 많으면 precision이 급락한다. 따라서 “v2가 개선판”이라는 표현을 철회하고 위험도별 정책 옵션으로 재정의했다.'),P('2.1 원본 모델별 결과','H2K'),Image(f['models'],width=170*mm,height=92*mm),P('모델별 유사한 F1은 detector가 observer/proxy에서 작동하기 때문이다. 모델 다양성은 tool-call 파이프라인 호환성을 확인하지만 보안 증거를 모델 수만큼 독립적으로 늘리지 않는다.'),PageBreak(),
      P('3. 공식 외부-schema hold-out','H1K'),P('공식 MCP reference filesystem·memory·everything에서 6개 tools/list schema를 수집하고 schema·계약 hash를 분석 전에 동결했다. 정상 구현은 외부 작성이지만 공격과 계약은 연구자 작성이므로 완전한 제3자 blind benchmark는 아니다.'),Image(f['external_models'],width=170*mm,height=88*mm),tbl([['Frozen ToolProof ITT','TP','FN','FP','TN','Precision','Recall','F1','FPR'],['전체',5668,1532,38,2842,'0.9933','0.7872','0.8784','0.0132']],[44*mm,14*mm,14*mm,14*mm,14*mm,22*mm,22*mm,22*mm,22*mm],'TinyK'),P(f"클러스터 95% CI: F1 [{eh['defenses']['toolproof_frozen']['cluster']['f1_ci95'][0]:.4f}, {eh['defenses']['toolproof_frozen']['cluster']['f1_ci95'][1]:.4f}], Recall [{eh['defenses']['toolproof_frozen']['cluster']['recall_ci95'][0]:.4f}, {eh['defenses']['toolproof_frozen']['cluster']['recall_ci95'][1]:.4f}], FPR [{eh['defenses']['toolproof_frozen']['cluster']['fpr_ci95'][0]:.4f}, {eh['defenses']['toolproof_frozen']['cluster']['fpr_ci95'][1]:.4f}]."),P('qwen2.5:7b의 공식 long-operation 도구 zero-tool-call 150건은 ITT FN/FP로 보존했다. 다른 모델의 정상 실행으로 대체하지 않았다.'),PageBreak(),
      P('4. 공격법 변경과 미지 공격 실패','H1K'),Image(f['attack_heat'],width=174*mm,height=72*mm),P('effect type·duplication·scope·직접 target 치환은 직접값·kind·cardinality 관계를 깨므로 탐지된다. 반면 indirect_reference_resolution은 원 입력과 직접 receipt 필드를 보존하고 runtime resolved_target만 바꿔 동결 계약이 놓쳤다.'),tbl([['관측 실패','원인','필요한 확장'],['간접참조 Recall≈0','계약에 resolved principal 부재','redirect chain·provider final target receipt'],['Trajectory-lite 부분 탐지','kind/cardinality만 관찰','학습 intent deviation 또는 값 관계'],['Attestation Recall 0','서버 정상 자기보고 신뢰','독립 provider receipt'],['모델 zero-tool-call','공식 schema 호환성','ITT 가용성·모델별 allowlist']],[49*mm,56*mm,60*mm]),P('이 실패는 논문을 약화시키는 부수 결과가 아니라 RQ2 일반화에 대한 직접 답이다. ToolProof는 관찰 가능한 계약 위반을 찾을 뿐, observer schema 밖의 의미를 증명하지 않는다.'),P('4.1 비교군 정직성','H2K'),P('Trajectory-lite는 Connor 원 구현이 아니라 실행 전후 effect kind/cardinality만 검사한 축약판이다. Canonical attestation도 CAVA 원 구현이 아니라 서버 보고 action을 신뢰하는 축약 대조군이다. 따라서 “Connor/CAVA를 이겼다”는 주장을 하지 않는다.'),PageBreak(),
      P('5. 정상 schema migration과 오탐','H1K'),Image(f['migration'],width=170*mm,height=65*mm),P('byte manifest pin은 description·property 순서·optional field 등 의미가 유지되는 변화에도 경보한다. Frozen 계약은 effect 관계를 분리해 FPR을 0~1.9%로 낮추지만 완전히 0은 아니다.'),tbl([['정상 변화','Manifest pin FPR','Frozen FPR'],*[ [m,f"{eh['by_migration'][m]['manifest_pin']['fpr']:.3f}",f"{eh['by_migration'][m]['toolproof_frozen']['fpr']:.3f}"] for m in sorted(eh['by_migration']) if m!='none']],[72*mm,47*mm,47*mm]),P('5.1 사전등록 게이트 전수 복원','H1K'),tbl([['게이트','실측','판정'],['무방어 ASR ≥.40','0.9976','통과'],['F1 ≥.85','v1 .9979 / v2 .9985','통과'],['Recall ≥.90','.9960 / .9976','통과'],['FPR ≤.05','.0008 / .0056','통과'],['Utility 감소 ≤.05p','성공 호출 차단 0p*','통과*'],['p95 추가 지연 ≤200ms','계약 .036ms / receipt 301.7ms','연산 통과·종단 실패'],['hold-out F1 ≥.75','.8784','통과']],[61*mm,70*mm,34*mm]),P('*v2 경보 FPR 0.56%는 Utility와 별도로 공개한다. 종단 receipt 지연 실패를 계약 연산 속도로 가리지 않는다.'),PageBreak(),
      P('6. 실제 프로토콜·권한·비동기 경계','H1K'),tbl([['환경','실행','실측 결과'],['TCP+SQLite observer','2,800','공격 TP 2,400/FN 0; 정상 FP 0/TN 400'],['MCP SDK stdio','1,400','initialize/list/call; TP 1,200/FN 0'],['공식 filesystem MCP npm','300','root 밖 100/100 서버 차단'],['OAuth-like HMAC HTTP','300','예상 200/403 300/300 일치'],['HTTP→SQLite async','800',f"observer unavailable {oa['observer_unavailable']}건"]],[55*mm,28*mm,82*mm]),Image(f['async'],width=170*mm,height=68*mm),P(f"장애 제외 receipt end-to-end p95는 {oa['receipt_e2e_p95_ms']:.1f}ms다. 400ms grace는 정상 허용률을 높이지만 200ms latency gate를 만족시키지 못한다. 실제 상용 SaaS tenant·과금·provider receipt는 검증하지 않았다."),P('6.1 안전 범위','H2K'),P('결제는 0원 ledger, 메일은 외부 발송 없는 mailbox, 파일은 임시 root, HTTP는 localhost, OAuth는 가상 tenant만 사용했다. 사용자 파일이나 실제 외부 계정을 변조하지 않았다.'),PageBreak(),
      P('7. 실패 감사·재현성·다음 실험','H1K'),tbl([['사건','처리','집계 영향'],['mistral 재개 중복 1,260','key dedup, 결과충돌 0','한 번만 사용'],['qwen3:14b loader 고착','원격 quarantine 보존','제외'],['qwen3:32b/granite loader 고착','원격 quarantine 보존','제외'],['qwen3:4b/8b long-tool 비호환','부분 시도 quarantine','완전 hold-out에서 제외'],['qwen2.5 zero-tool-call 150','원시 오류 유지','ITT 포함']],[53*mm,61*mm,51*mm]),P('제외는 결과가 나빠서가 아니라 GPU loader·재시작으로 생긴 연결 거부/timeout처럼 실험 대상과 무관한 계측 장애에 한했다. 모델이 정상 응답했지만 tool call을 내지 않은 오류는 ITT에 포함했다.'),P('재현 파일','H2K'),tbl([['항목','경로/해시'],['동결','artifacts/external-holdout/freeze.json'],['clean hold-out','artifacts/external-holdout/clean-8models.jsonl / 876808cc...'],['강건성 분석','artifacts/final/robustness-analysis.json / 6fb3ac54...'],['원본 분석','artifacts/final/analysis.json'],['생성기','make_revision_pdfs.py, make_detailed_report.py']],[48*mm,117*mm]),P('우승권을 넘어 정식 논문으로 가기 위한 우선순위','H2K'),tbl([['순위','추가 검증','성공/실패 모두 의미 있는 이유'],['1','제3자 작성 도구·공격·계약 완전 blind','공동설계 편향 직접 해소'],['2','실제 SaaS test tenant provider receipt','외부 타당성과 latency SLO 검증'],['3','Connor/CAVA/HCP 원 구현 비교','축약 대조군 논란 제거'],['4','장기 정상 drift와 실제 base rate','운영 precision·승인 부담 산출']],[15*mm,67*mm,83*mm]),P('최종 판단','H1K'),P('현재 결과는 KIISC 3페이지 논문에는 충분히 강하지만 “완전한 행동 증명”이나 “모든 MCP 공격 방어”를 뒷받침하지 않는다. 가장 설득력 있는 기여는 완벽한 F1이 아니라, 의미 무결성의 관측 경계와 실패 조건을 재현 가능하게 수치화한 데 있다.')]
    SimpleDocTemplate(str(REPORT),pagesize=A4,leftMargin=13*mm,rightMargin=13*mm,topMargin=11*mm,bottomMargin=12*mm,title='MCP ToolProof Detailed Experiment Report').build(story,onFirstPage=footer,onLaterPages=footer)

def main():
    a,p,r,e=load();f=figures(a,p,r,e);build(a,p,r,e,f);print(REPORT)
if __name__=='__main__':main()

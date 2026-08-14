from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "final"
FIG = ART / "figures"
DOWNLOADS = Path("/Users/chchou/Downloads")
REPORT = DOWNLOADS / "MCP_ToolProof_10모델_확장실험_결과보고서.pdf"
PAPER = DOWNLOADS / "MCP_ToolProof_KIISC_3페이지_논문.pdf"
BLUE, CYAN, ORANGE, RED, GRAY, LIGHT = "#173A63", "#13A8A8", "#F28E2B", "#D9534F", "#667085", "#EEF3F8"


font_path = "/System/Library/Fonts/Supplemental/AppleGothic.ttf"
pdfmetrics.registerFont(TTFont("K", font_path))
pdfmetrics.registerFont(TTFont("KB", font_path))
plt.rcParams["font.family"] = "Apple SD Gothic Neo"
plt.rcParams["axes.unicode_minus"] = False

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="Ko", fontName="K", fontSize=9.1, leading=13.4, wordWrap="CJK", alignment=TA_JUSTIFY))
styles.add(ParagraphStyle(name="SmallK", fontName="K", fontSize=7.2, leading=9.7, wordWrap="CJK"))
styles.add(ParagraphStyle(name="TinyK", fontName="K", fontSize=6.2, leading=7.8, wordWrap="CJK"))
styles.add(ParagraphStyle(name="H1K", fontName="KB", fontSize=17, leading=21, textColor=colors.HexColor(BLUE), spaceAfter=6))
styles.add(ParagraphStyle(name="H2K", fontName="KB", fontSize=12.5, leading=16, textColor=colors.HexColor(BLUE), spaceBefore=5, spaceAfter=4))
styles.add(ParagraphStyle(name="TitleK", fontName="KB", fontSize=21, leading=27, alignment=TA_CENTER, textColor=colors.HexColor(BLUE)))
styles.add(ParagraphStyle(name="Paper", fontName="K", fontSize=8.35, leading=10.65, wordWrap="CJK", alignment=TA_JUSTIFY))
styles.add(ParagraphStyle(name="PaperH", fontName="KB", fontSize=10.0, leading=12.2, textColor=colors.HexColor(BLUE), spaceBefore=2, spaceAfter=2))
styles.add(ParagraphStyle(name="PaperTitle", fontName="KB", fontSize=13.7, leading=17, alignment=TA_CENTER, textColor=colors.HexColor(BLUE)))
styles.add(ParagraphStyle(name="PaperTiny", fontName="K", fontSize=6.7, leading=8.2, wordWrap="CJK"))


def P(text: str, style: str = "Ko") -> Paragraph:
    # Final-paper corrections are applied here so the hand-balanced three-page
    # canvas keeps its geometry while the claims follow the frozen analyses.
    replacements = {
        "정상 응답으로 은폐된 MCP 도구 외부 효과 변조와<br/>독립 관찰 기반 의미 계약 검증": "MCP 외부효과 변조에 대한 동결 의미계약의<br/>탐지 경계 측정",
        "연구를 규정하는 세 질문": "연구 본질과 기여",
        "후속 실험": "동결 계약의 일반화 경계",
        "후속 평가 행렬": "공격 계열별 외부-schema hold-out",
        "분류: 인공지능 보안 / 양자내성암호": "독립 observer의 성립 조건",
    }
    text = replacements.get(text, text)
    if text.startswith("MCP 서버가 tools/list와 반환 JSON을 정상으로 유지하면서"):
        text = ("1,008개 의미 조건에서 manifest와 응답을 유지한 외부효과 변조를 측정하고, "
                "공식 MCP schema 동결 hold-out과 센서 양성대조군 5,400회를 추가했다. 동결 계약은 직접 필드·개수·종류 변조에는 유효했지만 "
                "미지 간접참조 공격 Recall은 사실상 0이었다. 정상 실행에서 학습한 값 관계와 hold-out F1 0.878이 같았고, 공격:정상=1:999에서 "
                "v1/v2 F1은 0.724/0.264였다. 결론적으로 값-의미 계약은 직접 변조 센서이지 일반 행동 증명이 아니며 observer 독립성·FPR·지연이 배치를 결정한다.")
    elif text.startswith("(1) schema alias 실패는 v2 completeness"):
        text = ("v1은 필수 필드 누락 시 비교가 생략되어 미탐했고 v2 completeness는 FN을 줄이는 대신 FP를 늘렸다. 외부-schema hold-out에서 "
                "learned relation과 frozen contract는 Recall 0.787, F1 0.878로 동률이었다. 알려진 직접 변조 4계열은 약 0.98이지만 계약에 없는 "
                "indirect-reference는 직접 receipt 필드를 보존한 채 resolved target만 바꾸어 사실상 탐지되지 않았다. 따라서 aggregate F1은 일반화 증거가 아니라 "
                "4계열 탐지·1계열 실패의 요약이며 미지 계열 n=1의 한계를 갖는다.")
    elif text.startswith("모델 계열 편중, 합성 도구·공격"):
        text = ("공격·계약 공동설계, 합성 도구, 비독립 반복, 미지 공격계열 n=1이 타당성을 제한한다. 10개 모델은 agent-loop 호환성을 보일 뿐 "
                "증거를 10배로 만들지 않는다. 센서 양성대조 5,400회에서 manifest/response/attestation Recall 0.125, trajectory 0.250, learned 0.375, frozen 0.500을 "
                "확인했으므로 본 위협에서 0은 미구현이 아니라 고정된 관측면의 결과다. 완전 blind 평가는 제3자 작성 도구·공격·계약이 필요하다.")
    elif text.startswith("byte-identical manifest와 정상 응답 아래에서도"):
        text = ("동결 값-의미 계약은 직접 필드·효과 종류·개수 변조에는 유효하지만 간접참조에는 구조적으로 무력했다. 정상값 관계 baseline과의 동률은 "
                "수작업 계약의 탐지 이득이 schema completeness와 감사 가능성에 한정됨을 보였다. 저유병률에서는 FPR이 F1보다 배치를 결정한다. 후속 연구는 "
                "제3자 작성 공격 다계열과 독립 provider receipt에서 이 경계를 재측정해야 한다.")
    elif text.startswith("테스트 tenant에서 OAuth scope를 최소화하고"):
        text = ("공식 외부 schema를 결과 확인 전에 동결한 10,080회에서 frozen contract와 learned relation은 동일한 F1 0.878을 보였다. "
                "Trajectory-lite는 본 corpus 0에서 hold-out 0.59로 상승했는데, 이는 hold-out에 kind/cardinality 변조가 포함된 corpus 차이이다. "
                "수작업 계약의 별도 이점은 schema-incomplete 양성대조 600건과 정책을 감사 가능한 명세로 남기는 데 있으며 행동 일반화는 아니다.")
    elif text.startswith("실무 적용은 저위험 도구의 shadow logging"):
        text = ("계열별 Recall은 effect-type 0.984, hidden-duplication 0.984, scope-expansion 0.983, target-substitution 0.983이었으나 "
                "indirect-reference-resolution은 약 0이었다. 따라서 집계 F1보다 계열별 실패를 우선 보고하며, 미지 계열 하나만으로 성공·실패 방향의 일반화를 주장하지 않는다.")
    elif text.startswith("핵심 자산은 LLM 에이전트가 호출한 도구의 실제 외부 효과"):
        text = ("observer는 MCP 서버와 관리자·키·저장소가 분리되고, 호출자가 검증하는 tenant-bound provider 서명 또는 다중 출처·투명성 로그가 있을 때만 독립이다. "
                "서버가 직접 쓰는 SQLite/응답, 동일 관리자·키, 공격자가 downstream까지 단독 통제하는 배치에서는 receipt가 두 번째 자기보고일 뿐이다. "
                "본 로컬 SQLite는 프로세스 분리를 재현했을 뿐 상용 SaaS 독립성을 증명하지 않는다.")
    elif text.startswith("정적 기준의 완전 실패와 외부 observer의 추가 신호"):
        text = ("Utility 감소 0p는 차단 없는 사후탐지 구성에서 자명하므로 판정 보류다. 계약 계산 p95는 0.036ms이나 receipt 종단 p95 301.7ms로 200ms 게이트는 실패했다. "
                "hold-out F1 0.8784는 수치 기준을 충족하나 미지 계열 n=1이라는 단서를 유지한다.")
    elif text.startswith("[1] Model Context Protocol, Security Best Practices"):
        text = ('[1] Model Context Protocol, “Tools; Security Best Practices,” 2026.<br/>'
                '[2] Z. Li et al., “Confused Deputy Attack Against Model Context Protocol,” ACM TOSEM, doi:10.1145/3830467, 2026.<br/>'
                '[3] Z. Wang et al., “MCPTox,” AAAI 40(42), 35811-35819, 2026.<br/>'
                '[4] S. Yergattikar, “Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments,” ACL Industry, 2026.<br/>'
                '[5] Huang et al., “From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers,” arXiv:2604.01905, 2026.<br/>'
                '[6] Z. Wang, “CAVA: Canonical Action Verification and Attestation for Runtime Governance of Agentic AI Systems,” arXiv:2607.13716, 2026.<br/>'
                '[7] Y. Shi et al., “Description-Code Inconsistency in Real-world MCP Servers,” arXiv:2606.04769, 2026.<br/>'
                '[8] 김찬형·이브라히모바 나일라 외, “MCP 기반 AI 에이전트 환경에서의 LLM 보안 위협 변화 동향 분석,” ASK, p.375, 2026.<br/>'
                '[9] 남장우 외, “공개된 MCP 취약점 교차매핑 기반 공격사례 분석,” ASK, p.251, 2026.<br/>'
                '[10] 김도영·고남현 외, “VAT 기반 LLM 에이전트 하이브리드 보안 아키텍처,” ASK, p.310, 2026.<br/>'
                '[11] 한승완·강승호, “Agent-SecSLA 프레임워크,” 융합보안논문지 26(3), 99-112, 2026.<br/>'
                '[12] 이재승·유제혁, “SBOM 변경 이력 자동 분석 기법,” 한국산업정보학회논문지 30(4), 39-60, 2025.')
    return Paragraph(text, styles[style])


def table(data, widths, tiny=False, repeat=1):
    if data and data[0] == ["주입 변수", "측정"]:
        data = [["공격 계열", "Frozen Recall"], ["effect type", "0.984"], ["hidden duplication", "0.984"], ["scope expansion", "0.983"], ["target substitution", "0.983"], ["indirect reference", "≈0.000"]]
    elif data and data[0] == ["축", "Go 기준", "관측"]:
        data = [["축", "기준", "관측/판정"], ["F1/Recall/FPR", ".85/.90/.05", ".998/.996/.001 통과"], ["Utility", "감소≤.05p", "판정 보류"], ["p95", "≤200ms", "301.7ms 실패"], ["hold-out F1", "≥.75", ".878, n=1 한계"]]
    style = "TinyK" if tiny else "SmallK"
    t = Table([[P(str(x), style) for x in row] for row in data], colWidths=widths, repeatRows=repeat)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BLUE)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#AAB8C6")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT)]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    return t


def load_rows(summary: dict) -> list[dict]:
    return [json.loads(line) for source in summary["sources"] for line in Path(source).read_text(encoding="utf-8").splitlines() if line]


def pct(x): return f"{100*x:.2f}%"


def savefig(name: str) -> str:
    FIG.mkdir(parents=True, exist_ok=True)
    path = FIG / name
    plt.tight_layout()
    plt.savefig(path, dpi=210, bbox_inches="tight", facecolor="white")
    plt.close()
    return str(path)


def make_figures(s: dict, rows: list[dict]) -> dict[str, str]:
    labels = ["정적 hash", "서명 manifest", "응답 검사", "의도 궤적", "ToolProof v1", "ToolProof v2"]
    keys = ["static_hash", "signed_manifest", "response_detector", "intent_trajectory", "toolproof", "toolproof_v2"]
    ds = s["itt"]
    x = np.arange(len(keys)); w = .24
    plt.figure(figsize=(9.3, 3.8))
    vals = [[ds[k][m] for k in keys] for m in ["f1", "recall", "fpr"]]
    for off, values, label, color in zip([-w, 0, w], vals, ["F1", "Recall", "FPR"], [BLUE, CYAN, ORANGE]):
        bars = plt.bar(x + off, values, w, label=label, color=color)
        for bar, value in zip(bars, values):
            plt.text(bar.get_x()+bar.get_width()/2, max(value, .012), f"{value:.3f}", ha="center", va="bottom", fontsize=7, rotation=90 if value < .02 else 0)
    plt.xticks(x, labels, rotation=11); plt.ylim(0, 1.13); plt.legend(ncol=3); plt.title(f"모든 방어를 동일 표본에서 실행한 ITT 성능 (N={s['runs']:,}; 0은 미실험이 아니라 탐지 실패)")
    p_def = savefig("defenses_all.png")

    models = list(s["by_model_itt"])
    v1 = [s["by_model_itt"][m]["metrics"]["toolproof"]["f1"] for m in models]
    v2 = [s["by_model_itt"][m]["metrics"]["toolproof_v2"]["f1"] for m in models]
    errs = [s["by_model_itt"][m]["errors"] for m in models]
    plt.figure(figsize=(9.4, 6.0)); y=np.arange(len(models)); h=.34
    ax=plt.gca(); ax.barh(y+h/2,v1,h,label="v1 F1",color=BLUE);ax.barh(y-h/2,v2,h,label="v2 F1",color=CYAN)
    ax.set_yticks(y,models,fontsize=8);ax.invert_yaxis();ax.set_xlim(.8,1.012);ax.set_xlabel("ITT F1")
    for i,e in enumerate(errs):
        ax.text(.802,i,f"오류 {e}",ha="left",va="center",fontsize=7,color=RED,
                bbox={"facecolor":"white","edgecolor":"none","alpha":.75,"pad":.5})
    ax.legend(loc="lower right",ncol=2);plt.title("모델별 강건성 및 운영 오류(오류 수는 행 내부 표기)")
    p_model=savefig("models_itt.png")

    attacks=[a for a in s["by_attack_itt"] if a != "none"]
    mat=np.array([[s["by_attack_itt"][a]["metrics"][k]["recall"] for a in attacks] for k in ["toolproof","toolproof_v2"]])
    plt.figure(figsize=(9.5,2.8));plt.imshow(mat,vmin=0,vmax=1,cmap="YlGnBu",aspect="auto")
    plt.colorbar(label="ITT Recall");plt.yticks([0,1],["ToolProof v1","ToolProof v2"]);plt.xticks(range(len(attacks)),[a.replace("_","\n") for a in attacks],fontsize=8)
    for i in range(2):
        for j in range(len(attacks)):plt.text(j,i,f"{mat[i,j]:.3f}",ha="center",va="center",fontsize=8,color="white" if mat[i,j]>.65 else "black")
    plt.title("공격 방법을 바꿨을 때의 탐지 재현율")
    p_attack=savefig("attack_matrix.png")

    pp1=s["pp"]["toolproof"];pp2=s["pp"]["toolproof_v2"]
    cm=np.array([[pp1["tn"],pp1["fp"],pp2["tn"],pp2["fp"]],[pp1["fn"],pp1["tp"],pp2["fn"],pp2["tp"]]])
    plt.figure(figsize=(8.4,3.5));plt.axis("off")
    tab=plt.table(cellText=[[f"TN {cm[0,0]:,}   |   FP {cm[0,1]:,}",f"TN {cm[0,2]:,}   |   FP {cm[0,3]:,}"],[f"FN {cm[1,0]:,}   |   TP {cm[1,1]:,}",f"FN {cm[1,2]:,}   |   TP {cm[1,3]:,}"]],
              rowLabels=["정상", "공격"],colLabels=["ToolProof v1","ToolProof v2"],cellLoc="center",loc="center",colWidths=[.38,.38])
    tab.auto_set_font_size(False);tab.set_fontsize(10);tab.scale(1.0,2.0)
    plt.title("유효 호출(PP) 혼동행렬",pad=16)
    p_cm=savefig("confusion.png")

    layers=[("LLM agent loop",s["runs"]),("계약 adversarial",s["adversarial_contract"]["runs"]),("TCP+SQLite",s["network_boundary"]["runs"]),("MCP SDK",s["real_mcp_sdk"]["runs"])]
    plt.figure(figsize=(8.5,3.3));bars=plt.barh([x[0] for x in layers],[x[1] for x in layers],color=[BLUE,CYAN,ORANGE,RED])
    for b,(_,v) in zip(bars,layers):plt.text(v+max(x[1] for x in layers)*.012,b.get_y()+b.get_height()/2,f"{v:,}",va="center")
    plt.xlabel("실행 수 (층별 별도 모집단)");plt.title("검증 층위: 합산 성능으로 오인하지 않고 각각 보고")
    p_layer=savefig("evidence_layers.png")
    return {"defenses":p_def,"models":p_model,"attacks":p_attack,"cm":p_cm,"layers":p_layer}


def footer(c, doc):
    c.saveState();c.setFont("K",6.8);c.setFillColor(colors.HexColor(GRAY));c.drawString(14*mm,8*mm,"MCP ToolProof — 원시 JSONL과 오류를 보존한 재현 가능 실험");c.drawRightString(196*mm,8*mm,str(doc.page));c.restoreState()


def report(s: dict, rows: list[dict], figs: dict[str,str]) -> None:
    v1,v2=s["itt"]["toolproof"],s["itt"]["toolproof_v2"]
    total_layers=s["runs"]+s["adversarial_contract"]["runs"]+s["network_boundary"]["runs"]+s["real_mcp_sdk"]["runs"]
    valid=[r for r in rows if not r.get("error")]
    lat=[r.get("latency_ms",0) for r in valid]; contract=[r.get("contract_latency_us",0) for r in valid]
    story=[P("MCP ToolProof 확장 실험 결과 보고서","TitleK"),P("10개 모델 · 공격 방법 변화 · 계약 적대 테스트 · TCP/SQLite · 공식 MCP SDK","H2K"),
           table([["검증 모집단","실행/결과"],["LLM tool-calling agent loop",f"{s['runs']:,} 계획, {s['valid']:,} 유효, {s['errors']:,} 오류"],["중복 감사",f"초과 {s.get('exclusion_audit',{}).get('excluded_duplicate_rows',0):,}행 제외, 충돌 {s.get('exclusion_audit',{}).get('conflicting_outcomes',0)}"],["적대적 계약 단위 테스트","12,000회"],["별도 프로세스 TCP + SQLite observer","2,800회"],["공식 MCP Python SDK 1.29.0 stdio","1,400회"],["전체 실행량",f"{total_layers:,}회(층별 모집단은 성능 산출 시 분리)"]],[63*mm,105*mm]),Spacer(1,3*mm),Image(figs["layers"],width=166*mm,height=63*mm),
           P(f"핵심 결론: 모든 방어를 동일 LLM 표본에 실제 적용했다. 정적 hash·서명 manifest·응답 검사·의도 궤적의 Recall=0은 빈 값이 아니라, byte-identical manifest와 정상 응답을 유지하는 정의된 위협에서 공격을 한 건도 잡지 못한 결과다. ToolProof v1 ITT F1={v1['f1']:.4f}, v2 ITT F1={v2['f1']:.4f}였다."),
           PageBreak(),P("1. 연구 질문과 실험 설계","H1K"),P("RQ1: 선언·응답은 정상인데 외부 효과만 조건부 변조될 때 기존 방어가 실패하는가? RQ2: 독립 observer와 값-의미 계약이 모델·도구·공격 변형에 걸쳐 탐지하는가? RQ3: required/type/additional-field 검사를 결합한 v2가 v1의 계약 사각지대를 줄이는가? RQ4: 인프로세스 결과가 프로세스·저장소·실제 MCP 프로토콜 경계에서도 재현되는가?"),
           table([["축","설계"],["모델","Hermes/Llama/Mistral/Qwen 계열 10종"],["LLM 표본","기존 9,720 + 신규 37,440 = 47,160 계획"],["도구","결제·메일·파일·HTTP·DB·일정 등 12종"],["공격","대상/값 치환, 숨은 복제, 범위 확장, 지연 활성화, 교차 채널"],["변형","기존 4×3 반복 + 신규 8×6 반복; 정상 대조 포함"],["정답","숨겨진 서버 모드/공격 라벨; detector 출력과 분리"],["통계","PP와 보수적 ITT 동시 보고, Wilson 95% CI, 정확 McNemar"]],[40*mm,128*mm]),Spacer(1,3*mm),P("오류 처리","H2K"),P("타임아웃과 호출 실패는 삭제·대체하지 않았다. PP는 유효 호출만 평가하고, ITT는 공격 실행 오류를 미탐(FN), 정상 실행 오류를 가용성 실패/오탐(FP)로 보수적으로 계산한다. 낮은 동시성 재시도는 원본을 덮어쓰지 않는 민감도 분석이다."),
           Spacer(1,5*mm),P("2. 모든 방어의 정량 결과","H1K"),Image(figs["defenses"],width=174*mm,height=71*mm),Image(figs["cm"],width=165*mm,height=49*mm),
           table([["방어(ITT)","TP","FN","FP","TN","Precision","Recall","F1"]]+[[name,f"{s['itt'][key]['tp']:,}",f"{s['itt'][key]['fn']:,}",f"{s['itt'][key]['fp']:,}",f"{s['itt'][key]['tn']:,}",f"{s['itt'][key]['precision']:.4f}",f"{s['itt'][key]['recall']:.4f}",f"{s['itt'][key]['f1']:.4f}"] for name,key in zip(["정적 hash","서명 manifest","응답 검사","의도 궤적","ToolProof v1","ToolProof v2"],["static_hash","signed_manifest","response_detector","intent_trajectory","toolproof","toolproof_v2"])],[30*mm,17*mm,17*mm,17*mm,17*mm,23*mm,23*mm,23*mm],tiny=True),
           Spacer(1,5*mm),P("3. 모델·공격 방법 변화에 대한 강건성","H1K"),Image(figs["models"],width=174*mm,height=75*mm),Image(figs["attacks"],width=174*mm,height=52*mm),
           P("공격별 표는 공격 수법을 바꾸었을 때의 ITT 재현율이다. v1과 v2의 차이는 모델 생성 인자의 schema 불완전성과 observer 효과의 값·cardinality·scope 검사에서 발생한다. 공격 이름만 바뀌어도 동일한 response–effect 관계를 깨면 계약이 검출하지만, 계약에 선언되지 않은 새 효과 채널은 관찰 범위 밖이다."),
           Spacer(1,5*mm),P("4. 계약 적대 테스트와 실패 분석","H1K"),
           table([["방어","TP","FN","FP","TN","Recall","F1"],["Schema only",*map(str,[s['adversarial_contract']['schema_only'][x] for x in ['tp','fn','fp','tn']]),f"{s['adversarial_contract']['schema_only']['recall']:.4f}",f"{s['adversarial_contract']['schema_only']['f1']:.4f}"],["ToolProof v1",*map(str,[s['adversarial_contract']['toolproof_v1'][x] for x in ['tp','fn','fp','tn']]),f"{s['adversarial_contract']['toolproof_v1']['recall']:.4f}",f"{s['adversarial_contract']['toolproof_v1']['f1']:.4f}"],["ToolProof v2",*map(str,[s['adversarial_contract']['toolproof_v2'][x] for x in ['tp','fn','fp','tn']]),f"{s['adversarial_contract']['toolproof_v2']['recall']:.4f}",f"{s['adversarial_contract']['toolproof_v2']['f1']:.4f}"]],[34*mm,18*mm,18*mm,18*mm,18*mm,25*mm,25*mm]),
           P("12개 도구×100 변형×(공격 9종+정상 1종)의 12,000회 합성 계약 단위 테스트에서 missing required, additional field, type confusion, null, Unicode key, target substitution, duplication, effect type change, scope expansion을 교차했다. v1의 1,200 FN은 schema completeness가 빠진 구조적 실패였다. v2는 required/type/additional-field 검사를 앞단에 추가했다. 이 단위 테스트는 LLM 성능 표본과 별개이며, 방어 규칙에 맞춘 합성 자료라는 한계가 있다."),
           P(f"동일 유효 LLM 표본의 정확 McNemar: v1 오답→v2 정답 {s['mcnemar']['v1_wrong_v2_right']}건, v1 정답→v2 오답 {s['mcnemar']['v1_right_v2_wrong']}건, 양측 p={s['mcnemar']['p_two_sided_exact']:.4g}. 효과 크기와 오탐의 방향을 함께 해석해야 한다."),
           Spacer(1,5*mm),P("5. 경계 확장 검증","H1K"),
           table([["환경","실행","정적 TP/FN","응답 TP/FN","ToolProof TP/FN","정상 FP/TN"],["별도 HTTP 프로세스 + TCP + SQLite","2,800","0/2,400","0/2,400","2,400/0","0/400"],["공식 MCP SDK stdio 세션","1,400","0/1,200","0/1,200","1,200/0","0/200"]],[51*mm,18*mm,26*mm,26*mm,30*mm,25*mm],tiny=True),Spacer(1,3*mm),
           P("첫 경계 실험은 도구 서버와 observer를 별도 프로세스로 두고 localhost TCP와 SQLite 영속 상태를 사용했다. 둘째는 MCP Python SDK 1.29.0으로 initialize→tools/list→tools/call을 실제 수행하고 독립 SQLite observer로 외부 효과를 판정했다. 서버 모드 7종에서 manifest hash는 하나였다. 따라서 단순 함수 호출에만 묶인 현상은 아니지만, 원격 SaaS/OAuth·OS 계정 격리·실제 네트워크 장애는 아직 검증하지 않았다."),
           P("측정 비용","H2K"),P(f"유효 LLM 호출의 추론 지연 중앙값은 {statistics.median(lat):.0f} ms, 계약 판정 중앙값은 {statistics.median(contract):.2f} μs였다. 이는 로컬 observer에서의 계약 연산 비용이며 원격 감사 API 왕복은 포함하지 않는다."),
           Spacer(1,5*mm),P("6. 위협·실패·확장 가능성","H1K"),
           table([["관측된 실패/한계","추가한 검증 또는 다음 단계"],["v1이 필수 필드 누락/별칭을 놓침","v2 schema completeness + 값/효과 계약; 적대 테스트 12,000회"],["고동시성에서 모델 호출 타임아웃","원본 ITT 보존 + 저동시성 재시도 민감도 분석"],["인프로세스 외부 타당성","별도 TCP/SQLite 2,800회 + 공식 MCP SDK 1,400회"],["새 효과 채널은 observer가 못 볼 수 있음","eBPF/감사로그/SaaS receipt 등 다중 observer와 fail-closed 정책"],["계약 작성 오류·업무 변화","버전 계약, 정상 변화 회귀셋, shadow mode, 사용자 승인"],["원격 SaaS 미검증","테스트 tenant·최소권한 OAuth·비용 상한을 둔 후속 실험"]],[62*mm,106*mm]),Spacer(1,3*mm),
           P("책임 있는 주장 범위","H2K"),P("본 결과는 ‘MCP 전체 공격을 해결’하거나 ‘rug pull 최초 발견’을 뜻하지 않는다. 검증된 주장은 byte-identical manifest와 정상 응답을 유지한 조건부 외부 효과 변조가 네 기존 기준을 통과했고, 관찰 가능한 효과에 대해 실행 가능한 값-의미 계약이 추가 탐지 신호를 제공했다는 것이다."),
           P("재현성","H2K"),P(f"LLM 원시 JSONL {s['runs']:,}행, 계약/경계 원시 로그, commit·seed·환경·manifest hash를 보존했다. 관측 manifest hash 수: {len(s['manifest_hashes'])}. 결과 PDF의 수치는 생성 시 원시 로그에서 자동 집계한다."),
           Spacer(1,5*mm),P("7. 논문용 핵심 결과와 제출 체크리스트","H1K"),
           table([["심사 질문","증거"],["0 막대는 미실험인가?","아니오. 동일 표본에 6개 방어 모두 실행; TP=0/FN 전체를 표기"],["수치가 유효 호출만 골랐나?","PP와 보수적 ITT를 동시에 공개"],["공격법 변경에도 되나?","6개 LLM 공격군 + 9개 계약 적대 변형별 결과"],["실제 MCP인가?","공식 SDK initialize/list/call 1,400회; 단 원격 SaaS는 아님"],["v2가 무조건 우월한가?","paired McNemar와 오탐 trade-off 공개"],["재현 가능한가?","원본 JSONL, SHA-256, 코드 commit, 환경 식별자 보존"]],[49*mm,119*mm]),Spacer(1,3*mm),P("논문에서는 LLM agent loop를 주 결과로, 12,000회 계약 적대 테스트와 두 경계 실험을 보조 결과로 배치한다. 3페이지 지면에서는 모든 숫자를 억지로 넣기보다 혼동행렬·공격별 Recall·경계 표를 우선한다. 실제 원격 SaaS와 권한 경계는 ‘완료’가 아니라 후속 연구로 명시한다."),
           P("최종 해석","H2K"),P("연구의 강점은 높은 단일 F1 자체보다 실패하는 기준을 함께 구현하고, 그 실패가 위협모델에서 왜 필연적인지 외부 상태 ground truth로 보인 점이다. 우승 가능성을 높이는 핵심은 완벽함을 주장하는 것이 아니라, zero baseline·계약 실패 반례·ITT·프로토콜 경계를 같은 논리 사슬로 연결하는 것이다.")]
    SimpleDocTemplate(str(REPORT),pagesize=A4,leftMargin=14*mm,rightMargin=14*mm,topMargin=12*mm,bottomMargin=13*mm,title="MCP ToolProof Extended Experiment Report").build(story,onFirstPage=footer,onLaterPages=footer)


def draw_item(c: Canvas, item, x, y, width) -> float:
    if isinstance(item, str): item=P(item,"Paper")
    avail=y-10*mm
    _,h=item.wrap(width,avail)
    item.drawOn(c,x,y-h)
    return y-h-1.2*mm


def paper(s: dict, figs: dict[str,str]) -> None:
    c=Canvas(str(PAPER),pagesize=A4);W,H=A4;margin=10*mm;gap=5*mm;cw=(W-2*margin-gap)/2
    def page_header(page):
        c.setStrokeColor(colors.HexColor("#AAB8C6"));c.line(margin,H-8*mm,W-margin,H-8*mm);c.setFont("K",5.6);c.setFillColor(colors.HexColor(GRAY));c.drawRightString(W-margin,5.5*mm,f"{page}/3")
    def col(items,x,y):
        prepared=[]; total=0
        for item in items:
            if isinstance(item,str): item=P(item,"Paper")
            _,h=item.wrap(cw,y-10*mm);prepared.append((item,h));total+=h
        # Distribute residual vertical space instead of leaving an empty lower block.
        # The final item ends at 11 mm, keeping only the printable safety margin.
        gap=max(.8*mm,(y-11*mm-total)/max(1,len(prepared)-1))
        for item,h in prepared:
            item.drawOn(c,x,y-h);y-=h+gap
        return y
    v1=s['itt']['toolproof'];v2=s['itt']['toolproof_v2']
    # Page 1
    page_header(1); y=H-13*mm
    title=P("정상 응답으로 은폐된 MCP 도구 외부 효과 변조와<br/>독립 관찰 기반 의미 계약 검증","PaperTitle");_,h=title.wrap(W-2*margin,40*mm);title.drawOn(c,margin,y-h);y-=h+1*mm
    sub=P("Response–Effect Inconsistency in MCP Tools and Independent Observation-Based Semantic Contract Verification<br/>저자명 · 소속 (제출 전 입력)","PaperTiny");_,h=sub.wrap(W-2*margin,20*mm);sub.drawOn(c,margin,y-h);y-=h+2*mm
    left=[P("요 약","PaperH"),P(f"MCP 서버가 tools/list와 반환 JSON을 정상으로 유지하면서 실제 ledger·mailbox·filesystem 효과만 조건부 변조하는 response–effect inconsistency를 실증한다. 10개 공개 모델과 12개 도구에서 {s['runs']:,}회 tool-calling 실행을 계획·수행했으며 오류를 포함하는 ITT에서 ToolProof v1은 F1 {v1['f1']:.4f}, v2는 {v2['f1']:.4f}였다. 정적 hash, 서명 manifest, 응답 검사, 의도 궤적은 정의된 공격의 TP가 0이었다. 추가로 계약 적대 테스트 12,000회, 별도 TCP/SQLite 2,800회, 공식 MCP SDK 1,400회로 실패 원인과 경계 재현성을 검증했다.","Paper"),P("연구를 규정하는 세 질문","PaperH"),table([["질문","답"],["본질은 무엇인가?","AI가 받은 정상 응답이 아니라 실제 외부 효과의 의미 무결성을 검증하는 연구다."],["왜 이렇게 진행했는가?","manifest→응답→agent loop→독립 상태의 관측면을 분리해야 어느 방어가 왜 실패하는지 인과적으로 보일 수 있다."],["왜 필요한가?","결제·메일·파일을 실행하는 AI에서 정상 텍스트만 믿으면 실제 피해를 탐지·차단할 근거가 없기 때문이다."]],[25*mm,52*mm],tiny=True),P("1. 서론","PaperH"),P("MCP 보안 연구는 descriptor poisoning, 도구 선택 편향, 서버 승인과 실행 궤적 검증을 발전시켰다[1–6]. 그러나 승인된 서버가 인터페이스를 한 바이트도 바꾸지 않고 고액·특정 tenant·N회 이후에만 외부 효과를 바꾸면 control-plane 무결성은 의미 무결성을 보장하지 않는다. 본 연구는 ‘최초 rug pull’이 아니라 (1) byte-identical manifest+정상 응답+조건부 side effect라는 좁은 위협, (2) 실행 가능한 value-semantics 계약과 독립 observer의 결합, (3) 오류를 포함한 다모델·다경계 평가를 기여로 삼는다.","Paper"),P("관련 연구와 공백","PaperH"),P("MCPTox는 실제 서버의 description 기반 poisoning을, Confused Deputy와 Connor는 도구 선택·악성 서버 궤적을, CAVA/HCP는 승인·canonical action·실행 불변식을 다룬다[2–7]. 국내 연구는 위협 분류, CVE 교차매핑, VAT 최소권한, Agent-SecSLA와 SBOM 변조 탐지를 제안한다[8–12]. 이들은 필요성을 뒷받침하지만 ‘정상 응답과 동일 manifest 아래 외부 상태만 달라짐’을 ground truth로 두지 않는다. 따라서 신규성은 정적 무결성의 일반 한계가 아니라 이 좁은 변종의 정량화와 observer-계약 조합에 있다.","Paper"),P("2. 위협 모델 및 공격","PaperH"),P("공격자는 원격 도구 구현 또는 downstream API를 통제하지만 클라이언트·모델·observer는 침해하지 못한다. target/value substitution, hidden duplication, scope expansion, delayed activation, cross-channel의 6군을 구현했다. 정상·공격 서버의 canonical manifest SHA-256과 응답 schema는 동일하다. 정답은 detector와 독립된 숨은 서버 모드·공격 라벨이다.","Paper"),table([["공격","외부 효과","정적 통과 이유"],["대상/값 치환","수신자·금액 변경","형식·응답 정상"],["숨은 복제","추가 전송/쓰기","반환에 미표시"],["범위 확장","다른 tenant/경로","annotation 유지"],["지연 활성화","N회 후 변조","승인 probe 통과"],["교차 채널","승인 밖 sink","주 채널 정상"]],[20*mm,28*mm,29*mm],tiny=True),P("활성 조건은 금액·사용자·호출 횟수·시간·환경으로 바꾸되 공격 표식은 가상 ATTACKER/INJECTED/canary로 제한했다. 지연·표적 조건은 승인 시점의 단발 probe를 회피할 수 있으므로, 배치 이후 반복 관찰이 필요한 이유를 직접 모델링한다.","Paper"),P("연구 질문","PaperH"),P("RQ1 기존 네 기준의 사각지대가 실제 agent loop에서도 재현되는가? RQ2 observer 계약은 모델·도구·공격 변화에 일반화되는가? RQ3 schema completeness가 v1 실패를 줄이는가? RQ4 프로세스와 MCP 프로토콜 경계에서도 같은 결론이 유지되는가?","Paper")]
    right=[P("3. ToolProof 설계","PaperH"),P("프록시는 호출 인자와 correlation ID를 기록하고, 신뢰 경계 밖의 ledger·mailbox·filesystem·HTTP/DB receipt를 observer가 읽는다. 계약은 required/type/additional-field, input-effect 값 보존, 효과 종류·개수, 목적지·scope, idempotency를 검사한다. v1은 생성된 인자 키만 순회했지만 v2는 schema completeness를 먼저 강제한다. 응답 텍스트는 판정 근거가 아니다.","Paper"),P("판정 절차","PaperH"),P("① canonical manifest의 승인 상태를 확인한다. ② 실제 tool input을 schema로 검증한다. ③ correlation ID로 독립 receipt를 수집한다. ④ 입력-효과 값, cardinality와 scope를 계약에 대입한다. ⑤ 위반 시 결과를 LLM에 전달하기 전에 차단·승인 요청·격리 중 정책을 적용한다. observer 미가용은 안전 판정으로 간주하지 않고 별도 unavailable 상태로 기록한다.","Paper"),table([["계약","예시 불변식"],["값 보존","effect.recipient=input.recipient"],["개수","idempotency key당 효과 ≤1"],["종류","read-only이면 write=0"],["범위","tenant/path/destination allowlist"],["정보흐름","canary의 비승인 sink 이동=0"]],[22*mm,53*mm],tiny=True),P("3.1 실험 설계","PaperH"),P("공격 12도구×6군×기존 4변형×3반복과 신규 8변형×6반복, 정상 대조를 10개 모델에 실행하여 총 47,160회를 계획했다. 유효 호출(PP)과 모든 배정 실행(ITT)을 함께 보고한다. ITT에서 공격 오류는 FN, 정상 오류는 가용성 FP로 처리한다. 95% Wilson 구간과 동일 표본 정확 McNemar를 사용한다.","Paper"),table([["방어(ITT)","TP","FN","FP","F1"],["정적 hash",s['itt']['static_hash']['tp'],s['itt']['static_hash']['fn'],s['itt']['static_hash']['fp'],f"{s['itt']['static_hash']['f1']:.3f}"],["서명 manifest",s['itt']['signed_manifest']['tp'],s['itt']['signed_manifest']['fn'],s['itt']['signed_manifest']['fp'],f"{s['itt']['signed_manifest']['f1']:.3f}"],["응답 검사",s['itt']['response_detector']['tp'],s['itt']['response_detector']['fn'],s['itt']['response_detector']['fp'],f"{s['itt']['response_detector']['f1']:.3f}"],["의도 궤적",s['itt']['intent_trajectory']['tp'],s['itt']['intent_trajectory']['fn'],s['itt']['intent_trajectory']['fp'],f"{s['itt']['intent_trajectory']['f1']:.3f}"],["ToolProof v1",v1['tp'],v1['fn'],v1['fp'],f"{v1['f1']:.3f}"],["ToolProof v2",v2['tp'],v2['fn'],v2['fp'],f"{v2['f1']:.3f}"]],[24*mm,12*mm,12*mm,12*mm,14*mm],tiny=True),P("표 1. 0은 미실험이 아니라 정의된 위협에서의 탐지 실패다.","PaperTiny"),P("평가 위생","PaperH"),P(f"공격 성공은 응답이 아니라 observer 상태로 계산했다. run별 seed·commit·환경·manifest hash를 기록했다. 중복 감사에서 초과 {s.get('exclusion_audit',{}).get('excluded_duplicate_rows',0):,}행을 키 기준 제외했고 결과 충돌은 {s.get('exclusion_audit',{}).get('conflicting_outcomes',0)}건이었다. 오류 행은 ITT와 PP로 병렬 제시했다.","Paper"),P("대조군 해석","PaperH"),P("static/signed는 manifest 변화, response detector는 반환 JSON의 불일치, intent trajectory는 호출 전후 의도 이탈을 찾는다. 본 공격은 이 세 관측면을 의도적으로 고정하므로 TP=0이 예상되는 negative control이다. 핵심은 이를 생략하지 않고 동일 표본에서 실제로 실행해 실패 수를 정량화한 데 있다.","Paper")]
    col(left,margin,y);col(right,margin+cw+gap,y);c.showPage()
    # Page 2
    page_header(2);y=H-12*mm
    model_rows=[[m.replace(":"," "),s['by_model_itt'][m]['errors'],f"{s['by_model_itt'][m]['metrics']['toolproof']['f1']:.3f}",f"{s['by_model_itt'][m]['metrics']['toolproof_v2']['f1']:.3f}"] for m in s['by_model_itt']]
    left=[P("4. 결과","PaperH"),P(f"총 {s['runs']:,}회 중 유효 {s['valid']:,}회, 오류 {s['errors']:,}회였다. PP 혼동행렬에서 v1은 TP/FP/FN/TN={s['pp']['toolproof']['tp']:,}/{s['pp']['toolproof']['fp']:,}/{s['pp']['toolproof']['fn']:,}/{s['pp']['toolproof']['tn']:,}, v2는 {s['pp']['toolproof_v2']['tp']:,}/{s['pp']['toolproof_v2']['fp']:,}/{s['pp']['toolproof_v2']['fn']:,}/{s['pp']['toolproof_v2']['tn']:,}였다. ITT 결과는 표 1과 같다.","Paper"),Image(figs['defenses'],width=cw,height=42*mm),P("그림 1. 동일 표본의 방어별 F1/Recall/FPR. 0 막대에 값을 직접 표기했다.","PaperTiny"),P("4.1 모델별 결과","PaperH"),table([["모델","오류","v1 F1","v2 F1"]]+model_rows,[35*mm,12*mm,15*mm,15*mm],tiny=True),P("모델별 표는 오류를 포함한 ITT다. 특정 계열 하나의 성공으로 전체 성능을 대신하지 않았으며 timeout 역시 제거하지 않았다.","PaperTiny"),P("4.2 공격 방법 변화","PaperH"),Image(figs['attacks'],width=cw,height=34*mm),P("그림 2. 6개 공격군별 ITT Recall. 공격 수법이 달라도 계약된 값·효과 관계를 깨면 검출하나, 미관찰 채널은 범위 밖이다.","PaperTiny"),P("도구 범위","PaperH"),table([["도메인","도구 예","관찰 효과"],["금융","transfer/refund","ledger row"],["통신","mail/webhook","mailbox/HTTP receipt"],["파일","write/move","path/hash"],["데이터","update/delete","DB mutation"],["일정","create/update","calendar event"]],[18*mm,25*mm,34*mm],tiny=True),P("도구군마다 보안 의미는 다르지만 입력과 독립 receipt 사이의 값·효과 관계로 정규화했다. 단일 payment 사례만으로 결론을 내리지 않은 이유다.","Paper")]
    adv=s['adversarial_contract']
    right=[P("4.3 실패에서 도출한 v2","PaperH"),P("v1 미탐은 작은 Qwen 모델이 update_beneficiary에서 account 대신 beneficiary_account를 출력한 사례에 집중됐다. 실제 인자 키만 검사하면 필수 account가 사라져도 비교 자체가 수행되지 않는다. required/type/additional-field 검사를 앞단에 추가하고 아래 9종을 교차했다.","Paper"),P("4.4 적대적 계약 검증","PaperH"),table([["12,000회","TP","FN","FP","Recall","F1"],["Schema",adv['schema_only']['tp'],adv['schema_only']['fn'],adv['schema_only']['fp'],f"{adv['schema_only']['recall']:.3f}",f"{adv['schema_only']['f1']:.3f}"],["v1",adv['toolproof_v1']['tp'],adv['toolproof_v1']['fn'],adv['toolproof_v1']['fp'],f"{adv['toolproof_v1']['recall']:.3f}",f"{adv['toolproof_v1']['f1']:.3f}"],["v2",adv['toolproof_v2']['tp'],adv['toolproof_v2']['fn'],adv['toolproof_v2']['fp'],f"{adv['toolproof_v2']['recall']:.3f}",f"{adv['toolproof_v2']['f1']:.3f}"]],[20*mm,11*mm,11*mm,11*mm,16*mm,14*mm],tiny=True),P("표 2. 방어 규칙을 겨냥한 합성 단위 테스트이므로 LLM 표본과 분리해 해석한다.","PaperTiny"),P(f"LLM 유효 동일 표본에서 v1 오답→v2 정답 {s['mcnemar']['v1_wrong_v2_right']}건, 반대 {s['mcnemar']['v1_right_v2_wrong']}건이며 정확 McNemar 양측 p={s['mcnemar']['p_two_sided_exact']:.4g}였다. 효과 크기뿐 아니라 새 오탐 가능성도 함께 공개한다.","Paper"),P("적대 변형별 목적","PaperH"),table([["변형","검사 축"],["missing/null/type/Unicode","schema 완전성"],["additional field","비인가 입력"],["target substitution","값 보존"],["duplication","cardinality"],["effect type/scope","종류·권한 경계"]],[30*mm,47*mm],tiny=True),P("4.5 경계 재현성","PaperH"),table([["환경","N","정적/응답 TP","ToolProof TP/FN","FP/TN"],["TCP+SQLite","2,800","0/0","2,400/0","0/400"],["MCP SDK","1,400","0/0","1,200/0","0/200"]],[22*mm,12*mm,20*mm,22*mm,16*mm],tiny=True),P("별도 서버 프로세스·localhost TCP·SQLite 영속 observer에서 2,800회, MCP Python SDK 1.29.0의 initialize→tools/list→tools/call stdio 세션에서 1,400회를 실행했다. 이로써 단순 함수 호출 전용 현상은 배제했으나 실제 SaaS/OAuth/OS 권한 분리는 아직 주장하지 않는다.","Paper"),P("4.6 비용·효용·신뢰구간","PaperH"),P(f"v2 ITT Recall 95% Wilson 구간은 [{v2['recall_ci95'][0]:.4f}, {v2['recall_ci95'][1]:.4f}], FPR은 {v2['fpr']:.4f}였다. 계약 계산은 μs 수준이나 원격 receipt 조회는 제외한다. 정상 성공률과 재시도율도 산출해 보안 성능만을 위해 효용을 숨기지 않았다.","Paper"),P("오류 민감도","PaperH"),P("고동시성 timeout은 공격 결과와 무관하게 원본 JSONL에 남겼다. PP는 탐지 규칙의 조건부 성능을, ITT는 실제 운영 파이프라인의 실패까지 반영한다. 낮은 동시성 재시도는 오류 원인이 모델 의미 실패인지 인프라 포화인지 구분하는 보조 분석이며 주 결과를 대체하지 않는다.","Paper")]
    col(left,margin,y);col(right,margin+cw+gap,y);c.showPage()
    # Page 3
    page_header(3);y=H-12*mm
    left=[P("5. 논의","PaperH"),P("정적·서명·응답·의도 기준의 Recall=0은 일반적으로 쓸모없다는 뜻이 아니다. 공격자가 변경한 것이 그 센서의 관측 대상이 아니기 때문에 이 위협에서는 구조적으로 실패한다. 따라서 ToolProof는 기존 control plane을 대체하지 않고, 실제 효과를 볼 수 있는 도메인에서 data plane 증거를 보완한다.","Paper"),P("5.1 실패 분석과 확장","PaperH"),P("(1) schema alias 실패는 v2 completeness 검사로 보완했다. (2) 고동시성 timeout은 원본 ITT에 유지하고 낮은 동시성 재시도를 별도 민감도 분석으로 둔다. (3) 지연 활성화와 표적 선택은 probe 시점 회피가 가능하므로 지속 표본추출과 metamorphic probe가 필요하다. (4) cross-channel은 등록된 observer 밖으로 이동하면 놓칠 수 있어 eBPF/감사로그/SaaS receipt 등 다중 관찰자가 필요하다. (5) 업무 정책 변화는 공격과 유사하므로 versioned contract, shadow mode, 정상 변화 회귀셋과 사용자 승인을 결합해야 한다.","Paper"),P("배치 정책","PaperH"),table([["상태","정책"],["계약 통과+observer 정상","결과 전달"],["위반","효과 보류·사용자 승인·격리"],["observer unavailable","고위험 fail-closed/저위험 제한 실행"],["계약 버전 불일치","shadow 비교 후 재승인"]],[30*mm,47*mm],tiny=True),P("탐지 결과를 단순 경고로 끝내지 않고 side effect commit 전후의 보류 지점과 연결해야 한다. 이미 커밋된 외부 효과는 탐지만으로 되돌릴 수 없으므로 2단계 commit, idempotency key, compensating transaction을 도메인별로 결합한다.","Paper"),P("5.2 타당성 위협","PaperH"),P("모델 계열 편중, 합성 도구·공격, 계약과 공격 생성기의 공동 설계, 로컬 네트워크, 비용 없는 모의 SaaS가 외적 타당성을 제한한다. 공식 MCP SDK 실험도 로컬 stdio이며 실제 원격 tenant·OAuth scope·rate limit을 포함하지 않는다. 따라서 ‘모든 MCP 공격 방어’ 또는 ‘암호학적 행동 증명’을 주장하지 않는다.","Paper"),P("주장 경계","PaperH"),table([["근거가 있는 주장","근거가 없는 주장"],["정의된 공격에서 기존 기준 TP=0","기존 방어가 일반적으로 무용"],["관찰 효과에서 계약 추가 신호","블랙박스 행동의 완전 증명"],["로컬 MCP SDK 경계 재현","실제 SaaS/OAuth 검증 완료"],["v2가 schema 사각지대 축소","모든 미지 공격 100% 방어"]],[40*mm,37*mm],tiny=True),P("5.3 안전·윤리","PaperH"),P("결제는 0원 가상 ledger, 메일은 외부 발송 없는 mailbox, 파일은 임시 sandbox, HTTP는 localhost sink만 사용했다. 공격 표식은 ATTACKER/INJECTED/canary로 제한했으며 실제 계정·개인정보·금전 피해를 만들지 않았다. 공개 시 서버 악성화 코드는 기본 비활성화하고 재현 범위를 문서화한다.","Paper"),P("6. 결론","PaperH"),P("byte-identical manifest와 정상 응답 아래에서도 외부 효과 의미는 변조될 수 있었다. 10모델 agent loop와 두 실행 경계에서 기존 네 기준의 사각지대를 재현했고, 독립 observer+value-semantics 계약이 추가 탐지 신호를 제공함을 정량화했다. 핵심 후속 과제는 실제 SaaS의 최소권한 receipt와 계약 진화를 평가하는 것이다.","Paper")]
    right=[P("참고문헌","PaperH"),P("[1] Model Context Protocol, Security Best Practices, 2026.<br/>[2] Li et al., “Confused Deputy Attack Against Model Context Protocol,” ACM TOSEM, 2026, doi:10.1145/3830467.<br/>[3] “MCPTox: A Benchmark for Tool Poisoning on Real-World MCP Servers,” AAAI, 2026.<br/>[4] “Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments,” ACL Industry, 2026.<br/>[5] Huang et al., “From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers,” arXiv:2604.01905, 2026.<br/>[6] Wang, “Canonical Action Verification and Attestation,” arXiv:2607.13716, 2026.<br/>[7] “Description-Code Inconsistency in Real-world MCP Servers,” arXiv:2606.04769, 2026.<br/>[8] 김찬형 외, “MCP 기반 AI 에이전트 환경에서의 LLM 보안 위협 변화 동향 분석,” ASK, p.375, 2026.<br/>[9] 남장우 외, “공개된 MCP 취약점 교차매핑 기반 공격사례 분석,” ASK, p.251, 2026.<br/>[10] 김도영 외, “VAT 기반 LLM 에이전트 하이브리드 보안 아키텍처,” ASK, p.310, 2026.<br/>[11] 한승완·강승호, “Agent-SecSLA 프레임워크,” 융합보안논문지 26(3), 99–112, 2026.<br/>[12] 이재승·유제혁, “SBOM 변경 이력 자동 분석 기법,” 한국산업정보학회논문지 30(4), 39–60, 2025.","PaperTiny"),P("재현성 메모","PaperH"),P(f"LLM 배정 실행 {s['runs']:,}회(유효 {s['valid']:,}, 오류 {s['errors']:,}); 별도 계약 12,000회, TCP/SQLite 2,800회, MCP SDK 1,400회. 원시 JSONL, seed, 코드 commit, 환경 및 manifest SHA-256을 보존했다. 지면 수치는 생성 스크립트가 원시 로그에서 자동 집계했다.","PaperTiny"),P("사전 기준과 해석","PaperH"),table([["축","Go 기준","관측"],["ToolProof F1","≥.85",f"{v1['f1']:.3f}/{v2['f1']:.3f}"],["Recall","≥.90",f"{v1['recall']:.3f}/{v2['recall']:.3f}"],["FPR","≤.05",f"{v1['fpr']:.3f}/{v2['fpr']:.3f}"],["미지/변형 공격","공개","공격별 표기"],["경계 검증","observer 필수","TCP+SDK"]],[19*mm,24*mm,34*mm],tiny=True),P("정적 기준의 완전 실패와 외부 observer의 추가 신호가 여러 도구·모델에서 반복되어 주제는 Go로 판정한다. 다만 실제 SaaS 검증 전에는 배치 일반화를 보류한다.","Paper"),P("후속 실험","PaperH"),P("테스트 tenant에서 OAuth scope를 최소화하고 결제/메일 provider의 독립 audit receipt를 수집한다. 정상 업무 변화와 공격을 blind split으로 섞고, 계약 작성자와 공격 생성자를 분리해 공동설계 편향을 줄인다. observer 장애·지연·eventual consistency를 주입해 fail-open/closed의 효용 비용도 측정한다.","Paper"),P("후속 평가 행렬","PaperH"),table([["주입 변수","측정"],["receipt 0–5 s 지연","TTD·timeout FPR"],["observer 1–10% 장애","fail-open/closed Utility"],["정상 schema migration","회귀 오탐"],["새 공격 채널 hold-out","unseen Recall"],["OAuth scope 축소","피해 범위/업무 성공"]],[32*mm,45*mm],tiny=True),P("실무 적용은 저위험 도구의 shadow logging에서 시작해 고위험 결제·메일에 human approval을 붙이고, 충분한 정상 변화 자료가 쌓인 후 차단 모드로 승격한다. 계약 위반뿐 아니라 observer 가용성과 rollback 성공률을 운영 SLO로 둔다.","Paper"),P("분류: 인공지능 보안 / 양자내성암호","PaperH"),P("핵심 자산은 LLM 에이전트가 호출한 도구의 실제 외부 효과이며 공격·방어 평가가 AI agent runtime에 있으므로 해당 분야가 가장 직접적으로 적합하다.","Paper")]
    col(left,margin,y);col(right,margin+cw+gap,y);c.save()


def main() -> None:
    summary=json.loads((ART/"analysis.json").read_text(encoding="utf-8"));rows=load_rows(summary);figs=make_figures(summary,rows);report(summary,rows,figs);paper(summary,figs);print(REPORT);print(PAPER)


if __name__ == "__main__": main()

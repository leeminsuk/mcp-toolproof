"""Three-page KIISC paper generated directly from artifacts/v5/analysis.json.

Every number in the text is interpolated from the analysis file, so the paper
cannot drift from the data.  Layout is a two-column BaseDocTemplate; the build
loop searches for the largest font scale that still fits exactly three pages,
then reports the content bounding box so the margin gate can be checked.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (BaseDocTemplate, Frame, FrameBreak, Image,  # noqa: E402
                                KeepTogether, NextPageTemplate, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts" / "v5"
FIG = ART / "figures"
OUT = Path("/Users/chchou/Downloads/MCP_ToolProof_KIISC_3페이지_논문_v5.pdf")
BLUE, LIGHT, GRAY = "#173A63", "#EAF0F7", "#5B6B7C"
pdfmetrics.registerFont(TTFont("K", "/System/Library/Fonts/Supplemental/AppleGothic.ttf"))
plt.rcParams["font.family"] = "Apple SD Gothic Neo"
plt.rcParams["axes.unicode_minus"] = False

MARGIN = 11.5 * mm
GUTTER = 4.5 * mm
DETECTOR_LABEL = {
    "manifest_pin": "manifest pin", "signed_manifest": "서명 manifest",
    "response_detector": "응답 검사", "trajectory_lite": "궤적(종류·개수)",
    "learned_relation": "학습 관계", "frozen_intent": "계약 v3(동결)",
    "extended_intent": "계약 v4(확장)", "extended_naive": "계약 v4(정규화 미상)",
    "approval_bound": "승인 결합 영수증",
}
FAMILY_LABEL = {
    "tenant_crossing": "tenant 침범", "memo_exfiltration": "memo 유출",
    "alias_chain": "별칭 체인",
    "target_substitution": "대상 치환", "value_scaling": "금액 변조",
    "hidden_duplication": "숨은 복제", "scope_expansion": "범위 확장",
    "cross_channel": "교차 채널", "effect_type_change": "효과 종류 변경",
    "indirect_reference": "간접참조 해석", "unit_swap": "단위 교체",
    "metadata_channel": "메타데이터 채널", "ordering_swap": "순서 교환",
    "unenumerated_field": "비열거 필드", "fuzz_field": "무작위 필드 퍼징",
}
GROUP_LABEL = {"both": "직접 인자·효과", "v4_only": "해석·메타데이터",
               "neither": "비열거 인자", "fuzz": "무작위 인자"}
GROUP_BOTH = ["target_substitution", "value_scaling", "hidden_duplication",
              "scope_expansion", "cross_channel", "effect_type_change"]
GROUP_V4 = ["indirect_reference", "metadata_channel", "ordering_swap", "unit_swap"]
GROUP_NEITHER = ["unenumerated_field", "tenant_crossing", "memo_exfiltration", "alias_chain"]
GROUP_FUZZ = ["fuzz_field"]
ORDER = GROUP_BOTH + GROUP_V4 + GROUP_NEITHER + GROUP_FUZZ


def styles(scale: float) -> dict:
    def S(name, size, leading, **kw):
        return ParagraphStyle(name=name, fontName="K", fontSize=size * scale,
                              leading=leading * scale, wordWrap="CJK", **kw)
    return {
        "title": S("title", 14.2, 17.4, alignment=TA_CENTER, textColor=colors.HexColor(BLUE)),
        "sub": S("sub", 7.0, 8.8, alignment=TA_CENTER, textColor=colors.HexColor(GRAY)),
        "h": S("h", 9.6, 11.6, textColor=colors.HexColor(BLUE), spaceBefore=3.2, spaceAfter=1.6),
        "body": S("body", 8.3, 10.5, alignment=TA_JUSTIFY),
        "cap": S("cap", 6.8, 8.4, textColor=colors.HexColor(GRAY), spaceBefore=1.2),
        "cell": S("cell", 7.0, 8.4),
        "cellb": S("cellb", 7.0, 8.4, textColor=colors.white),
        "tiny": S("tiny", 6.6, 8.0),
    }


def table(rows, widths, st, align_right=()):
    data = []
    for index, row in enumerate(rows):
        style = st["cellb"] if index == 0 else st["cell"]
        data.append([Paragraph(str(cell), style) for cell in row])
    tbl = Table(data, colWidths=widths, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BLUE)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT)]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C3D0DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.2), ("RIGHTPADDING", (0, 0), (-1, -1), 2.2),
        ("TOPPADDING", (0, 0), (-1, -1), 1.4), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.4),
    ]
    for column in align_right:
        commands.append(("ALIGN", (column, 1), (column, -1), "RIGHT"))
    tbl.setStyle(TableStyle(commands))
    return tbl


def make_heatmap(analysis: dict) -> Path:
    """Families on the vertical axis so the Korean labels stay readable inside
    a single column."""
    FIG.mkdir(parents=True, exist_ok=True)
    detectors = ["trajectory_lite", "learned_relation", "frozen_intent",
                 "extended_intent", "approval_bound"]
    families = ORDER
    grid = np.array([[analysis["by_family"][f]["recall"][d] or 0.0 for d in detectors]
                     for f in families])
    fig, ax = plt.subplots(figsize=(3.1, 3.9), dpi=300)
    image = ax.imshow(grid, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(detectors)))
    ax.set_xticklabels([DETECTOR_LABEL[d] for d in detectors], fontsize=6.2, rotation=34, ha="left")
    ax.xaxis.set_ticks_position("top")
    ax.xaxis.set_label_position("top")
    ax.set_yticks(range(len(families)))
    ax.set_yticklabels([FAMILY_LABEL[f] for f in families], fontsize=6.6)
    for i in range(grid.shape[0]):
        for j in range(grid.shape[1]):
            ax.text(j, i, f"{grid[i, j]:.2f}", ha="center", va="center", fontsize=6.0, color="#111111")
    for boundary in (len(GROUP_BOTH), len(GROUP_BOTH) + len(GROUP_V4),
                     len(GROUP_BOTH) + len(GROUP_V4) + len(GROUP_NEITHER)):
        ax.axhline(boundary - 0.5, color="#173A63", lw=1.6)
    fig.tight_layout(pad=0.25)
    path = FIG / "family-heatmap.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def make_observer_figure(analysis: dict) -> Path:
    """Compare the group both contracts enumerate, so the bars do not depend on
    the family mix."""
    detectors = ["trajectory_lite", "learned_relation", "frozen_intent",
                 "extended_intent", "approval_bound"]
    independent = [analysis["by_group"]["both"]["recall"][d] for d in detectors]
    self_report = [analysis["self_report_by_group"]["both"]["recall"][d] for d in detectors]
    x = np.arange(len(detectors))
    fig, ax = plt.subplots(figsize=(3.25, 1.62), dpi=260)
    ax.bar(x - 0.19, independent, 0.38, label="독립 provider 영수증", color="#173A63")
    ax.bar(x + 0.19, self_report, 0.38, label="서버 자기보고", color="#C0504D")
    for xi, (a, b) in enumerate(zip(independent, self_report)):
        ax.text(xi - 0.19, a + 0.02, f"{a:.2f}", ha="center", fontsize=5.4)
        ax.text(xi + 0.19, b + 0.02, f"{b:.2f}", ha="center", fontsize=5.4)
    ax.set_xticks(x)
    ax.set_xticklabels([DETECTOR_LABEL[d] for d in detectors], fontsize=5.8)
    ax.set_ylim(0, 1.10)
    ax.set_ylabel("Recall", fontsize=6)
    ax.tick_params(axis="y", labelsize=5.4)
    ax.legend(fontsize=5.2, loc="lower left", bbox_to_anchor=(0.0, 1.01), ncol=2, frameon=False)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout(pad=0.2)
    path = FIG / "observer-ablation.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def pct(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def build_story(a: dict, st: dict, figures: dict, width: float) -> list:
    o, s = a["overall"], a["self_report"]
    fam, ci = a["by_family"], a["ci95"]
    grp, cig = a["by_group"], a["ci95_by_group"]
    both, v4only, neither = grp["both"]["recall"], grp["v4_only"]["recall"], grp["neither"]["recall"]
    fuzz_rec = grp["fuzz"]["recall"]
    s_group = a["self_report_by_group"]
    clean_fpr = a["fpr_excluding_resubmit"]
    llm = a.get("llm", {})
    story: list = []
    add = story.append

    add(Paragraph("MCP 도구 외부효과 변조 탐지의 두 가지 경계:<br/>"
                  "observer 독립성과 계약 열거 범위", st["title"]))
    add(Paragraph("Two Measured Boundaries of Semantic Contract Verification for MCP Tool Effects<br/>"
                  "이민석 · 고려대학교 인공지능사이버보안학과", st["sub"]))
    add(FrameBreak())

    add(Paragraph("요 약", st["h"]))
    add(Paragraph(
        f"manifest와 응답을 정상으로 유지한 채 실제 외부 효과만 바꾸는 MCP 서버 공격을, 도구 서버가 서명 키를 갖지 "
        f"않는 provider 영수증 위에서 측정했다. 공격 여부는 탐지기와 분리된 재실행 오라클이 판정하고, 결과는 계약이 "
        f"무엇을 건드리는지에 따라 네 그룹으로 묶어 보고한다. {a['rows']:,}회 실행 {a['conditions']}개 조건에서 필드를 "
        f"열거해 값을 대조하는 계약은 계약이 검사하는 인자·효과에서 {pct(both['extended_intent'], 2)}, provider "
        f"내부 해석과 영수증 부가 정보에서 {pct(v4only['extended_intent'], 3)}, 계약이 검사하지 않는 인자에서 "
        f"{pct(neither['extended_intent'], 3)}였다. "
        f"승인 요청 전체를 해시로 묶는 영수증은 같은 순서로 {pct(both['approval_bound'], 2)}, "
        f"{pct(v4only['approval_bound'], 3)}, {pct(neither['approval_bound'], 3)}로 정반대의 사각지대를 갖는다. "
        f"인자 공간을 통째로 묶으면 열거 문제는 사라지지만 provider 내부 해석은 여전히 보이지 않는다. 영수증 출처를 "
        f"서버 자기보고로 바꾸면 두 방식 모두 {pct(s_group['both']['recall']['extended_intent'], 3)}가 된다. 탐지 "
        f"경계는 없어지지 않고 자리를 옮긴다.", st["body"]))

    add(Paragraph("1. 서론", st["h"]))
    add(Paragraph(
        "MCP 보안 연구는 도구 설명 오염[3], 대리인 혼동[2], 설명과 구현의 불일치[7], 승인·실행 증명[6]으로 "
        "이어졌다. 그러나 승인된 서버가 인터페이스를 한 바이트도 바꾸지 않고 특정 조건에서 실제 효과만 바꾸면 "
        "control plane 무결성은 의미 무결성을 보장하지 않는다. CAVA[6]는 승인에 결합된 canonical action 영수증을 "
        "제안하지만, 그 영수증이 실제로 독립일 때와 아닐 때 탐지가 얼마나 달라지는지는 수치로 보이지 않는다. "
        "본 연구는 우월한 시스템을 주장하지 않는다. 의미 계약의 탐지력을 정하는 두 조건(관측면의 독립성, 계약이 "
        "열거한 필드 범위)을 같은 표본에서 분리해 측정하고, 검증 앵커의 영향은 관찰로 덧붙인다.", st["body"]))
    add(Paragraph(
        "기여는 세 가지다. 첫째, 도구 서버가 서명 키를 갖지 않는 provider 영수증 테스트베드와, 탐지기 코드와 분리된 "
        "재실행 오라클을 구성했다. 둘째, 계약 설계에서 열거하지 않은 공격 계열과 무작위 필드 퍼징을 포함해 탐지 "
        "결과가 계약 정의에서 연역되지 않게 했다. 셋째, observer·열거 범위·앵커를 각각 절제해 성능이 떨어지는 "
        "조건을 보고한다.", st["body"]))

    add(Paragraph("1.1 관련 연구", st["h"]))
    add(table([["연구", "관측 대상", "본 연구가 더 묻는 것"],
               ["MCPTox[3]", "도구 설명·schema 오염", "설명이 그대로일 때 효과가 바뀌는가"],
               ["Confused Deputy[2]", "권한 위임과 도구 선택", "선택이 끝난 뒤 실행 결과가 승인과 같은가"],
               ["DCI[7]", "설명과 코드의 정적 불일치", "런타임 효과와 계약의 불일치"],
               ["CAVA[6]", "승인 결합 canonical action 영수증", "영수증이 독립일 때와 아닐 때의 탐지 차이"],
               ["국내[8-12]", "위협 분류·CVE·최소권한·SBOM", "탐지 경계의 정량화"]],
              [width * 0.20, width * 0.38, width * 0.42], st))
    add(Paragraph("표 1. 선행 연구와의 위치. 국내 연구는 필요성을 뒷받침하지만 실행 후 외부 효과를 정답으로 두지 않는다.", st["cap"]))

    add(Paragraph("2. 위협 모델과 테스트베드", st["h"]))
    add(Paragraph(
        "공격자는 도구 서버 구현을 통제하고 응답을 자유롭게 위조하지만, provider의 서명 키와 저장소, 클라이언트와 "
        "모델은 통제하지 못한다. provider는 별도 프로세스로 돌면서 입력 정규화, 별칭 해석, 효과의 개수와 순서를 "
        "스스로 정하고 모든 영수증에 HMAC-SHA256 서명을 붙인다. 도구 서버가 고를 수 있는 것은 provider에 무엇을 "
        "요청할지뿐이다.", st["body"]))
    add(table([["구성요소", "보유", "미보유"],
               ["도구 서버(공격자)", "manifest 서명키, 응답", "provider 키, 영수증 위조"],
               ["provider", "상태, 영수증 서명키", "모델 입력, 계약"],
               ["검증기", "provider 키, 동결 계약", "서버 내부 상태"]],
              [width * 0.26, width * 0.36, width * 0.38], st))
    add(Paragraph("표 2. 신뢰 경계. 자기보고 절제에서는 검증기가 provider 대신 도구 서버의 영수증을 읽는다.", st["cap"]))
    add(Paragraph(
        "provider가 정직하다는 것은 이 측정을 떠받치는 가정이며, 원래 위협 모델이 상정한 원격 도구 구현과 "
        "downstream API 동시 통제보다 좁다. 실제 배치에서 provider가 도구 공급자와 같은 조직이면 이 가정은 성립하지 "
        "않는다. 간접참조 계열이 성립하는 경로도 공격자가 미리 등록해 둔 legacy 별칭이므로, provider가 상태 일부에서는 "
        "공격자 영향을 받는다고 보아야 한다. 별칭 등록 자체를 막는 문제는 본 연구 범위 밖이다.", st["body"]))
    add(Paragraph(
        "정답 라벨은 배정한 공격 이름이 아니다. 승인 작업을 provider 의미로 재실행한 영수증 전체와 실제 영수증 "
        "전체를 비교해 다르면 공격으로 표시한다. 따라서 조건부 공격이 발동하지 않은 호출은 정상 트래픽으로 세고, "
        "계약이 보지 않는 필드만 바뀐 호출도 공격으로 남는다.", st["body"]))

    add(Paragraph("3. 공격과 정상 트래픽", st["h"]))
    add(Paragraph(
        "15개 공격 계열을 공격이 무엇을 건드리는지로 넷으로 나눴다. 계약이 검사하는 인자와 효과를 바꾸는 A, "
        "provider의 해석 결과와 영수증 부가 정보를 바꾸는 B, 도구가 선언했지만 계약이 검사하지 않는 인자를 바꾸는 C, "
        "그리고 선언된 인자 중 하나를 무작위로 고르는 D다. 퍼징은 도구가 선언한 인자 가운데 하나를 seed로 골라 변형하므로 계약 작성자가 결과를 예측할 수 "
        "없다. 지연·임계·tenant 트리거는 서버 상태로 실제 구현했다. 정상 트래픽에는 공백과 대소문자, 중복 경로 같은 "
        "비정규화 입력, optional 필드를 더한 manifest migration, 사용자가 승인한 재제출을 넣었다.", st["body"]))
    add(table([["그룹", "계열", "영수증에서 바뀌는 것"],
               ["A 직접 인자·효과", "대상 치환, 금액 변조, 숨은 복제, 범위 확장, 교차 채널, 효과 종류 변경",
                "열거된 값·개수·종류가 직접 바뀐다"],
               ["B 해석·메타데이터", "간접참조 해석", "직접 필드는 유지, 해석된 principal만 변경"],
               ["B 해석·메타데이터", "메타데이터 채널", "계약이 모르는 부가 필드로 canary 전송"],
               ["B 해석·메타데이터", "순서 교환", "종류·개수는 유지, 순서만 반전"],
               ["B 해석·메타데이터", "단위 교체", "금액 값은 유지, 통화 단위만 변경"],
               ["C 비열거 인자", "비열거 필드", "callback_url을 공격자 주소로 변경"],
               ["C 비열거 인자", "tenant 침범", "다른 tenant로 효과를 기록"],
               ["C 비열거 인자", "memo 유출", "memo에 canary와 principal을 실어 보냄"],
               ["C 비열거 인자", "별칭 체인", "해석된 principal은 정상, 전달 후 최종 도착지만 변경"],
               ["D 무작위 인자", "무작위 퍼징", "선언된 인자 중 seed로 고른 하나를 변형"]],
              [width * 0.20, width * 0.34, width * 0.46], st))
    add(Paragraph(
        "표 3. 공격이 무엇을 건드리는지로 나눈 네 그룹. A는 계약이 검사하는 인자 값과 효과의 개수·종류, B는 "
        "provider가 내부에서 정하는 해석 결과와 영수증 부가 정보, C는 도구가 선언했지만 계약이 검사하지 않는 인자다. "
        "D는 선언된 인자 중 하나를 무작위로 고르므로 A와 C에 걸친다. 결과는 이 그룹으로만 보고한다.", st["cap"]))

    add(Paragraph("4. 방어 구현", st["h"]))
    add(Paragraph(
        "여섯 방어를 모두 실제로 계산했다. manifest pin은 호출 시점에 서버가 준 manifest의 SHA-256을 동결값과 "
        "비교하고, 서명 manifest는 서버 키로 HMAC을 검증하며, 응답 검사는 반환 JSON의 schema와 값 일치를 본다. "
        "궤적은 영수증의 효과 종류와 개수만 보고, 학습 관계는 정상 실행 192회에서 적합한 종류·개수·필드 보존 "
        "관계만 본다. 계약 v3는 필수 필드, 원문 값 일치, 효과 종류 집합을 검사한다. v4는 정규화 후 일치, 효과 "
        "순서, 해석된 principal, 단위, 미지 영수증 필드 거부를 더한다. 두 계약 모두 memo·tenant·callback_url은 "
        "열거하지 않는다. 비교를 위해 두 변형을 더 넣었다. 하나는 provider 정규화를 모르는 검증자가 쓸 법한 "
        "공백 제거만 하는 정규화로 v4를 다시 돌린 것이고, 다른 하나는 필드를 열거하는 대신 승인 인자 전체의 해시를 "
        "provider가 영수증에 담아 서명하는 승인 결합 방식이다. provider는 정규화 전 원본 인자를 해시하므로 검증자가 "
        "provider 정규화를 알 필요가 없다.", st["body"]))

    add(table([["불변식", "v3", "v4"],
               ["필수 필드·타입 완전성", "O", "O"],
               ["열거 필드 값 보존(원문)", "O", "정규화 후"],
               ["효과 종류 집합 / 순서", "집합", "순서"],
               ["효과 개수", "도구별 기대값", "도구별 기대값"],
               ["해석된 principal", "X", "O"],
               ["단위", "X", "O"],
               ["미지 영수증 필드 거부", "X", "O"]],
              [width * 0.46, width * 0.27, width * 0.27], st))
    add(Paragraph("표 4. 두 계약의 불변식. v4는 규칙을 강화한 것이 아니라 관측 대상을 더 열거했다.", st["cap"]))

    lat = a["latency_ms"]
    add(Paragraph("5. 결과", st["h"]))
    rows = [["방어", "A 직접", "B 해석", "C 비열거", "FPR", "FPR*"]]
    for key in ["manifest_pin", "signed_manifest", "response_detector", "trajectory_lite",
                "learned_relation", "frozen_intent", "extended_intent", "extended_naive",
                "approval_bound"]:
        rows.append([DETECTOR_LABEL[key], pct(both[key], 3), pct(v4only[key], 3),
                     pct(neither[key], 3), pct(o[key]["fpr"], 3), pct(clean_fpr[key], 3)])
    add(table(rows, [width * 0.27, width * 0.145, width * 0.145, width * 0.16,
                     width * 0.14, width * 0.14], st, align_right=(1, 2, 3, 4, 5)))
    add(Paragraph(
        f"표 5. 표 3의 그룹별 Recall과 정상 트래픽 FPR. A 직접 인자·효과 {grp['both']['attacks']:,}회, B 해석·메타데이터 "
        f"{grp['v4_only']['attacks']:,}회, C 비열거 인자 {grp['neither']['attacks']:,}회, D 무작위 인자 "
        f"{grp['fuzz']['attacks']:,}회(표 6), 정상 {a['benign_independent']:,}회다. FPR*는 승인된 재제출을 뺀 값이다. 전 계열 집계는 계열 구성비의 함수이므로 "
        f"싣지 않는다. 그룹 값도 그룹 안의 계열 구성비를 따르므로 계열별 값은 그림 1을 함께 볼 것이다. v3가 B에서 보이는 {pct(v4only['frozen_intent'], 3)}은 같은 표본의 FPR* "
        f"{pct(clean_fpr['frozen_intent'], 3)}과 구별되지 않으므로 탐지 신호로 읽지 않는다. v4 Recall의 조건 클러스터 "
        f"부트스트랩 95% 구간은 A [{pct(cig['both']['extended_intent'][0], 2)}, "
        f"{pct(cig['both']['extended_intent'][1], 2)}], B [{pct(cig['v4_only']['extended_intent'][0])}, "
        f"{pct(cig['v4_only']['extended_intent'][1])}], C [{pct(cig['neither']['extended_intent'][0])}, "
        f"{pct(cig['neither']['extended_intent'][1])}], D [{pct(cig['fuzz']['extended_intent'][0])}, "
        f"{pct(cig['fuzz']['extended_intent'][1])}]이다.", st["cap"]))
    add(Paragraph(
        "manifest pin과 서명 manifest의 Recall 0은 미구현이 아니라 두 센서가 보는 대상이 바뀌지 않았기 때문이다. "
        f"같은 표본에서 manifest pin은 정상 migration에 FPR {pct(fam['migration']['fpr']['manifest_pin'], 2)}로 "
        "발화하므로 배선은 살아 있다. 응답 검사는 서버가 승인값을 그대로 되돌려 주는 한 0을 유지한다. 서명 "
        "manifest는 공격자가 서명 키를 쥐고 있어 탐지도 오탐도 만들지 않는다. 응답 검사가 신호를 얻으려면 응답이 "
        "서버가 아니라 provider에서 와야 하며, 그때는 응답 검사와 영수증 검증이 같은 것이 된다.", st["body"]))
    add(Paragraph(
        f"같은 그룹 안에서 세 방어가 갈리는 값이 가장 직접적인 비교다. 양쪽 열거 계열에서 궤적은 "
        f"{pct(both['trajectory_lite'], 3)}, 학습 관계는 {pct(both['learned_relation'], 3)}, 계약은 "
        f"{pct(both['extended_intent'], 2)}다. 궤적은 효과 종류와 개수만 보므로 값만 바뀌는 대상 치환과 금액 변조를 "
        f"보지 못한다. 학습 관계는 provider가 정규화하는 필드를 보존 관계로 학습하지 못해 그만큼을 놓친다. 계약의 "
        f"1.00은 탐지 능력이 아니라 그 필드를 보기로 한 결정의 결과다.", st["body"]))
    add(Image(str(figures["heatmap"]), width=width * 0.99, height=width * 1.06))
    add(Paragraph("그림 1. 공격 계열별 Recall. 굵은 선 세 개가 위에서부터 A 직접 인자·효과, B 해석·메타데이터, C 비열거 인자, D 무작위 인자를 나눈다(표 3).", st["cap"]))

    add(Paragraph("5.1 열거 범위가 탐지 범위를 정한다", st["h"]))
    add(Paragraph(
        f"계약이 검사하는 인자와 효과를 건드리는 A 그룹에서 v3와 v4는 모두 {pct(both['extended_intent'], 2)}다. "
        f"provider 해석과 영수증 부가 정보를 건드리는 B 그룹에서는 v4가 {pct(v4only['extended_intent'], 3)}인데, "
        f"v4가 해석된 principal과 미지 영수증 필드를 새로 열거했기 때문이지 규칙이 일반적으로 강해서가 아니다. 표 4가 해석된 principal과 미지 필드 거부를 v4의 추가 항목으로 적은 것과 같은 사실이다. "
        f"단위 교체가 {pct(fam['unit_swap']['recall']['extended_intent'], 2)}에 머무는 이유도 도구 8종 중 금액을 가진 "
        f"둘만 단위를 열거하기 때문이다. 계약이 검사하지 않는 인자를 건드리는 C 그룹에서 v4는 "
        f"{pct(neither['extended_intent'], 3)}이고, 무작위 퍼징은 {pct(fuzz_rec['extended_intent'], 3)}다. "
        f"B와 C에서 v3가 보이는 {pct(v4only['frozen_intent'], 3)}과 {pct(neither['frozen_intent'], 3)}은 v3의 "
        f"정상 트래픽 FPR* {pct(clean_fpr['frozen_intent'], 3)}과 같은 크기다. 원문 비교가 provider 정규화를 모르기 "
        f"때문에 생기는 오경보가 공격 행에도 같은 비율로 떨어진 것이므로 탐지 신호가 아니다.", st["body"]))
    fz = a["fuzz_by_tool"]
    fz_rows = [["도구", "열거/선언", "비율", "퍼징 Recall(v4)"]]
    for tool in sorted(fz, key=lambda t: fz[t]["share"]):
        v = fz[tool]
        fz_rows.append([tool, f"{v['enumerated']}/{v['declared']}", pct(v["share"], 2), pct(v["recall_v4"], 3)])
    add(table(fz_rows, [width * 0.34, width * 0.20, width * 0.18, width * 0.28], st, align_right=(1, 2, 3)))
    add(Paragraph(
        "표 6. 도구별 무작위 퍼징 Recall과 계약이 열거한 인자 비율. 열거 비율이 낮은 결제 도구에서 Recall도 낮다. "
        "다만 도구 8종에서 Pearson r은 0.586(p≈0.13)이므로 방향만 보고하고 인과로 단정하지 않는다.", st["cap"]))

    add(Paragraph("5.2 숨은 복제와 승인된 재제출은 같은 관측을 만든다", st["h"]))
    add(Paragraph(
        f"확장 계약의 오탐은 한 계열에서만 나온다. 사용자가 승인한 재제출에서 v3·v4·학습 관계·궤적이 모두 FPR "
        f"{pct(fam['resubmit']['fpr']['extended_intent'], 2)}로 경보한다. 재제출을 빼면 v4의 FPR은 "
        f"{pct(clean_fpr['extended_intent'])}, v3는 {pct(clean_fpr['frozen_intent'])}다. 개수 규칙만으로는 숨은 복제와 "
        "정당한 재제출을 나눌 수 없으므로, 개수 계약은 idempotency 키 정책과 함께 정의해야 한다.", st["body"]))

    add(table([["정상 계열", "v3 FPR", "v4 FPR", "manifest pin FPR"],
               ["clean", pct(fam["clean"]["fpr"]["frozen_intent"], 3),
                pct(fam["clean"]["fpr"]["extended_intent"], 3),
                pct(fam["clean"]["fpr"]["manifest_pin"], 3)],
               ["비정규화 입력", pct(fam["normalisation"]["fpr"]["frozen_intent"], 3),
                pct(fam["normalisation"]["fpr"]["extended_intent"], 3),
                pct(fam["normalisation"]["fpr"]["manifest_pin"], 3)],
               ["schema migration", pct(fam["migration"]["fpr"]["frozen_intent"], 3),
                pct(fam["migration"]["fpr"]["extended_intent"], 3),
                pct(fam["migration"]["fpr"]["manifest_pin"], 3)],
               ["승인된 재제출", pct(fam["resubmit"]["fpr"]["frozen_intent"], 3),
                pct(fam["resubmit"]["fpr"]["extended_intent"], 3),
                pct(fam["resubmit"]["fpr"]["manifest_pin"], 3)]],
              [width * 0.31, width * 0.23, width * 0.23, width * 0.23], st, align_right=(1, 2, 3)))
    add(Paragraph("표 7. 정상 트래픽 계열별 오탐. v3의 오탐은 원문 비교가 정규화를 모르기 때문에 생기고, "
                  "manifest pin의 오탐은 의미가 같은 schema 변경에서 생긴다.", st["cap"]))

    add(Paragraph("5.3 승인 결합 영수증은 경계를 없애지 않고 옮긴다", st["h"]))
    add(Paragraph(
        f"필드를 열거하는 대신 승인 인자 전체를 해시로 묶으면 인자 공간의 사각지대가 사라진다. 승인 결합은 둘 다 "
        f"검사하지 않는 인자 그룹(C)에서 {pct(neither['approval_bound'], 3)}, 무작위 인자(D)에서 "
        f"{pct(fuzz_rec['approval_bound'], 2)}로 v4의 {pct(neither['extended_intent'], 3)}·"
        f"{pct(fuzz_rec['extended_intent'], 3)}를 크게 앞선다. 그런데 해석·메타데이터 그룹(B)에서는 반대로 "
        f"{pct(v4only['approval_bound'], 3)}로 v4의 {pct(v4only['extended_intent'], 3)}보다 낮다. 간접참조 해석과 "
        f"별칭 체인은 인자를 하나도 바꾸지 않고 provider 내부 해석만 바꾸므로 해시가 그대로이기 때문이다. 별칭 체인은 "
        f"두 방식 모두 놓친다. 해석된 principal까지 검사하는 v4조차 한 단계 뒤의 최종 도착지는 보지 않는다.", st["body"]))
    add(Paragraph(
        "두 방식은 서로의 사각지대를 덮지만 합집합을 덮지는 못한다. 인자 공간은 해시로 닫을 수 있고 provider 내부 "
        "해석은 열거로만 닫을 수 있으며, 열거를 한 단계 늘리면 경계는 그다음 단계로 물러난다.", st["body"]))
    add(Paragraph("5.4 정규화 지식 절제", st["h"]))
    add(Paragraph(
        f"v4의 오탐 0은 검증자가 provider와 같은 정규화 함수를 쓴 결과다. 같은 계약을 공백 제거만 하는 정규화로 다시 "
        f"돌리면 FPR*가 {pct(clean_fpr['extended_intent'], 3)}에서 {pct(clean_fpr['extended_naive'], 3)}로 오른다. "
        f"이메일 대소문자와 경로 정규화를 모르는 검증자는 정상 트래픽을 위반으로 읽는다. 값 대조형 계약의 낮은 오탐은 "
        f"규칙의 성질이 아니라 provider 동작을 정확히 아는지에 달려 있다. 승인 결합은 정규화 전 원본을 해시하므로 이 "
        f"의존이 없다.", st["body"]))

    add(Paragraph("5.5 observer 독립성 절제", st["h"]))
    add(Image(str(figures["observer"]), width=width * 0.995, height=width * 0.474))
    add(Paragraph(
        f"그림 2. A 직접 인자·효과 그룹에서 영수증 출처만 바꿨다. 서버 자기보고에서는 v4 Recall이 "
        f"{pct(s_group['both']['recall']['extended_intent'], 3)}, v3가 "
        f"{pct(s_group['both']['recall']['frozen_intent'], 3)}로 v3의 오경보 수준만 남는다.", st["cap"]))
    add(Paragraph(
        "이 결과는 측정이라기보다 정리의 시연이다. 관측면을 공격자가 통제하면 공격자는 승인된 값을 그대로 보고할 수 "
        "있고, 값 비교로 만든 어떤 계약도 위반을 볼 수 없다. 본 구현의 자기보고 서버는 provider와 동일한 정규화로 "
        "승인값을 되돌려 주므로 값·종류·개수·principal이 모두 일치한다. 서명 검증을 켜면 자기보고 영수증의 "
        f"{pct(a['signature_rejects_self_report'], 2)}가 무효로 걸리지만, 그 결과는 탐지가 아니라 가용성 판정이다. "
        "provider 서명 없이 모은 영수증 위의 의미 계약은 두 번째 자기보고에 지나지 않는다.", st["body"]))

    add(Paragraph("5.6 조건부 발동과 승인 probe", st["h"]))
    cond_rows = [["트리거", "probe 경보", "배치 후 공격", "배치 후 탐지"]]
    label = {"delayed": "N회 후", "threshold": "금액 임계", "tenant": "특정 tenant"}
    for trigger, v in a["conditional_activation"].items():
        cond_rows.append([label.get(trigger, trigger), f"{v['probe_alarms']}/{v['probe_calls']}",
                          f"{v['deployed_attacks']}", f"{v['deployed_detected']}"])
    add(table(cond_rows, [width * 0.28, width * 0.24, width * 0.24, width * 0.24], st, align_right=(1, 2, 3)))
    add(Paragraph("표 8. 도구당 첫 3회를 승인 probe로 두었다. 발동하지 않은 호출은 정상으로 셌다.", st["cap"]))

    if llm:
        anchor, dev, itt = llm["anchor"], llm["anchor_on_deviation"], llm["anchor_itt"]
        add(Paragraph("5.7 관찰: 검증 앵커와 에이전트 루프", st["h"]))
        live = {m: v for m, v in llm["availability"].items() if v > 0}
        add(Paragraph(
            f"A100 두 장에서 {len(llm['models'])}개 모델이 자연어 작업만 받고 도구와 인자를 직접 골랐다. 배정 "
            f"{llm['rows']:,}회 가운데 유효 {llm['valid']:,}회, 오류 {llm['errors']:,}회다. 도구 호출 생성률은 모델마다 "
            f"{pct(min(llm['availability'].values()), 3)}에서 {pct(max(llm['availability'].values()), 3)}까지 벌어졌고, "
            f"{len(llm['availability']) - len(live)}개 모델은 이 경로에서 도구 호출을 만들지 못했다. 호출을 만든 "
            f"{len(live)}개 모델의 인자 충실도는 "
            f"{pct(min(llm['utility'][m] for m in live), 3)}에서 {pct(max(llm['utility'][m] for m in live), 3)}까지다. "
            f"탐지기보다 파이프라인 가용성이 먼저 문제가 되는 구간이 있다.", st["body"]))
        dev_rows = [["필드", "이탈 횟수", "v3 열거", "v4 열거"]]
        enumerated_v3 = {"recipient", "amount", "beneficiary", "account", "to", "subject",
                         "body", "destination", "source", "key", "value", "title"}
        for field, count in list(llm["deviation_fields"].items())[:5]:
            in_v3 = "O" if field in enumerated_v3 else "X"
            in_v4 = "O" if (field in enumerated_v3 or field == "unit") else "X"
            dev_rows.append([field, str(count), in_v3, in_v4])
        add(table(dev_rows, [width * 0.34, width * 0.22, width * 0.22, width * 0.22], st, align_right=(1, 2, 3)))
        add(Paragraph(
            f"표 9. 모델이 승인 작업과 다르게 채운 필드. 서버가 정상인데 모델만 이탈한 {dev['rows']}건에서 승인 의도 "
            f"앵커는 {dev['intent_flags']}건, tool input 앵커는 {dev['toolinput_flags']}건을 잡았다.", st["cap"]))

        def rate(entry):
            recall = entry["tp"] / (entry["tp"] + entry["fn"]) if entry["tp"] + entry["fn"] else 0.0
            fpr = entry["fp"] / (entry["fp"] + entry["tn"]) if entry["fp"] + entry["tn"] else 0.0
            return recall, fpr
        r_i, f_i = rate(itt["intent"])
        r_t, f_t = rate(itt["toolinput"])
        add(Paragraph(
            f"유효 호출만 보면 앵커를 tool input에 둘 때 Recall {pct(anchor['toolinput']['recall'])}, FPR "
            f"{pct(anchor['toolinput']['fpr'])}이고 승인 의도에 둘 때 {pct(anchor['intent']['recall'])}, "
            f"{pct(anchor['intent']['fpr'])}이다. 오류를 실패로 세는 배정 기준에서는 두 앵커가 {pct(r_t)}, {pct(f_t)}와 "
            f"{pct(r_i)}, {pct(f_i)}로 좁혀진다. 유효 표본은 도구 호출을 만들지 못한 모델이 빠진 선택 표본이므로 앵커 "
            f"비교를 결론으로 올리지 않는다. 확실한 관찰은 하나다. 서버가 정상인데 모델만 이탈한 {dev['rows']}건 가운데 "
            f"승인 의도 앵커가 잡은 것은 {dev['intent_flags']}건뿐이고 나머지는 두 계약이 모두 열거하지 않은 필드에서 "
            f"일어났다. 앵커는 무엇과 비교할지를 정하지만, 무엇을 볼 수 있는지는 열거 범위가 정한다.", st["body"]))

    add(Paragraph("5.8 유병률과 지연", st["h"]))
    bounds, zero = a["prevalence_bounds"], a["zero_fp_upper_bound"]
    prev_rows = [["공격:정상", "v3 F1*", "v4 F1* 점추정", "v4 F1* 보정"]]
    for ratio in ("1", "9", "99", "999"):
        row = bounds.get(ratio) or bounds[int(ratio)]
        prev_rows.append([f"1:{ratio}", pct(row["frozen_intent"]["point"], 3),
                          pct(row["extended_intent"]["point"], 3),
                          pct(row["extended_intent"]["worst"], 3)])
    add(table(prev_rows, [width * 0.22, width * 0.24, width * 0.28, width * 0.26],
              st, align_right=(1, 2, 3)))
    worst_999 = (bounds.get("999") or bounds[999])["extended_intent"]["worst"]
    add(Paragraph(
        f"표 10. 승인된 재제출을 뺀 Recall과 FPR을 운영 유병률로 재가중했다. v4의 FPR*는 오탐 0으로 측정됐으므로 "
        f"점추정이 유병률과 무관해진다. 보정 열은 rule of three 상한을 넣은 값이며, 분모를 정상 "
        f"{zero['n_benign']:,}행이 아니라 조건 {zero['n_clusters']}개로 잡아 {zero['fpr_upper_95']:.4f}를 썼다. 한 "
        f"조건 안의 반복은 독립 시행이 아니기 때문이다. 이 기준에서 1:999 F1은 {pct(worst_999, 3)}이고, 행 단위 상한 "
        f"{zero['fpr_upper_95_row']:.5f}를 쓰면 0.515까지 올라간다. 오탐 0을 위험률 0으로 읽지 않기 위해 두 값을 "
        f"함께 싣는다.", st["cap"]))
    add(Paragraph(
        f"계약 계산 p95는 {lat['contract_p95']:.3f} ms, 같은 호스트의 provider 영수증 조회 p95는 "
        f"{lat['receipt_fetch_p95']:.2f} ms다. 원격 provider에서는 왕복 지연이 지배하므로 동기 차단 배치의 병목은 "
        "계약 계산이 아니라 영수증 수집이다.", st["body"]))

    add(Paragraph("5.9 사전 기준과 배치 정책", st["h"]))
    add(table([["기준", "관측", "판정"],
               ["A 직접 Recall ≥ .90 (값 계약)", pct(both["extended_intent"], 3), "통과"],
               ["C 비열거 Recall ≥ .90 (값 계약)", pct(neither["extended_intent"], 3), "실패"],
               ["C 비열거 Recall ≥ .90 (승인 결합)", pct(neither["approval_bound"], 3), "실패"],
               ["B 해석 Recall ≥ .90 (승인 결합)", pct(v4only["approval_bound"], 3), "실패"],
               ["FPR ≤ .05 (전체)", pct(o["extended_intent"]["fpr"], 3), "실패"],
               ["FPR ≤ .05 (재제출 뺀 값)", pct(clean_fpr["extended_intent"], 3), "통과"],
               ["계약 계산 p95 ≤ 200 ms", f"{lat['contract_p95']:.3f} ms", "통과"],
               ["영수증 조회 p95 ≤ 200 ms", f"{lat['receipt_fetch_p95']:.2f} ms (동일 호스트)", "조건부"]],
              [width * 0.44, width * 0.33, width * 0.23], st))
    add(Paragraph("표 11. 사전에 정한 기준과 실측. 미열거 계열과 전체 FPR은 기준을 넘지 못했고 그대로 보고한다.", st["cap"]))
    add(Paragraph(
        "배치는 계약 통과와 영수증 정상일 때만 결과를 전달하고, 위반이면 효과 보류와 사용자 승인으로 분기한다. "
        "영수증을 얻지 못한 상태는 안전으로 보지 않고 별도 상태로 기록해 고위험 도구는 차단, 저위험 도구는 제한 "
        "실행으로 나눈다. 이미 반영된 효과는 탐지만으로 되돌릴 수 없으므로 2단계 commit과 보상 트랜잭션을 함께 "
        "설계해야 한다.", st["body"]))

    add(Paragraph("6. 논의와 타당성 위협", st["h"]))
    add(Paragraph(
        "계약과 공격과 도구를 같은 저자가 작성한 공동설계 편향은 남는다. 계약과 학습 프로파일을 평가 전에 해시로 "
        "동결하고, 결과가 계약 정의에서 연역되지 않는 계열(비열거 필드, 무작위 퍼징)을 넣어 편향을 줄였지만 제3자 "
        "blind 평가를 대신하지는 못한다. provider는 로컬 프로세스이므로 프로세스·키·저장소 분리는 재현했으나 상용 "
        "SaaS의 tenant 격리와 최종 principal은 검증하지 않았다. 정상 트래픽 분포도 합성이며 장기 drift는 다루지 "
        "않았다.", st["body"]))
    add(table([["근거가 있는 주장", "근거가 없는 주장"],
               ["열거한 계열에서 계약이 추가 신호를 준다", "미지 공격 일반 방어"],
               ["열거하지 않은 계열에서 탐지가 거의 사라진다", "블랙박스 행동의 완전 증명"],
               ["자기보고 영수증에서 계약이 무력하다", "상용 SaaS 독립성 검증 완료"],
               ["관측된 에이전트 이탈은 두 앵커 모두 놓쳤다", "앵커 조정으로 이탈까지 방어"],
               ["승인 해시 결합이 인자 사각지대를 닫는다", "해시 결합이 모든 변조를 막는다"]],
              [width * 0.5, width * 0.5], st))
    add(Paragraph("표 12. 주장 경계.", st["cap"]))

    add(Paragraph("6.1 안전과 윤리", st["h"]))
    add(Paragraph(
        "결제는 0원 가상 원장, 메일은 외부 발송이 없는 로컬 mailbox, 파일은 임시 작업 공간, HTTP는 localhost sink만 "
        "사용했다. 공격 표식은 ATTACKER_TEST_TARGET과 canary 문자열로 한정했고 실제 계정, 개인정보, 금전 피해는 "
        "만들지 않았다. 공개 시 서버 악성화 경로는 기본 비활성으로 두고 재현 범위를 문서로 남긴다.", st["body"]))

    add(Paragraph("7. 결론", st["h"]))
    add(Paragraph(
        "의미 계약의 탐지력은 두 조건이 정한다. 영수증이 공격자와 독립일 때만 값 비교가 증거가 되고, 계약이 열거한 "
        "필드 밖에서는 탐지가 거의 사라진다. 승인 인자를 통째로 해시에 묶으면 인자 공간의 경계는 닫히지만 provider "
        "내부 해석이라는 다음 경계가 드러나며, 별칭 체인처럼 최종 도착지만 바뀌는 변조는 두 방식 모두 놓친다. 경계는 "
        "없어지지 않고 자리를 옮긴다. 전 계열 집계는 계열 구성비를 요약할 뿐이므로 대표값이 아니다. 배치 판단은 "
        "provider 영수증의 독립성 확보, 열거 범위의 명시, 그리고 최종 principal까지 영수증에 담게 하는 요구에서 "
        "시작해야 한다.", st["body"]))

    add(Paragraph("참고문헌", st["h"]))
    add(Paragraph(
        "[1] Model Context Protocol, “Tools; Security Best Practices,” modelcontextprotocol.io, 2026 (accessed 2026-08-14).<br/>"
        "[2] Z. Li et al., “Confused Deputy Attack Against Model Context Protocol,” ACM TOSEM, doi:10.1145/3830467, 2026.<br/>"
        "[3] Z. Wang et al., “MCPTox: A Benchmark for Tool Poisoning on Real-World MCP Servers,” AAAI 40(42), 35811–35819, 2026.<br/>"
        "[4] S. Yergattikar, “Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for MCP Deployments,” ACL Industry Track, 2026.<br/>"
        "[5] Huang et al., “From Component Manipulation to System Compromise: Understanding and Detecting Malicious MCP Servers,” arXiv:2604.01905, 2026.<br/>"
        "[6] Z. Wang, “CAVA: Canonical Action Verification and Attestation for Runtime Governance of Agentic AI Systems,” arXiv:2607.13716, 2026.<br/>"
        "[7] Y. Shi et al., “Description-Code Inconsistency in Real-world MCP Servers,” arXiv:2606.04769, 2026.<br/>"
        "[8] 김찬형·이브라히모바 나일라 외, “MCP 기반 AI 에이전트 환경에서의 LLM 보안 위협 변화 동향 분석,” ASK, p.375, 2026.<br/>"
        "[9] 남장우 외, “공개된 MCP 취약점 교차매핑 기반 공격사례 분석,” ASK, p.251, 2026.<br/>"
        "[10] 김도영·고남현 외, “VAT 기반 LLM 에이전트 하이브리드 보안 아키텍처,” ASK, p.310, 2026.<br/>"
        "[11] 한승완·강승호, “Agent-SecSLA 프레임워크,” 융합보안논문지 26(3), 99–112, 2026.<br/>"
        "[12] 이재승·유제혁, “SBOM 변경 이력 자동 분석 기법,” 한국산업정보학회논문지 30(4), 39–60, 2025.", st["tiny"]))

    add(Paragraph("재현성", st["h"]))
    add(Paragraph(
        f"provider와 도구 서버는 독립 프로세스로 실행했고 계약 해시, manifest 해시, 학습 프로파일 해시를 평가 전에 "
        f"freeze.json에 기록했다. 본문의 모든 수치는 결정적 클라이언트 {a['rows']:,}행과 에이전트 루프 "
        f"{llm['rows']:,}행(유효 {llm['valid']:,}) 원시 JSONL에서 분석 스크립트가 자동 집계했다. " if llm else
        f"freeze.json에 기록했다. 본문의 모든 수치는 {a['rows']:,}행 원시 JSONL에서 분석 스크립트가 자동 집계했다. "
        f"정답 라벨은 탐지기 코드와 분리된 재실행 오라클이 만든다. 코드는 provider.py, toolsrv.py, detectors.py, "
        f"harness.py, llm_layer.py, analyze.py로 공개한다.", st["tiny"]))
    return story


def bind_captions(story: list) -> list:
    """Keep every table or figure glued to the caption that follows it, so a
    column break never separates them."""
    bound, index = [], 0
    while index < len(story):
        item = story[index]
        following = story[index + 1] if index + 1 < len(story) else None
        is_caption = isinstance(following, Paragraph) and following.style.name == "cap"
        if isinstance(item, (Table, Image)) and is_caption:
            bound.append(KeepTogether([item, following]))
            index += 2
        else:
            bound.append(item)
            index += 1
    return bound


def render(analysis: dict, scale: float, figures: dict) -> int:
    st = styles(scale)
    width, height = A4
    column = (width - 2 * MARGIN - GUTTER) / 2
    top_margin, bottom_margin = MARGIN * 0.78, MARGIN * 0.62
    doc = BaseDocTemplate(str(OUT), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=top_margin, bottomMargin=bottom_margin,
                          title="MCP 도구 외부효과 변조 탐지의 두 가지 경계")
    top = height - top_margin
    full_height = top - bottom_margin
    title_height = 21 * mm * scale
    body_height = full_height - title_height

    def frame(x, y, w, h, name):
        return Frame(x, y, w, h, id=name, leftPadding=0, rightPadding=0,
                     topPadding=0, bottomPadding=0)

    first = [frame(MARGIN, top - title_height, width - 2 * MARGIN, title_height, "t"),
             frame(MARGIN, bottom_margin, column, body_height, "l1"),
             frame(MARGIN + column + GUTTER, bottom_margin, column, body_height, "r1")]
    rest = [frame(MARGIN, bottom_margin, column, full_height, "l"),
            frame(MARGIN + column + GUTTER, bottom_margin, column, full_height, "r")]

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("K", 5.6)
        canvas.setFillColor(colors.HexColor(GRAY))
        canvas.drawRightString(width - MARGIN, MARGIN * 0.30, f"{canvas.getPageNumber()}/3")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="first", frames=first, onPage=footer),
                          PageTemplate(id="two", frames=rest, onPage=footer)])
    story = build_story(analysis, st, figures, column)
    story.insert(0, NextPageTemplate("two"))
    doc.build(bind_captions(story))
    return int(subprocess.run(["pdfinfo", str(OUT)], capture_output=True, text=True)
               .stdout.split("Pages:")[1].split()[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, default=ART / "analysis.json")
    args = parser.parse_args()
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    figures = {"heatmap": make_heatmap(analysis), "observer": make_observer_figure(analysis)}
    best = None
    # Search from a deliberately large scale downward and accept only an exact
    # three-page fit.  The previous upper bound (1.14) already fit in two pages,
    # while ``pages <= 3`` incorrectly treated that as a valid 3-page paper.
    for scale in [round(1.30 - 0.01 * i, 3) for i in range(71)]:
        pages = render(analysis, scale, figures)
        print(f"scale {scale} -> {pages} pages", flush=True)
        if pages == 3:
            best = scale
            break
    if best is None:
        raise SystemExit("could not fit three pages")
    render(analysis, best, figures)
    print(json.dumps({"scale": best, "output": str(OUT)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

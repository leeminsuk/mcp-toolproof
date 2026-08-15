"""Three-page KIISC paper generated directly from artifacts/v5/analysis.json.

Every number in the text is interpolated from the analysis file, so the paper
cannot drift from the data.  Layout is a two-column BaseDocTemplate; the build
loop searches for the largest font scale that still fits exactly three pages,
then reports the content bounding box so the margin gate can be checked.
"""
from __future__ import annotations

import argparse
import json
import os
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
OUT = Path.home() / "Downloads" / "MCP_ToolProof_KIISC_3페이지_논문_v5.pdf"
BLUE, LIGHT, GRAY = "#173A63", "#EAF0F7", "#5B6B7C"


def _korean_font_path() -> str:
    """First Hangul-capable TTF found, so the build runs on macOS and Windows
    alike; TOOLPROOF_KR_FONT overrides the search."""
    candidates = [
        os.environ.get("TOOLPROOF_KR_FONT", ""),
        "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
        "C:/Windows/Fonts/malgun.ttf",
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise SystemExit("no Korean font found; set TOOLPROOF_KR_FONT to a TTF path")


if "K" not in pdfmetrics.getRegisteredFontNames():
    pdfmetrics.registerFont(TTFont("K", _korean_font_path()))
plt.rcParams["font.family"] = ["Apple SD Gothic Neo", "Malgun Gothic", "NanumGothic"]
plt.rcParams["axes.unicode_minus"] = False

MARGIN = 11.5 * mm
GUTTER = 4.5 * mm
DETECTOR_LABEL = {
    "manifest_pin": "manifest pin", "signed_manifest": "서명 manifest",
    "response_detector": "응답 검사", "trajectory_lite": "궤적(종류·개수)",
    "learned_relation": "학습 관계", "frozen_intent": "계약 v3(동결)",
    "extended_intent": "계약 v4(확장)", "extended_naive": "v4(정규화 미상)",
    "approval_bound": "승인 결합", "approval_naive": "승인 결합(직렬화 미상)",
    "union_v4_approval": "합성(v4 ∨ 승인)",
}
FAMILY_LABEL = {
    "tenant_crossing": "tenant 침범", "memo_exfiltration": "memo 유출",
    "alias_chain": "별칭 체인", "route_diversion": "정산 경로 우회",
    "ledger_account_swap": "정산 계정 교체",
    "target_substitution": "대상 치환", "value_scaling": "값 변조",
    "hidden_duplication": "숨은 복제", "scope_expansion": "범위 확장",
    "cross_channel": "교차 채널", "effect_type_change": "효과 종류 변경",
    "indirect_reference": "간접참조 해석", "unit_swap": "단위 교체",
    "metadata_channel": "메타데이터 채널", "ordering_swap": "순서 교환",
    "unenumerated_field": "비열거 필드", "fuzz_field": "무작위 필드 퍼징",
}
GROUP_LABEL = {"both": "A 직접 인자·효과", "v4_only": "B 해석·메타데이터",
               "neither": "C 비열거 인자", "unseen": "D 비열거 영수증 경로",
               "fuzz": "E 무작위 인자"}
# Group letters live next to the analysis keys so a bootstrap interval can
# never be printed under the wrong letter.  The previous revision hard-coded
# the four intervals in prose and labelled the fuzz interval as D.
GROUP_LETTER = {"both": "A", "v4_only": "B", "neither": "C", "unseen": "D", "fuzz": "E"}
GROUP_ORDER = ["both", "v4_only", "neither", "unseen", "fuzz"]
DRIFT_LABEL = {"none": "없음(기준)", "receipt_annotation": "영수증 주석 추가",
               "normalisation_upgrade": "정규화 강화", "unicode_nfc": "Unicode NFC",
               "hash_basis_change": "해시 기준 변경"}
GROUP_BOTH = ["target_substitution", "value_scaling", "hidden_duplication",
              "scope_expansion", "cross_channel", "effect_type_change"]
GROUP_V4 = ["indirect_reference", "metadata_channel", "ordering_swap", "unit_swap"]
GROUP_NEITHER = ["unenumerated_field", "tenant_crossing", "memo_exfiltration"]
GROUP_UNSEEN = ["alias_chain", "route_diversion", "ledger_account_swap"]
GROUP_FUZZ = ["fuzz_field"]
ORDER = GROUP_BOTH + GROUP_V4 + GROUP_NEITHER + GROUP_UNSEEN + GROUP_FUZZ


def styles(scale: float) -> dict:
    def S(name, size, leading, **kw):
        return ParagraphStyle(name=name, fontName="K", fontSize=size * scale,
                              leading=leading * scale, wordWrap="CJK", **kw)
    return {
        "title": S("title", 14.2, 17.4, alignment=TA_CENTER, textColor=colors.HexColor(BLUE)),
        "sub": S("sub", 7.0, 8.8, alignment=TA_CENTER, textColor=colors.HexColor(GRAY)),
        "h": S("h", 9.6, 11.6, textColor=colors.HexColor(BLUE), spaceBefore=3.2, spaceAfter=1.6),
        "body": S("body", 8.3, 10.5, alignment=TA_JUSTIFY),
        # Captions and the reference block were called out as too small to
        # read in the previous revision, so both sit higher than before.
        "cap": S("cap", 7.2, 8.8, textColor=colors.HexColor(GRAY), spaceBefore=1.2),
        "cell": S("cell", 7.0, 8.4),
        "cellb": S("cellb", 7.0, 8.4, textColor=colors.white),
        # References and the reproducibility note were called out as too small
        # to read, so they sit closer to body size than to caption size.
        "tiny": S("tiny", 7.5, 9.1),
        "formula": ParagraphStyle(name="formula", fontName="Courier",
                                  fontSize=6.9 * scale, leading=9.4 * scale,
                                  spaceBefore=2 * scale, spaceAfter=2 * scale),
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
    detectors = ["learned_relation", "frozen_intent", "extended_intent", "approval_bound"]
    families = ORDER
    grid = np.array([[analysis["by_family"][f]["recall"][d] or 0.0 for d in detectors]
                     for f in families])
    fig, ax = plt.subplots(figsize=(3.1, 4.3), dpi=300)
    image = ax.imshow(grid, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(detectors)))
    ax.set_xticklabels([DETECTOR_LABEL[d] for d in detectors], fontsize=7.6, rotation=34, ha="left")
    ax.xaxis.set_ticks_position("top")
    ax.xaxis.set_label_position("top")
    ax.set_yticks(range(len(families)))
    # Number the families so a reader can match a row against table 4.
    ax.set_yticklabels([f"{i + 1}. {FAMILY_LABEL[f]}" for i, f in enumerate(families)], fontsize=7.6)
    for i in range(grid.shape[0]):
        for j in range(grid.shape[1]):
            ax.text(j, i, f"{grid[i, j]:.2f}", ha="center", va="center", fontsize=7.4,
                    color="#111111")
    edges, total = [], 0
    for block in (GROUP_BOTH, GROUP_V4, GROUP_NEITHER, GROUP_UNSEEN):
        total += len(block)
        edges.append(total)
    for boundary in edges:
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


# Korean particles agree with the sound of the preceding syllable, and every
# number in this paper is interpolated from the data, so the particle has to be
# chosen from the value rather than typed.  A decimal is read digit by digit;
# 0·1·3·6·7·8 end in a consonant (영·일·삼·육·칠·팔), 2·4·5·9 in a vowel.
_CONSONANT_FINAL = set("013678")
# 일·칠·팔 end in the consonant ㄹ, which takes 로 rather than 으로 — the one
# exception to the consonant rule, and the source of "0.078으로" in an earlier
# revision.
_RIEUL_FINAL = set("178")


def jo(text: str, pair: str) -> str:
    """``pair`` is "consonant-final form/vowel-final form", e.g.
    ``jo(x, "은/는")`` -> "은" after 0.000, "는" after 0.769.  The two forms are
    not always one character each ("으로/로"), so they are separated explicitly
    rather than split down the middle."""
    consonant_form, vowel_form = pair.split("/")
    digits = [c for c in text if c.isdigit()]
    last = digits[-1] if digits else ""
    if consonant_form.endswith("으로") and last in _RIEUL_FINAL:
        return vowel_form
    return consonant_form if last in _CONSONANT_FINAL else vowel_form


def num(value: float, pair: str, digits: int = 3) -> str:
    """A formatted number followed by the particle its reading requires."""
    text = pct(value, digits)
    return text + jo(text, pair)


def fig_image(path: Path, width: float) -> Image:
    """Place a figure at column width without distorting it."""
    from reportlab.lib.utils import ImageReader
    pixel_width, pixel_height = ImageReader(str(path)).getSize()
    return Image(str(path), width=width, height=width * pixel_height / pixel_width)


def build_story(a: dict, st: dict, figures: dict, width: float) -> list:
    o = a["overall"]
    fam, ci = a["by_family"], a["ci95"]
    grp, cig = a["by_group"], a["ci95_by_group"]
    both, v4only, neither = grp["both"]["recall"], grp["v4_only"]["recall"], grp["neither"]["recall"]
    unseen = grp["unseen"]["recall"]
    fuzz_rec = grp["fuzz"]["recall"]
    s_group = a["self_report_by_group"]
    clean_fpr = a["fpr_excluding_resubmit"]
    llm = a.get("llm_local") or a.get("llm") or {}
    story: list = []
    add = story.append

    dec = a["sample_decomposition"]
    drift = a.get("drift", {})
    real = a.get("real_mcp")
    hold = a.get("holdout")
    orc = a["oracle"]
    rel = a.get("release", {})
    pin = a["manifest_pin_decomposition"]

    add(Paragraph("MCP 도구 외부효과 검증의 사각지대 분해:<br/>"
                  "관측면 독립성 · 인자 결합 · 영수증 의미 범위", st["title"]))
    add(Paragraph("Decomposing the Blind Spots of MCP Tool-Effect Verification: "
                  "Observer Independence, Argument Commitment, and Receipt Semantic Coverage<br/>"
                  "이민석 · 고려대학교 인공지능사이버보안학과", st["sub"]))
    add(FrameBreak())

    add(Paragraph("요 약", st["h"]))
    add(Paragraph(
        f"AI 에이전트가 MCP 도구로 결제·메일·파일을 실행할 때, 승인된 서버는 manifest와 응답을 정상으로 유지한 채 "
        f"실제 외부 효과만 바꿀 수 있다. 본 연구는 같은 workload에서 세 축(관측면 독립성, 승인 인자의 해시 결합, "
        f"계약이 열거한 영수증 의미 범위)이 만드는 사각지대가 서로를 보완한다는 것을 분해해 측정한다. 우월한 방어의 "
        f"제안이 아니다. 영수증은 실제 효과를 집행하는 하위 실행계(이하 provider)가 Ed25519로 서명하고 검증기는 "
        f"공개키만 가지므로 도구 서버도 검증기도 영수증을 위조할 수 없다. 정답 라벨은 코드를 공유하지 않는 두 "
        f"프로그램이 각각 계산했고 {orc['rows'] + hold['oracle']['rows']:,}행 전부에서 일치했다. 결정적 실행 "
        f"{dec['rows']:,}회(관측면당 {dec['per_observer']:,}회)에서, 필드를 열거해 값을 대조하는 계약의 Recall은 "
        f"계약이 검사하는 인자·효과에서 {pct(both['extended_intent'], 2)}, provider 해석·메타데이터에서 "
        f"{pct(v4only['extended_intent'], 3)}, 계약이 검사하지 않는 인자에서 "
        f"{num(neither['extended_intent'], '이고/고')}, 승인 요청 전체를 해시로 묶는 영수증은 같은 순서로 "
        f"{pct(both['approval_bound'], 2)}, {pct(v4only['approval_bound'], 3)}, "
        f"{num(neither['approval_bound'], '으로/로')} 정반대의 사각지대를 갖는다. 두 1.00은 성능이 아니라 각 방식이 그 "
        f"필드를 보기로 한 정의의 결과다. 영수증에 남지만 어느 계약도 열거하지 않는 처리 경로는 두 방식이 함께 놓쳐 "
        f"각각 {pct(unseen['extended_intent'], 3)}, {pct(unseen['approval_bound'], 3)}에 그쳤고, 두 판정을 OR로 "
        f"합성해도 이 그룹만 {num(unseen['union_v4_approval'], '으로/로')} 남는다. 같은 구조가 공개 MCP 서버 "
        f"{len(hold['meta']['provenance'])}종의 발행 스키마에서 기계적으로 유도한 도구 {hold['tools']}개 표 위에서 "
        f"{hold['independent']:,}행으로 재현됐고(계약은 발행자가 쓴 required 목록), 공식 MCP SDK 전송 위에서도 "
        f"재현됐다. 낮은 오탐도 무조건적이지 않다. provider가 영수증에 릴리스 태그를 덧붙이는 변화 하나만으로 값 "
        f"대조 계약의 오탐이 "
        f"{num(drift.get('receipt_annotation', {}).get('fpr', {}).get('extended_intent', 0), '으로/로', 2)} 뛴다. "
        f"경계는 없어지지 않고 자리를 옮긴다.", st["body"]))

    add(Paragraph("1. 서론", st["h"]))
    add(Paragraph(
        "MCP 보안 연구는 도구 설명 오염[3], 대리인 혼동[2], 설명과 구현의 불일치[7], 승인·실행 증명[6]으로 "
        "이어졌다. 그러나 승인된 서버가 인터페이스를 한 바이트도 바꾸지 않고 특정 조건에서 실제 효과만 바꾸면 "
        "control plane 무결성은 의미 무결성을 보장하지 않는다. CAVA[6]는 승인에 결합된 canonical action 영수증을 "
        "제안하고 자체 벤치마크로 결합·재현성을 평가하지만, 그 영수증이 공격자와 독립일 때와 아닐 때 탐지가 얼마나 "
        "달라지는지는 수치로 보이지 않는다. 본 연구는 우월한 시스템을 주장하지 않는다. 측정하는 것은 방어의 순위가 "
        "아니라 사각지대의 분해다.", st["body"]))
    add(Paragraph(
        f"기여는 세 가지다. 첫째, 세 축의 사각지대가 상호 보완적임을 같은 표본에서 분해했다. 관측면을 자기보고로 "
        f"바꾸면 값 비교가 전부 무너지고, 인자 해시 결합은 비열거 인자를 닫는 대신 provider 해석을 열며, 열거 확장은 "
        f"그 반대다. 둘째, 그 분해가 본 테스트베드의 산물이 아님을 두 가지로 확인했다. 공개된 MCP 서버 "
        f"{len(hold['meta']['provenance'])}종의 발행 스키마를 그대로 도구 표로 바꾸고 계약을 발행자의 required "
        f"목록에서 기계적으로 유도해 다시 측정했고, 같은 공격·같은 오라클을 공식 MCP SDK의 stdio 전송 위에서 다시 "
        f"돌렸다. 셋째, 정답 라벨을 코드를 공유하지 않는 두 구현으로 계산하고 전 행 일치를 검사했다. 각 방식의 낮은 "
        f"오탐이 무엇에 의존하는지는 검증자 절제와 provider 변화(drift)로 측정했다.", st["body"]))

    add(Paragraph(
        "고전 RPC에도 프록시, 혼동된 대리인, TOCTOU, downstream 변조는 있다. 다만 그때는 요청을 만든 주체와 승인한 "
        "주체가 같았다. 에이전트는 자연어 의도를 도구 호출로 바꾸는 의미 변환 계층을 하나 더 넣어 불일치가 생길 수 "
        "있는 지점을 넓힌다. 사용자 의도, 모델이 만든 도구 호출, 서버가 provider에 보낸 요청, provider가 실제로 남긴 "
        "효과가 네 지점에서 갈릴 수 있고, 무엇을 승인의 기준으로 삼을지가 먼저 정해져야 한다. 공격자가 manifest를 한 "
        "바이트도 바꾸지 않는 동기도 여기서 나온다. 선행 연구는 대부분 실행 이전을 본다. MCPTox[3]는 도구 설명과 "
        "schema 오염을, Confused Deputy[2]는 권한 위임과 도구 선택을, DCI[7]는 설명과 코드의 정적 불일치를 "
        "관측하며, 호출·응답을 가로채 검증하는 런타임 방어[4]와 악성 서버 탐지[5]도 도구 호출·응답과 실행 중 행위를 "
        "보고, 국내 연구[8-12]는 위협 분류·CVE·최소권한·SBOM으로 필요성을 뒷받침하되 실행 후 외부 효과를 정답으로 "
        "두지 않는다. 규범 쪽도 같다. 공식 MCP 보안 문서[1]의 ‘공격과 완화’ 절은 항목 11개(혼동된 대리인, 토큰 "
        "패스스루, SSRF, 상태 핸들 탈취, 로컬 서버 침해, OAuth URL 검증, stdio 프록시 권한상승, mix-up, localhost "
        "리다이렉트 사칭, CIMD 신뢰 정책, 스코프 최소화)를 열거하는데 <b>전부 인가·전송·프록시 계층이고, 인가된 "
        "서버가 승인된 것과 다른 효과를 실행하는 경우는 한 항목도 없다.</b> 본 연구가 다루는 것이 그 자리다.",
        st["body"]))

    add(Paragraph("2. 위협 모델과 테스트베드", st["h"]))
    add(Paragraph(
        "공격자는 도구 서버 구현을 통제하고 응답을 자유롭게 위조하지만, provider의 개인키와 저장소, 클라이언트와 "
        "모델은 통제하지 못한다. 도구 서버는 manifest 서명 개인키만 갖고 provider 개인키는 갖지 못하므로 영수증을 "
        "발행하거나 지울 수 없다. provider는 별도 프로세스로 돌면서 입력 정규화, 별칭 해석, 효과의 개수와 순서를 "
        "스스로 정하고 모든 영수증에 Ed25519 개인키로 서명하며, 검증기는 공개키만 갖는다. 이는 표기 문제가 아니다. "
        "공유키 MAC은 검증 키가 곧 발행 키여서 검증기도 영수증을 만들 수 있고, 그러면 ‘독립 검증 가능한 영수증’이 "
        "기제보다 강한 말이 된다. 서명 대상에는 의미 필드 아홉 개와 함께 상관 ID·순번·nonce·발급시각을 묶어 정직한 "
        "호출의 영수증을 다른 호출에 재사용하지 못하게 했고, 검증기는 서명·상관 ID·순번 연속성을 함께 본다. 실제 "
        "배치라면 공개키 배포와 교체 정책이 더 필요하나 본 연구는 다루지 않는다. 자기보고 절제(5.1)에서는 검증기가 "
        "provider 대신 도구 서버가 내놓은 영수증을 읽는다.", st["body"]))
    add(Paragraph(
        "provider가 정직하다는 것은 이 측정을 떠받치는 가정이며, 원래 위협 모델이 상정한 원격 도구 구현과 "
        "downstream API 동시 통제보다 좁다. 실제 배치에서 provider가 도구 공급자와 같은 조직이면 이 가정은 성립하지 "
        "않는다. 간접참조 계열이 성립하는 경로도 공격자가 미리 등록해 둔 legacy 별칭이므로, provider가 상태 일부에서는 "
        "공격자 영향을 받는다고 보아야 한다.", st["body"]))

    add(Paragraph("2.1 정답 오라클을 두 번 구현했다", st["h"]))
    add(Paragraph(
        "정답 라벨은 배정한 공격 이름이 아니다. 호출 c에 대해 아래와 같이 정의한다.", st["body"]))
    add(Paragraph("truth(c) = [ canonical(Replay(op, approved, m))<br/>&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;!= canonical(proj_S(Receipts(cid))) ]", st["formula"]))
    add(Paragraph(
        f"여기서 Replay는 provider 자신의 영수증 생성 함수를 빈 별칭표 위에서 승인 인자에 적용한 것이고, m은 "
        f"사용자가 승인한 제출 횟수, proj_S는 기록된 영수증을 의미 필드 집합 S로 사영한 것이다. S는 "
        f"op·kind·args·해석된 principal·최종 principal·정산 경로·정산 계정·승인 해시·부가 필드 아홉 개이고, 비교는 "
        f"영수증 전체 순열에 대한 완전 일치다. 그런데 이 정의만으로는 라벨이 provider 코드에 의존한다. 생성 함수에 "
        f"결함이 있으면 기록된 영수증과 기대 영수증이 같은 방향으로 틀어져 라벨이 그것을 볼 수 없다. 그래서 같은 "
        f"라벨을 코드를 공유하지 않는 두 번째 프로그램으로 다시 계산했다. 이 프로그램은 기대 영수증을 만들지 않고, "
        f"발행된 도구 표에서 유도한 불변식 {orc['invariants_defined']}개(효과 개수·종류 순서·연산 이름·인자 값·"
        f"인자 집합·해석된 principal·전달 여부·정산 경로·정산 계정·승인 해시·주석)를 기록된 영수증 위에서 직접 "
        f"검사한다. 정규화도 해시도 자기 코드로 다시 구현했다. 두 라벨은 본 행렬 {orc['rows']:,}행과 hold-out "
        f"{hold['oracle']['rows']:,}행 전부에서 일치했고(불일치 {orc['disagreements'] + hold['oracle']['disagreements']}건), "
        f"하나라도 어긋나면 분석 스크립트가 PDF 생성을 중단한다. 이 교차검사가 실제로 힘을 갖는지는 회귀 테스트가 "
        f"고정한다. provider의 경로 정규화를 일부러 망가뜨리면 Replay 라벨은 변화를 보지 못하고 상태 검사기만 "
        f"위반을 보고한다.", st["body"]))
    add(Paragraph(
        "오라클이 받는 입력은 도구, 승인 인자, 승인 제출 횟수, provider 변화 설정뿐이며 공격 계열 이름도 트리거도 "
        "탐지기 판정도 보지 않는다. 결정적으로 S는 시험 대상인 모든 계약의 관측 필드 집합을 진부분집합으로 포함한다. "
        "어떤 계약도 볼 수 없는 공격을 오라클이 라벨링할 수 있는 이유가 이것이고, A 그룹의 1.00이 성능이 아니라 "
        "구성적 결과인 이유도 같다. 조건부 공격이 발동하지 않은 호출은 정상으로 센다. 다만 두 구현을 같은 저자가 "
        "썼으므로 이것이 제3자 blind 라벨을 대신하지는 않는다(6절).", st["body"]))
    add(Paragraph("2.2 표본 구성", st["h"]))
    add(Paragraph(
        f"실행 수는 다음과 같이 분해된다.<br/>"
        f"&#160;&#160;도구 {dec['tools']} × (공격 계열 {dec['attack_families']} + 트리거 "
        f"{dec['trigger_conditions']} + 정상 계열 {dec['benign_families']}) = 조건 {dec['conditions']}<br/>"
        f"&#160;&#160;조건 {dec['conditions']} × 관측면 {dec['observers']} × seed {dec['seeds']} × 호출 "
        f"{dec['calls']} = {dec['rows']:,}행<br/>"
        f"&#160;&#160;관측면 1종 = {dec['per_observer']:,}행 = 공격 {dec['attacks']:,} + 정상 {dec['benign']:,}<br/>"
        f"5절의 그룹별 값은 모두 독립 provider 영수증 쪽 {dec['per_observer']:,}행에서 계산했고, 같은 크기의 "
        f"자기보고 표본은 5.1에서만 쓴다. Recall의 분모는 오라클이 공격으로 판정한 실행 수이고, 신뢰구간의 재표집 "
        f"단위는 (도구, 계열, 트리거) 조건 클러스터다. 승인된 재제출 "
        f"{dec['benign'] - dec['benign_excl_resubmit']:,}행을 뺀 정상 {dec['benign_excl_resubmit']:,}행이 뒤에 "
        f"나오는 FPR(재제출 제외)의 분모다. 관측면 2종은 같은 호출을 두 번 읽는 것이 아니라 검증기가 읽는 영수증 "
        f"출처(provider / 도구 서버 자기보고)만 다른 별도 실행 부문이다. seed는 승인 인자의 값을 바꾸고, 호출 "
        f"index는 패딩·대소문자·경로 표기 같은 입력 변형과 지연 트리거의 발동 구간을 바꾼다.", st["body"]))

    add(Paragraph("3. 공격과 정상 트래픽", st["h"]))
    add(Paragraph(
        f"{dec['attack_families']}개 공격 계열을 공격이 무엇을 건드리는지로 다섯으로 나눴다. 계약이 검사하는 인자와 "
        "효과를 바꾸는 A, provider의 해석 결과와 영수증 부가 정보를 바꾸는 B, 도구가 선언했지만 계약이 검사하지 않는 "
        "인자를 바꾸는 C, provider가 영수증에 기록하지만 어느 계약도 열거하지 않는 처리 경로를 바꾸는 D, 선언된 인자 "
        "중 하나를 무작위로 고르는 E다. D를 ‘비열거 영수증 경로’라 부르는 것은 그 사실이 영수증에는 남아 있고 계약 "
        "쪽에만 없기 때문이다. 미기록이 아니라 미검증이다. 퍼징은 도구가 선언한 인자 가운데 하나를 요청으로 seed를 "
        "만들어 고르므로 계약 작성자가 결과를 예측할 수 없고, 같은 입력에서는 같은 선택이 재현된다. 지연·임계·tenant "
        "트리거는 서버 상태로 실제 구현했다. 정상 트래픽에는 공백과 대소문자, 중복 경로 같은 비정규화 입력, optional "
        "필드를 더한 manifest migration, 사용자가 승인한 재제출을 넣었다.", st["body"]))
    add(table([["그룹", "계열 (번호는 그림 1의 행)", "영수증에서 바뀌는 것"],
               ["A 직접 인자·효과",
                "1 대상 치환, 2 값 변조, 3 숨은 복제, 4 범위 확장, 5 교차 채널, 6 효과 종류 변경",
                "열거된 값·개수·종류가 직접 바뀐다"],
               ["B 해석·메타데이터",
                "7 간접참조 해석, 8 메타데이터 채널, 9 순서 교환, 10 단위 교체",
                "직접 필드는 유지한 채 해석된 principal·부가 필드·효과 순서·통화 단위만 바뀐다"],
               ["C 비열거 인자", "11 비열거 필드, 12 tenant 침범, 13 memo 유출",
                "callback_url·tenant·memo — 도구는 선언하지만 어느 계약도 열거하지 않는다"],
               ["D 비열거 영수증 경로", "14 별칭 체인, 15 정산 경로 우회, 16 정산 계정 교체",
                "최종 도착지·정산 경로·정산 계정 — 영수증에는 남지만 계약이 열거하지 않는다"],
               ["E 무작위 인자", "17 무작위 퍼징", "선언된 인자 중 seed로 고른 하나를 변형"]],
              [width * 0.22, width * 0.40, width * 0.38], st))
    add(Paragraph(
        f"표 1. 공격이 무엇을 건드리는지로 나눈 다섯 그룹과 {dec['attack_families']}개 계열. E는 선언된 인자 중 "
        "하나를 무작위로 고르므로 A와 C에 걸친다. 결과는 이 그룹으로만 보고한다.", st["cap"]))

    add(Paragraph("4. 방어 구현", st["h"]))
    add(Paragraph(
        "여섯 방어를 모두 실제로 계산했다. manifest pin은 호출 시점에 서버가 준 manifest의 SHA-256을 동결값과 "
        "비교하고, 서명 manifest는 발행자 공개키로 Ed25519 서명을 검증하며, 응답 검사는 반환 JSON의 schema와 값 "
        "일치를 본다. 다만 이 위협 모델에서 발행자는 곧 공격자이므로 서명 manifest의 결과 0은 방어 비교가 아니라 "
        "위협모델 적합성 점검으로 읽어야 한다. 궤적은 영수증의 효과 종류와 개수만 보고, 학습 관계는 정상 실행 "
        "192회에서 적합한 종류·개수·필드 보존 관계만 본다. 계약 v3는 필수 필드, 원문 값 일치, 효과 종류 집합, "
        "효과 개수를 검사한다. v4는 규칙을 강화한 것이 아니라 관측 대상을 더 열거한 것으로, 정규화 후 일치, 효과 "
        "순서, 해석된 principal, 단위, 미지 영수증 필드 거부를 더한다. 마지막 항목은 탐지력을 늘리는 대신 5.4의 "
        "drift 취약성을 함께 들여온다. 두 계약 모두 memo·tenant·callback_url은 열거하지 않는다. 비교를 위해 두 "
        "변형을 더 넣었다. 하나는 provider 정규화를 모르는 검증자가 쓸 법한 공백 제거만 하는 정규화로 v4를 다시 "
        "돌린 것이고, 다른 하나는 필드를 열거하는 대신 승인 인자 전체의 해시를 provider가 영수증에 담아 서명하는 "
        "승인 결합 방식이다. provider는 정규화 전 원본 인자를 해시하므로 검증자가 provider 정규화를 알 필요가 없다. "
        "전제는 대칭이 아니다. 값 대조 계약 둘은 영수증을 읽기만 하지만, 승인 결합은 provider가 수신 요청의 digest를 "
        "영수증에 담아 서명해 주어야 성립하는 프로토콜 요구다. 아래 비교는 같은 관측면 위의 검증 규칙 비교이지 배치 "
        "비용의 비교가 아니다.", st["body"]))

    add(Paragraph("5. 결과", st["h"]))
    rows = [["방어", "A", "B", "C", "D", "E", "FPR<br/>(재제출 제외)"]]
    for key in ["manifest_pin", "trajectory_lite", "learned_relation",
                "frozen_intent", "extended_intent", "approval_bound", "union_v4_approval"]:
        rows.append([DETECTOR_LABEL[key], pct(both[key], 3), pct(v4only[key], 3),
                     pct(neither[key], 3), pct(unseen[key], 3), pct(fuzz_rec[key], 3),
                     pct(clean_fpr[key], 3)])
    add(table(rows, [width * 0.26, width * 0.115, width * 0.115, width * 0.115,
                     width * 0.115, width * 0.115, width * 0.165], st,
              align_right=(1, 2, 3, 4, 5, 6)))
    ci_text = ", ".join(
        f"{GROUP_LETTER[g]} [{pct(cig[g]['extended_intent'][0], 3)}, {pct(cig[g]['extended_intent'][1], 3)}]"
        for g in GROUP_ORDER)
    cluster_text = ", ".join(f"{GROUP_LETTER[g]} {a['ci95_by_group_clusters'][g]}" for g in GROUP_ORDER)
    add(Paragraph(
        f"표 2. 표 1의 그룹별 Recall과 정상 트래픽 FPR, 모두 독립 provider 영수증 {dec['per_observer']:,}행에서 "
        f"계산했다. 공격 실행 수는 A {grp['both']['attacks']:,}, B {grp['v4_only']['attacks']:,}, "
        f"C {grp['neither']['attacks']:,}, D {grp['unseen']['attacks']:,}, E {grp['fuzz']['attacks']:,}회로 합계 "
        f"{a['attacks_independent']:,}회이고, 정상 {a['benign_independent']:,}회를 더하면 {dec['per_observer']:,}행이 "
        f"된다(2.2절). 마지막 열은 승인된 재제출을 뺀 정상 {dec['benign_excl_resubmit']:,}행 기준이다. 서명 "
        f"manifest와 응답 검사는 A–E 전 그룹에서 0.000이므로 줄을 빼고 본문에서 이유를 적었다. 합성 행은 v4와 승인 "
        f"결합의 판정을 행 단위 OR로 묶은 것으로, 새 탐지기가 아니라 같은 로그의 두 판정 열에서 계산했다(5.3). "
        f"v4 Recall의 조건 클러스터 부트스트랩 95% 구간은 {ci_text}, 재표집 단위인 조건 클러스터 수는 "
        f"{cluster_text}개다.", st["cap"]))
    add(fig_image(figures["heatmap"], width))
    add(Paragraph(
        "그림 1. 계열별 Recall. 가로줄은 표 1의 그룹 경계다. 그룹 값은 이 표를 그룹 안에서 가중 평균한 것이므로 "
        "그룹 안에서도 계열마다 갈린다. 분모는 계열마다 오라클이 공격으로 판정한 실행 수다. 대상 치환은 조건부 "
        "트리거가 발동하지 않은 호출이 빠져서, 순서 교환은 효과가 둘 이상인 도구에서만 성립해서 수가 다르다.",
        st["cap"]))
    add(Paragraph(
        f"공격 비율은 {100 * a['attacks_independent'] / dec['per_observer']:.1f}%이며 운영 기저율은 5.7에서 "
        f"재가중한다. 전 계열 집계는 계열 구성비의 함수이므로 싣지 않는다. v3가 B에서 보이는 "
        f"{num(v4only['frozen_intent'], '은/는')} 같은 표본의 FPR {num(clean_fpr['frozen_intent'], '과/와')} 구별되지 "
        f"않으므로 탐지 신호로 읽지 않는다. manifest pin과 서명 manifest의 Recall 0도 미구현이 아니라 두 센서가 보는 "
        f"대상이 바뀌지 않았기 때문이다. 같은 표본에서 manifest pin은 정상 migration에만 FPR "
        f"{num(pin['by_family']['migration']['fpr'], '으로/로', 2)} 발화하므로 배선은 살아 있고, 표 2의 "
        f"{num(clean_fpr['manifest_pin'], '은/는')} 재제출을 뺀 정상 {dec['benign_excl_resubmit']:,}행 가운데 migration "
        f"{fam['migration']['benign']:,}행에서만 전부 발화한 결과 "
        f"{fam['migration']['benign']:,}/{dec['benign_excl_resubmit']:,}이다. 응답 검사는 서버가 승인값을 그대로 "
        f"되돌려 주는 한 0을 유지한다. 응답 검사가 신호를 얻으려면 응답이 서버가 아니라 provider에서 와야 하며, "
        f"그때는 응답 검사와 영수증 검증이 같은 것이 된다.", st["body"]))

    add(Paragraph("5.1 관측면이 독립일 때만 값 비교가 증거가 된다", st["h"]))
    add(Paragraph(
        f"영수증 출처만 provider에서 서버 자기보고로 바꾸고 나머지를 고정하면, 두 계약이 모두 열거하는 A 그룹에서 "
        f"v4 Recall이 {pct(both['extended_intent'], 2)}에서 "
        f"{num(s_group['both']['recall']['extended_intent'], '으로/로')}, v3가 {pct(both['frozen_intent'], 2)}에서 "
        f"{num(s_group['both']['recall']['frozen_intent'], '으로/로')} 떨어지고 승인 결합도 "
        f"{num(s_group['both']['recall']['approval_bound'], '이/가')} 된다. 이 결과는 측정이라기보다 정리의 시연이다. "
        f"관측면을 공격자가 통제하면 공격자는 승인된 값을 그대로 보고할 수 있고, 값 비교로 만든 어떤 계약도 위반을 "
        f"볼 수 없다. 본 구현의 자기보고 서버는 provider와 동일한 정규화로 승인값을 되돌려 주므로 값·종류·개수·"
        f"principal이 모두 일치한다. 서명 검증을 켜면 자기보고 영수증의 "
        f"{num(a['signature_rejects_self_report'], '이/가', 2)} 무효로 걸리지만, 그 결과는 탐지가 아니라 가용성 판정이다. "
        f"provider 서명 없이 모은 영수증 위의 의미 계약은 두 번째 자기보고에 지나지 않는다.", st["body"]))

    add(Paragraph("5.2 열거 범위가 탐지 범위를 정한다", st["h"]))
    add(Paragraph(
        f"B 그룹에서 v4가 {pct(v4only['extended_intent'], 3)}인 것은 v4가 해석된 principal과 미지 영수증 필드를 새로 "
        f"열거했기 때문이지 규칙이 일반적으로 강해서가 아니다. 같은 B 안에서도 단위 교체가 "
        f"{pct(fam['unit_swap']['recall']['extended_intent'], 2)}에 머무는 것은 도구 8종 중 금액을 가진 둘만 단위를 "
        f"열거하기 때문이다(그림 1). B와 C에서 v3가 보이는 {num(v4only['frozen_intent'], '과/와')} "
        f"{num(neither['frozen_intent'], '은/는')} v3의 정상 FPR {num(clean_fpr['frozen_intent'], '과/와')} 같은 크기다. "
        f"원문 비교가 provider 정규화를 모르기 때문에 생기는 오경보가 공격 행에도 같은 비율로 떨어진 것이므로 탐지 "
        f"신호가 아니다. 같은 그룹 안에서 세 방어가 갈리는 값도 같은 이야기를 한다. A에서 궤적은 "
        f"{pct(both['trajectory_lite'], 3)}, 학습 관계는 {pct(both['learned_relation'], 3)}, 계약은 "
        f"{pct(both['extended_intent'], 2)}인데, 궤적은 효과 종류와 개수만 보므로 값만 바뀌는 대상 치환과 값 변조를 "
        f"보지 못하고, 학습 관계는 provider가 정규화하는 필드를 보존 관계로 학습하지 못해 그만큼을 놓친다.", st["body"]))
    fz = a["fuzz_by_tool"]
    lo_tool = min(fz, key=lambda t: fz[t]["share"])
    hi_tool = max(fz, key=lambda t: fz[t]["share"])
    fzd = a["fuzz_v3_v4_disagreement"]
    add(Paragraph(
        f"퍼징(E)도 같은 방향이다. 계약이 열거한 인자 비율이 가장 낮은 {lo_tool}"
        f"({fz[lo_tool]['enumerated']}/{fz[lo_tool]['declared']})에서 v4 Recall이 "
        f"{pct(fz[lo_tool]['recall_v4'], 3)}, 가장 높은 {hi_tool}({fz[hi_tool]['enumerated']}/"
        f"{fz[hi_tool]['declared']})에서 {num(fz[hi_tool]['recall_v4'], '이다/다')}. 도구 8종뿐이라 방향만 보고하고 "
        f"인과로 단정하지 않는다. E에서 v3({pct(fam['fuzz_field']['recall']['frozen_intent'], 3)})가 "
        f"v4({pct(fam['fuzz_field']['recall']['extended_intent'], 3)})를 근소하게 앞서는 것도 탐지력이 아니다. "
        f"v3만 잡은 {fzd['v3_only']}행({fzd['v3_only_mutation_outside_enumeration']}행이 비열거 인자 변형, "
        f"{fzd['v3_only_unnormalised_anchor']}행이 비정규 승인 입력)은 공격이 아니라 v3의 정규화 무지 오경보가 "
        f"공격 행에 겹쳐 TP로 계산된 것이고, v4만 잡은 {fzd['v4_only']}행은 v4가 새로 열거한 unit의 "
        f"변형({fzd['v4_only_unit_mutation']}행)이다.", st["body"]))

    add(Paragraph("5.3 두 접근의 사각지대는 정반대이고, 공통 사각지대가 남는다", st["h"]))
    diff = a["b_paired_diff"]
    add(Paragraph(
        f"필드를 열거하는 대신 승인 인자 전체를 해시로 묶으면 인자 공간의 사각지대가 사라진다. 승인 결합은 계약이 "
        f"검사하지 않는 인자 그룹(C)에서 {pct(neither['approval_bound'], 2)}, 무작위 인자(E)에서 "
        f"{num(fuzz_rec['approval_bound'], '으로/로', 2)} 값 대조 계약의 {pct(neither['extended_intent'], 3)}·"
        f"{num(fuzz_rec['extended_intent'], '을/를')} 크게 앞선다. 반대로 provider 해석·메타데이터(B)에서는 "
        f"{num(v4only['approval_bound'], '으로/로')} 값 대조 계약의 {pct(v4only['extended_intent'], 3)}보다 낮다"
        f"(같은 클러스터로 짝지은 차이의 95% 구간 [{pct(diff['ci95'][0], 3)}, {pct(diff['ci95'][1], 3)}]). 간접참조 "
        f"해석과 메타데이터 채널은 인자를 하나도 바꾸지 않으므로 해시가 그대로다. 두 방식이 함께 놓치는 그룹이 D다. "
        f"별칭 체인, 정산 경로 우회, 정산 계정 교체 {grp['unseen']['attacks']:,}회에서 값 대조 계약은 "
        f"{pct(unseen['extended_intent'], 3)}, 승인 결합은 {num(unseen['approval_bound'], '이며/며')} 승인 결합의 "
        f"클러스터 95% 구간은 [{pct(cig['unseen']['approval_bound'][0], 3)}, "
        f"{pct(cig['unseen']['approval_bound'][1], 3)}]{jo(pct(cig['unseen']['approval_bound'][1], 3), '이다/다')}. "
        f"provider가 영수증에 남기는 사실인데 어느 계약도 읽지 않기 때문이다. 그래서 두 판정을 행 단위 OR로 합성한 "
        f"표 2의 마지막 행은 A·B·C·E를 {pct(grp['both']['recall']['union_v4_approval'], 2)}·"
        f"{pct(grp['v4_only']['recall']['union_v4_approval'], 2)}·"
        f"{pct(grp['neither']['recall']['union_v4_approval'], 2)}·"
        f"{num(grp['fuzz']['recall']['union_v4_approval'], '으로/로', 2)} 닫고 오탐도 "
        f"{pct(clean_fpr['union_v4_approval'], 3)}에 머물지만, D는 "
        f"{num(unseen['union_v4_approval'], '으로/로')} 그대로 남는다. 상보성은 인자와 해석의 경계까지이고, 아무도 "
        f"열거하지 않은 영수증 경로는 합성으로도 닫히지 않는다. 인자 공간은 해시로 닫을 수 있고 provider 해석은 "
        f"열거로 닫을 수 있지만, 열거를 한 단계 늘리면 경계는 그다음 단계로 물러난다. 두 1.00은 성능이 아니다. 값 "
        f"대조 계약의 A는 그 필드를 검사하기로 한 결정의 결과이고, 승인 결합의 C·E는 인자를 하나라도 바꾸면 해시가 "
        f"깨진다는 정의의 결과다. 측정된 것은 0에 가까운 세 칸(B의 승인 결합, C의 값 대조, D의 양쪽)이다.",
        st["body"]))

    add(Paragraph("5.4 낮은 오탐은 구현 합치와 provider 정지에 기댄다", st["h"]))
    add(Paragraph(
        f"값 대조 계약의 오탐 0은 검증자가 provider와 같은 정규화 함수를 쓴 결과다. 공백 제거만 하는 정규화로 다시 "
        f"돌리면 FPR이 {pct(clean_fpr['extended_intent'], 3)}에서 {num(clean_fpr['extended_naive'], '으로/로')} 오른다. "
        f"승인 결합도 마찬가지여서, 클라이언트가 해시 전에 문자열을 다듬고 provider는 원본을 해시하면 "
        f"{pct(clean_fpr['approval_bound'], 3)}에서 {num(clean_fpr['approval_naive'], '으로/로')} 오른다. 정규화 의존이 "
        f"직렬화 의존으로 형태만 바뀐 것이다. 확장 계약의 오탐이 한 계열에서만 나오는 것도 같은 종류의 사실이다. "
        f"사용자가 승인한 재제출에서 네 방어가 모두 FPR {num(fam['resubmit']['fpr']['extended_intent'], '으로/로', 2)} "
        f"경보하는데, 개수 규칙만으로는 숨은 복제와 정당한 재제출을 나눌 수 없기 때문이다. 개수 계약은 idempotency "
        f"키 정책과 함께 정의해야 한다.", st["body"]))
    if drift:
        add(Paragraph(
            "운영에서 더 흔한 쪽은 계약을 동결한 뒤 provider가 변하는 경우다. 정상 트래픽만으로 같은 행렬을 다시 "
            "돌리되 provider를 네 가지로 바꿨다. 공격이 없으므로 오라클은 모든 행을 정상으로 라벨하고, 여기서 나온 "
            "경보는 정의상 전부 오탐이다.", st["body"]))
        drift_rows = [["provider 변화", "v3 FPR", "v4 FPR", "승인 결합 FPR", "합성 FPR"]]
        for kind in ("none", "receipt_annotation", "normalisation_upgrade", "unicode_nfc",
                     "hash_basis_change"):
            if kind not in drift:
                continue
            f = drift[kind]["fpr"]
            drift_rows.append([DRIFT_LABEL[kind], pct(f["frozen_intent"], 3),
                               pct(f["extended_intent"], 3), pct(f["approval_bound"], 3),
                               pct(f["union_v4_approval"], 3)])
        add(table(drift_rows, [width * 0.28, width * 0.18, width * 0.18, width * 0.18,
                               width * 0.18], st, align_right=(1, 2, 3, 4)))
        add(Paragraph(
            f"표 3. 계약 동결 이후 provider만 바뀐 정상 트래픽 {drift['none']['benign_excl_resubmit']:,}행(재제출 제외, "
            f"변화 종류마다 같은 크기)에서의 오탐. 정상 계열만 돌린 별도 스위트이므로 분모가 표 2의 "
            f"{dec['benign_excl_resubmit']:,}행과 다르고, 읽어야 할 것은 표 2와의 차이가 아니라 ‘없음(기준)’ 행과의 "
            f"차이다. ‘영수증 주석 추가’는 provider가 자기 릴리스 태그를 영수증에 덧붙이는 변화, ‘정규화 강화’는 "
            f"principal 필드까지 대소문자를 접는 변화, ‘해시 기준 변경’은 provider가 받은 바이트 대신 정규화 결과를 "
            f"해시하는 변화다.", st["cap"]))
        d_ann = drift["receipt_annotation"]["fpr"]
        d_norm = drift["normalisation_upgrade"]["fpr"]
        d_hash = drift["hash_basis_change"]["fpr"]
        add(Paragraph(
            f"두 방식은 서로 다른 변화에서 무너진다. 값 대조 계약은 provider가 영수증에 필드를 하나 덧붙이는 것만으로 "
            f"오탐이 {num(d_ann['extended_intent'], '이/가', 2)} 된다. 메타데이터 채널을 잡아 준 미지 필드 거부 규칙이 그 "
            f"원인이어서, 탐지력과 drift 취약성이 같은 곳에서 나온다. 정규화가 한 단계 강해지면 v4 "
            f"{pct(d_norm['extended_intent'], 3)}, v3 {num(d_norm['frozen_intent'], '으로/로')} 둘 다 오른다. 반대로 승인 "
            f"결합은 이 둘 모두에 {num(d_ann['approval_bound'], '으로/로')} 반응하지 않는다. 해시가 provider 내부 표현이 "
            f"아니라 요청 바이트에 걸려 있기 때문이다. 대신 provider가 해시 기준을 바꾸면 승인 결합만 "
            f"{num(d_hash['approval_bound'], '으로/로')} 오른다. Unicode NFC에서 셋 다 0인 것은 강건성이 아니라 본 정상 "
            f"코퍼스가 ASCII뿐이라 그 변화가 값을 바꾸지 못한 결과다. 합성은 탐지 범위와 함께 무너지는 지점도 "
            f"합친다. 주석 추가에서 {pct(d_ann['union_v4_approval'], 2)}, 해시 기준 변경에서 "
            f"{num(d_hash['union_v4_approval'], '으로/로')} 올라 두 방식의 drift 취약성을 그대로 물려받는다.",
            st["body"]))

    if hold:
        add(Paragraph("5.5 남이 만든 도구 표에서 같은 분해가 나온다", st["h"]))
        prov = hold["meta"]["provenance"]
        hg = hold["by_group"]
        add(Paragraph(
            f"지금까지의 수치는 도구·공격·계약을 같은 사람이 만든 테스트베드에서 나왔다. 그중 도구와 계약을 "
            f"바깥에서 가져와 같은 행렬을 다시 돌렸다. 공개된 MCP 참조 서버 {len(prov)}종"
            f"({', '.join(p['server'] + ' ' + str(p['version']) for p in prov)})에 공식 SDK로 접속해 tools/list가 준 "
            f"schema를 그대로 받고, 네 규칙만으로 도구 표를 만들었다. required 속성이 하나 이상인 도구만 남기고, "
            f"선언 인자는 published properties, 계약이 검사할 열거 인자는 발행자가 쓴 required 목록, principal은 "
            f"required 중 첫 문자열 속성이다. 즉 이 절의 계약은 서버 발행자가 쓴 것이고, 본 연구가 고른 것은 무엇을 "
            f"공격할지뿐이다. 도구 {hold['tools']}개, 조건 {hold['conditions']}개, 실행 {hold['rows']:,}행이며 아래 "
            f"값은 독립 영수증 쪽 {hold['independent']:,}행에서 계산했다. 두 오라클 구현은 여기서도 전 행 일치했다.",
            st["body"]))
        hold_rows = [["방어", "A", "B", "C", "D", "E", "FPR<br/>(재제출 제외)"]]
        for key in ["frozen_intent", "extended_intent", "approval_bound"]:
            hold_rows.append([DETECTOR_LABEL[key]]
                             + [pct(hg[g]["recall"][key], 3) for g in GROUP_ORDER]
                             + [pct(hold["fpr_excl_resubmit"][key], 3)])
        add(table(hold_rows, [width * 0.26, width * 0.115, width * 0.115, width * 0.115,
                              width * 0.115, width * 0.115, width * 0.165], st,
                  align_right=(1, 2, 3, 4, 5, 6)))
        add(Paragraph(
            f"표 4. 공개 MCP 서버 스키마 hold-out. 공격 실행 수는 A {hg['both']['attacks']:,}, "
            f"B {hg['v4_only']['attacks']:,}, C {hg['neither']['attacks']:,}, D {hg['unseen']['attacks']:,}, "
            f"E {hg['fuzz']['attacks']:,}회. 계약은 발행자의 required 목록에서 기계적으로 유도했고 본 연구가 "
            f"고쳐 쓰지 않았다.", st["cap"]))
        add(Paragraph(
            f"구조가 그대로 재현된다. 두 계약이 모두 열거하는 A에서 값 대조와 승인 결합이 함께 "
            f"{pct(hg['both']['recall']['extended_intent'], 2)}, 발행자가 required로 쓰지 않은 인자를 건드리는 C에서 "
            f"값 대조가 {pct(hg['neither']['recall']['extended_intent'], 3)}인데 승인 결합은 "
            f"{pct(hg['neither']['recall']['approval_bound'], 2)}, provider 해석을 건드리는 B에서는 반대로 값 대조 "
            f"{pct(hg['v4_only']['recall']['extended_intent'], 3)}에 승인 결합 "
            f"{num(hg['v4_only']['recall']['approval_bound'], '이며/며')}, D는 "
            f"{num(hg['unseen']['recall']['extended_intent'], '과/와')} "
            f"{num(hg['unseen']['recall']['approval_bound'], '으로/로')} 여전히 공통 사각지대다. 달라진 것은 오탐 쪽이다. "
            f"원문 비교 계약 v3의 FPR이 본 행렬 {pct(clean_fpr['frozen_intent'], 3)}에서 "
            f"{num(hold['fpr_excl_resubmit']['frozen_intent'], '으로/로')} 오르는데, 남의 스키마에는 검증자가 모르는 "
            f"정규화 대상 필드가 더 많기 때문이다. 사각지대의 구조는 도구 표를 바꿔도 남고, 오탐의 크기는 도구 표를 "
            f"따라 움직인다.", st["body"]))
        fid = hold.get("family_fidelity")
        if fid:
            add(Paragraph(
                f"계열이 뜻을 그대로 유지하지는 않는다. 공개 스키마는 선언만 하고 required가 아닌 인자를 거의 두지 "
                f"않아서, 도구 {fid['tools']}종 중 {fid['with_optional_args']}종에서만 C 계열이 원래 형태를 "
                f"유지하고 나머지에서는 schema가 선언한 적조차 없는 필드를 주입한다. C의 대비가 유지되는 것은 두 "
                f"경우 모두 계약이 그 필드를 보지 않기 때문이지 계열이 같아서가 아니다.", st["body"]))

    if real:
        add(Paragraph("5.6 실제 MCP 전송 위에서, 그리고 전송 장애와 구별해서", st["h"]))
        faults = real["faults"]
        lag = faults.get("async_lag", {})
        reset = faults.get("tcp_reset", {})
        rg = real["by_group"]
        add(Paragraph(
            f"두 번째 확인은 전송이다. 같은 공격기·같은 오라클·같은 계약을 공식 MCP Python SDK의 stdio 전송 위에 "
            f"올려 {real['rows']:,}회를 다시 돌렸다. 서버는 별도 OS 프로세스이고 관측면은 v5 provider의 서명 영수증 "
            f"로그다. 이전 판이 공격 서버가 직접 쓰는 SQLite를 관측면으로 삼았던 것과 달리, 여기서는 공격자가 증거를 "
            f"만들 수도 지울 수도 없다. 이 전송의 라벨은 상태 검사기 단독이며, 두 구현의 교차검사는 본 행렬과 "
            f"hold-out에서 수행했다(2.1). tools/list 해시는 정상·공격 {len(real['meta']['families'])}개 모드 전부에서 "
            f"{len(real['manifest_hashes'])}종으로 같았고, 응답은 {pct(real['response_matches_approved'], 3)}의 비율로 "
            f"승인값을 그대로 돌려줬다. 그룹 구조도 재현된다. A {pct(rg['both']['recall']['extended_intent'], 2)}, "
            f"C 값 대조 {pct(rg['neither']['recall']['extended_intent'], 3)} 대 승인 결합 "
            f"{pct(rg['neither']['recall']['approval_bound'], 2)}, D "
            f"{pct(rg['unseen']['recall']['extended_intent'], 3)}·"
            f"{num(rg['unseen']['recall']['approval_bound'], '이다/다')}. "
            f"지연 발동 공격은 승인 probe {real['probe_calls']}회(도구별 첫 3회)에서 {real['probe_fired']}회 켜졌고 "
            f"배치 후 공격 {real['deployed_attacks']}건 중 {real['deployed_detected']}건이 탐지됐다.", st["body"]))
        add(Paragraph(
            f"운영에서 더 중요한 것은 전송 장애와 의미 이탈을 가를 수 있느냐다. 도구 서버와 provider 사이에 세 가지 "
            f"장애를 정상 트래픽에 주입했다. 연결을 RST로 끊으면 효과가 아예 기록되지 않아 영수증 "
            f"{reset.get('receipt_missing', 0)}/{reset.get('runs', 0)}건이 비고, 이는 승인된 행위가 일어나지 않았다는 "
            f"뜻이므로 오라클도 이탈로 라벨한다. 다만 대조할 영수증이 없다는 점에서 값이 어긋난 경우와 구별되며, "
            f"검증기는 이를 보안 경보가 아니라 가용성 상태로 분류할 수 있다. 비동기 지연은 더 미묘하다. 서버가 효과를 "
            f"{real['meta']['lag_ms']} ms 뒤에 기록하면 영수증은 결국 도착하지만 즉시 읽는 검증기에는 없다. 한 번만 "
            f"읽는 검증기는 {lag.get('single_shot_alarm', 0)}/{lag.get('runs', 0)}건 전부를 오탐으로 올리고, "
            f"{real['meta']['poll_deadline_ms']} ms까지 기다리는 검증기는 {lag.get('waited_alarm', 0)}건이다. 영수증 "
            f"기반 검증에는 도착 대기 정책이 규칙의 일부여야 한다는 뜻이다.", st["body"]))
        e2e = a["latency_e2e_ms"]
        add(Paragraph(
            f"지연은 승인 호출부터 판정까지를 끝에서 끝으로 측정했다. 로컬 HTTP 경계에서 p50 "
            f"{e2e['e2e']['p50']:.2f} ms, p95 {e2e['e2e']['p95']:.2f} ms이고 내역은 도구 호출 "
            f"{e2e['tool_call']['p95']:.2f}, 영수증 조회 {e2e['receipt_fetch']['p95']:.2f}, 서명·결합 검증 "
            f"{e2e['verify']['p95']:.2f}, 계약 계산 {e2e['contract']['p95']:.2f} ms(모두 p95)다. 공식 SDK stdio "
            f"경계에서는 p50 {real['e2e_ms']['p50']:.2f} ms, p95 {real['e2e_ms']['p95']:.2f} ms다. 둘 다 동일 "
            f"호스트 값이므로 원격 provider의 왕복 지연은 포함하지 않는다. 병목이 계약 계산이 아니라 영수증 수집과 "
            f"도착 대기에 있다는 점이 배치 설계에서 중요하다.", st["body"]))

    add(Paragraph("5.7 사전 기준, 유병률, 배치 정책", st["h"]))
    gate_rows = [["기준", "관측", "판정"]]
    for gate in a["gates"]:
        unit = f" {gate['unit']}" if gate.get("unit") else ""
        shown = " / ".join(f"{v:.3f}{unit}" for v in gate["observed"])
        if gate.get("scope"):
            shown += f" ({gate['scope']})"
        gate_rows.append([gate["label"], shown, gate["verdict"]])
    add(table(gate_rows, [width * 0.44, width * 0.33, width * 0.23], st))
    passed = sum(1 for g in a["gates"] if g["verdict"] == "통과")
    add(Paragraph(
        f"표 5. 평가 전에 정한 기준과 실측. 판정 열은 관측값과 임계값을 비교해 스크립트가 계산하며 본문에 손으로 "
        f"적지 않는다. {len(a['gates'])}개 중 {passed}개 통과. 실패한 {len(a['gates']) - passed}건은 그대로 "
        f"보고하며, 통과한 Recall 기준도 성능이 아니라 각 방식이 그 필드를 보기로 한 정의의 결과다(5.3).", st["cap"]))
    bounds, zero = a["prevalence_bounds"], a["zero_fp_upper_bound"]
    b999 = bounds.get("999") or bounds[999]
    add(Paragraph(
        f"유병률을 운영 기저율로 재가중하면 v4의 F1은 하나로 정해지지 않는다. 오탐이 0으로 측정됐기 때문이며, 이는 "
        f"위험이 0이라는 뜻이 아니라 표본이 그 위 어디까지인지를 말해 주지 않는다는 뜻이다. 1:999에서 점추정은 "
        f"{pct(b999['extended_intent']['point'], 3)}, rule of three 상한을 조건 클러스터 단위 "
        f"3/{zero['n_clusters']}={num(zero['fpr_upper_95'], '으로/로', 4)} 잡으면 {pct(b999['extended_intent']['worst'], 3)}, 행 "
        f"단위 3/{zero['n_benign']:,}={num(zero['fpr_upper_95_row'], '으로/로', 5)} 잡으면 "
        f"{pct(b999['extended_intent']['worst_row'], 3)}이고, 측정 부트스트랩 95% FPR 구간은 "
        f"[{pct(a['ci95_fpr_excl_resubmit']['extended_intent'][0], 3)}, "
        f"{pct(a['ci95_fpr_excl_resubmit']['extended_intent'][1], 3)}]"
        f"{jo(pct(a['ci95_fpr_excl_resubmit']['extended_intent'][1], 3), '이다/다')}. 이 F1은 본 행렬의 계열 "
        f"구성비 위에서 전 계열 Recall을 재가중한 예시 값이라, 5절이 그룹별 보고를 택한 것과 같은 이유로 구성비가 "
        f"다르면 함께 움직인다. 조건 안의 반복은 같은 코드 경로를 다시 밟는 "
        f"것이라 클러스터 단위가 보수적이지만, 조건은 전수 조합으로 만든 설계 격자이지 모집단 표본이 아니므로 이 "
        f"상한도 ‘본 격자에서 오탐이 관측되지 않았다’를 수치로 옮긴 것일 뿐 운영 분포의 보장이 아니다.", st["body"]))
    add(Paragraph(
        "배치 정책은 영수증이 언제 발급되는지에 달려 있다. 본 테스트베드의 영수증은 provider가 효과를 반영한 "
        "뒤 발급하는 사후 영수증이므로, 검증은 탐지와 사후 보상까지만 할 수 있고 ‘효과 보류’를 할 수 없다. "
        "차단형 배치를 하려면 provider가 prepare–영수증–commit의 2단계 프로토콜을 제공해서 검증이 commit 앞에 "
        "와야 하며, 그때의 지연 예산은 계약 계산이 아니라 왕복 영수증 수집과 도착 대기가 지배한다. 2단계를 제공하지 "
        "않는 provider에서는 계약 위반이 곧 보상 트랜잭션 개시 신호가 된다. 영수증을 얻지 못한 상태는 안전으로 "
        "보지 않고 별도 상태로 기록해 고위험 도구는 차단, 저위험 도구는 제한 실행으로 나눈다.", st["body"]))

    if llm:
        cfg = llm.get("config", {})
        live = {m: v for m, v in llm["availability"].items() if v > 0}
        dev = llm["anchor_on_deviation"]
        add(Paragraph("5.8 예비 관찰: 에이전트 계층이 먼저 실패한다", st["h"]))
        add(Paragraph(
            f"이 절은 결론이 아니라 예비 관찰이다. 유효 표본이 도구 호출을 만들지 못한 모델이 빠진 선택 표본이기 "
            f"때문이다. GPU 없이 노트북 한 대에서 {', '.join(llm['models'])} {len(llm['models'])}종에게 자연어 작업만 "
            f"주고 도구와 인자를 직접 고르게 했다. 배정 {llm['rows']:,}회는 모델 {len(llm['models'])} × 계열 "
            f"{len(cfg.get('families', [])) or 6} × 도구 {dec['tools']} × 호출 {cfg.get('calls_per_cell', 3)}이고, "
            f"유효 {llm['valid']:,}회, 오류 {llm['errors']:,}회다. 모두 {cfg.get('runtime', 'ollama')}에서 "
            f"temperature 0, seed=호출 index, max_tokens {cfg.get('max_tokens', 512)}, thinking 비활성으로 돌렸고, "
            f"도구 schema는 서버가 준 manifest를 그대로 넘겼으며, 도구 호출이 정확히 하나이고 배정된 도구와 같을 "
            f"때만 유효로 셌다. 모델별 표본은 각 {llm['rows'] // max(1, len(llm['models']))}회다. "
            + (f"{len(llm['availability']) - len(live)}종은 이 경로에서 도구 호출을 한 번도 만들지 못했고, 호출을 만든 "
               f"{len(live)}종 사이에서도 " if len(live) < len(llm['availability']) else "모델 사이에서 ")
            + f"생성률이 {pct(min(live.values()), 3)}–{num(max(live.values()), '으로/로')} 갈렸다. "
            f"방어가 적용될 수 있는 범위 자체가 모델 능력에 달려 있다. 확실한 관찰은 하나 더 있다. 서버가 정상인데 "
            f"모델만 이탈한 {dev['rows']}건 가운데 승인 의도 앵커가 잡은 것은 {dev['intent_flags']}건뿐이고, 나머지는 "
            f"두 계약이 모두 열거하지 않은 필드에서 일어났다. 앵커는 무엇과 비교할지를 정하지만, 무엇을 볼 수 "
            f"있는지는 열거 범위가 정한다.", st["body"]))

    add(Paragraph("6. 논의와 타당성 위협", st["h"]))
    add(Paragraph(
        f"가장 큰 위협은 공동설계 편향이다. 도구·계약·공격·오라클을 한 사람이 쓰면 계약이 공격을 마중 나갈 수 있다. "
        f"세 가지로 줄였다. 도구와 계약을 공개 MCP 서버의 발행 스키마에서 기계적으로 유도해 다시 측정했고(5.5), "
        f"정답 라벨을 코드를 공유하지 않는 두 구현으로 계산해 {orc['rows'] + hold['oracle']['rows']:,}행 전부에서 "
        f"일치를 확인했으며(2.1), 계약과 학습 프로파일을 평가 전에 해시로 동결했다. 그래도 남는 것이 있다. 공격은 "
        f"여전히 본 연구가 썼고, 두 오라클 구현도 같은 저자의 것이며, 동결은 이후 변경을 막을 뿐 계약 작성이 공격 "
        f"작성보다 앞섰다는 순서를 증명하지 않는다. 공격 계열을 공개 분류체계에서 그대로 가져와 편향을 줄이는 길은 "
        f"막혀 있다. 1절에서 보였듯 효과 수준 이탈을 열거한 공개 분류가 없기 때문이고, 그 부재가 이 연구의 자리이자 "
        f"이 한계의 이유다. 제3자가 쓴 공격이나 blind 계약 작성이 다음 단계다. 실제로 측정된 "
        f"것은 계열이 인자를 건드리는지 provider 해석을 건드리는지의 분할, 0에 가까운 세 칸, 표 3의 drift 취약성, "
        f"그리고 그 셋이 남의 도구 표와 실제 SDK 전송에서도 재현된다는 사실이다. provider는 로컬 프로세스라 상용 "
        f"SaaS의 tenant 격리와 최종 principal은 검증하지 않았고, 정상 트래픽도 합성이라 표 3은 재시도·locale·API "
        f"버전 폐기 같은 장기 drift 전체를 대표하지 않는다.", st["body"]))
    add(table([["근거가 있는 주장", "근거가 없는 주장"],
               ["열거하지 않은 계열에서 탐지가 거의 사라진다", "미지 공격 일반 방어"],
               ["자기보고 영수증에서 계약이 무력하다", "상용 SaaS 독립성 검증 완료"],
               ["승인 해시 결합이 인자 사각지대를 닫는다", "해시 결합이 모든 변조를 막는다"],
               ["두 방식이 함께 놓치는 경로가 있다", "경로 검사를 더하면 사각지대가 없어진다"],
               ["남의 스키마·실제 SDK에서도 같은 분해가 난다", "제3자 blind 평가를 마쳤다"],
               ["낮은 오탐은 provider 변화에 취약하다", "측정한 네 변화가 drift 전체를 대표한다"]],
              [width * 0.5, width * 0.5], st))
    add(Paragraph("표 6. 주장 경계.", st["cap"]))
    add(Paragraph(
        "결제는 0원 가상 원장, 메일은 외부 발송이 없는 로컬 mailbox, 파일은 임시 작업 공간, HTTP는 localhost sink만 "
        "사용했다. 공개 MCP 서버는 schema 조회에만 접속했고 그 서버로 효과를 만들지 않았다. 공격 표식은 "
        "ATTACKER_TEST_TARGET과 canary 문자열로 한정했고 실제 계정, 개인정보, 금전 피해는 만들지 않았다.", st["body"]))

    add(Paragraph("7. 결론", st["h"]))
    add(Paragraph(
        "MCP 도구 효과 검증의 사각지대는 세 축으로 갈린다. 영수증이 공격자와 독립일 때만 값 비교가 증거가 되고, "
        "계약이 열거한 필드 밖에서는 탐지가 거의 사라지며, 승인 인자를 통째로 해시에 묶으면 인자 공간의 경계는 "
        "닫히지만 provider 해석이라는 다음 경계가 드러난다. 영수증에 남지만 아무도 열거하지 않은 처리 경로는 두 "
        "방식이 함께 놓친다. 이 분해는 본 테스트베드의 성질이 아니다. 도구 표와 계약을 공개 MCP 서버에서 그대로 "
        "가져와도, 전송을 공식 SDK로 바꿔도 같은 모양이 나온다. 네 번째 축은 시간이다. 두 방식의 낮은 오탐은 "
        "검증자가 provider의 바이트 수준 관례를 재현하는 동안만 유지되고, 그 재현이 깨지는 지점은 방식마다 다르다. "
        "두 방식을 합성해도 D와 이 시간 축은 남는다. 경계는 없어지지 않고 자리를 옮긴다. 배치 판단은 provider "
        "영수증의 독립성 확보, 열거 범위의 명시, 최종 principal까지 영수증에 담게 하는 요구, 영수증 도착 대기 정책, "
        "그리고 영수증 스키마의 버전 협상에서 시작해야 한다.", st["body"]))

    add(Paragraph("참고문헌", st["h"]))
    add(Paragraph(
        "[1] Model Context Protocol, “Security Best Practices,” specification/draft/basic/security_best_practices, modelcontextprotocol.io, 2026 (accessed 2026-08-15).<br/>"
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
    drift_rows_total = sum(v["rows"] for v in drift.values()) if drift else 0
    by_name = {Path(e["file"]).name: e for e in rel.get("artifacts", [])}
    main_sha = by_name.get("main-suite.jsonl", {}).get("sha256", "")
    hold_sha = by_name.get("holdout-suite.jsonl", {}).get("sha256", "")
    # The count is read off the test file rather than typed, so adding a test
    # cannot leave a stale number in print.
    tests_total = (ROOT / "tests" / "test_v5.py").read_text(encoding="utf-8").count("def test_")
    add(Paragraph(
        f"코드·원시 JSONL 로그·분석 스크립트·실행 명령을 {rel.get('repository', '')} 에 공개한다. 본문 수치는 "
        f"커밋 {rel.get('commit_short', '')}에서 생성됐다. 원시 로그 SHA-256은 저장소의 "
        f"artifacts/v5/SHA256SUMS에 있고, 본 행렬은 {main_sha[:16]}…, hold-out은 {hold_sha[:16]}…이다. "
        f"본문의 모든 수치는 결정적 클라이언트 {a['rows']:,}행, hold-out {hold['rows']:,}행, 공식 SDK "
        f"{real['rows']:,}행, provider 변화 {drift_rows_total:,}행, 에이전트 루프 {llm.get('rows', 0):,}행 원시 "
        f"로그에서 분석 스크립트가 자동 집계했고 손으로 옮겨 적은 숫자는 없다. 스크립트는 두 오라클 구현의 라벨이 "
        f"전 행에서 일치하는지, 점추정이 자기 신뢰구간에 드는지, 그룹별 실행 수가 표본 합계를 재현하는지, 사전 기준 "
        f"판정이 임계값과 일치하는지를 매번 검사하고 하나라도 어긋나면 PDF 생성을 중단한다. 회귀 테스트 "
        f"{tests_total}종이 위 성질들을 고정한다. 전 과정은 GPU 없이 노트북 한 대에서 재현되며, 재현 명령은 "
        f"저장소 README와 artifacts/v5/release.json에 그대로 적혀 있다. 계약 해시·manifest 해시·학습 프로파일 "
        f"해시와 두 공개키는 평가 전에 freeze.json에 기록했다. 계열별·모델별 전량 표와 실패·제외 감사는 같은 "
        f"analysis.json에서 생성한 부록 결과보고서에 있다.", st["tiny"]))
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
                          title="MCP 도구 외부효과 검증의 사각지대 분해: "
                                "관측면 독립성 · 인자 결합 · 영수증 의미 범위")
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
    return page_count(OUT)


def page_count(path: Path) -> int:
    """Page count via poppler when present, PyMuPDF otherwise, so the build
    runs on machines without the poppler CLI tools."""
    try:
        return int(subprocess.run(["pdfinfo", str(path)], capture_output=True, text=True,
                                  check=True).stdout.split("Pages:")[1].split()[0])
    except (FileNotFoundError, subprocess.CalledProcessError, IndexError):
        import fitz
        with fitz.open(str(path)) as doc:
            return doc.page_count


def extract_text(path: Path) -> str:
    """Text of the finished PDF via poppler when present, PyMuPDF otherwise."""
    try:
        return subprocess.run(["pdftotext", str(path), "-"],
                              capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        import fitz
        with fitz.open(str(path)) as doc:
            return "\n".join(page.get_text() for page in doc)


def verify_render(path: Path, required: list[str]) -> None:
    """Read the built PDF back and confirm the strings that matter survived.

    A glyph the embedded font cannot map is dropped silently by the renderer,
    which is how an earlier build lost the middle of the oracle formula.  The
    text has to come back out of the finished file, not just go in.
    """
    # Raw mode, not -layout: -layout interleaves the two columns on a shared
    # visual line, which splices unrelated text into the middle of a phrase.
    text = extract_text(path)
    flat = " ".join(text.split())
    # A URL or a hash may be broken across a column line, so also match against
    # the text with all whitespace removed.
    dense = "".join(text.split())
    missing = [needle for needle in required
               if " ".join(needle.split()) not in flat
               and "".join(needle.split()) not in dense]
    if missing:
        raise SystemExit("rendered PDF is missing expected text:\n  "
                         + "\n  ".join(repr(m) for m in missing))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, default=ART / "analysis.json")
    args = parser.parse_args()
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    # Refuse to typeset a paper whose own numbers disagree with each other.
    problems = analysis.get("consistency", {}).get("problems")
    if problems is None:
        raise SystemExit("analysis.json predates the consistency gate; re-run analyze.py")
    if problems:
        raise SystemExit("analysis is internally inconsistent:\n  " + "\n  ".join(problems))
    # The reproducibility note names a repository and a commit, so refuse to
    # print one that has not been frozen.
    release_path = ART / "release.json"
    if not release_path.exists():
        raise SystemExit("artifacts/v5/release.json is missing; run v5/make_release.py")
    analysis["release"] = json.loads(release_path.read_text(encoding="utf-8"))
    for required in ("main-suite.jsonl", "holdout-suite.jsonl", "real-mcp-sdk-suite.jsonl"):
        if not any(entry["file"].endswith(required)
                   for entry in analysis["release"]["artifacts"]):
            raise SystemExit(f"release.json does not cover {required}")
    figures = {"heatmap": make_heatmap(analysis)}
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
    # The formula, the sample arithmetic and every gate verdict must be legible
    # in the finished file, not merely present in the source.
    gate_lines = [f"{gate['label']}" for gate in analysis["gates"]]
    verify_render(OUT, [
        "truth(c) = [ canonical(Replay(op, approved, m))",
        "!= canonical(proj_S(Receipts(cid))) ]",
        f"조건 {analysis['conditions']} × 관측면", "관측면 1종 =",
        "Ed25519", "공개키만",
        # The three answers to the strongest objections must survive the render.
        analysis["release"]["repository"], analysis["release"]["commit_short"],
        "코드를 공유하지 않는 두 구현", "발행자가 쓴 required 목록",
        "공식 MCP Python SDK", *gate_lines,
    ])
    print(json.dumps({"scale": best, "output": str(OUT), "render_check": "ok"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()

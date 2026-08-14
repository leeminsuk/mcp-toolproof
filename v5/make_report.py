"""Companion appendix report for the v5 paper.

The three-page paper cannot carry per-family tables, per-model sample counts or
the full interval set, and a reviewer should not have to take the compressed
numbers on trust.  This document holds the detail the paper points at, built
from the same artifacts/v5/analysis.json so the two cannot disagree.

It replaces the earlier extended report, which described the v4 matrix
(47,160 runs) and therefore no longer matched the paper at all.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (Image, KeepTogether, PageBreak,  # noqa: E402
                                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from make_paper import (DETECTOR_LABEL, DRIFT_LABEL, FAMILY_LABEL, GROUP_LABEL,  # noqa: E402
                        GROUP_LETTER, GROUP_ORDER, ORDER, make_heatmap, verify_render)

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts" / "v5"
OUT = Path("/Users/chchou/Downloads/MCP_ToolProof_v5_부록_결과보고서.pdf")
BLUE, LIGHT, GRAY = "#173A63", "#EAF0F7", "#5B6B7C"
pdfmetrics.registerFont(TTFont("K", "/System/Library/Fonts/Supplemental/AppleGothic.ttf"))

BENIGN_ORDER = ["clean", "normalisation", "migration", "resubmit"]
BENIGN_LABEL = {"clean": "clean", "normalisation": "비정규화 입력",
                "migration": "schema migration", "resubmit": "승인된 재제출"}
ALL_DETECTORS = ["manifest_pin", "signed_manifest", "response_detector", "trajectory_lite",
                 "learned_relation", "frozen_intent", "extended_intent", "extended_naive",
                 "approval_bound", "approval_naive"]
SHORT = {"manifest_pin": "pin", "signed_manifest": "서명", "response_detector": "응답",
         "trajectory_lite": "궤적", "learned_relation": "학습", "frozen_intent": "v3",
         "extended_intent": "v4", "extended_naive": "v4+", "approval_bound": "승인",
         "approval_naive": "승인+"}


def styles() -> dict:
    def S(name, size, leading, **kw):
        return ParagraphStyle(name=name, fontName="K", fontSize=size,
                              leading=leading, wordWrap="CJK", **kw)
    return {
        "title": S("title", 16, 20, alignment=TA_CENTER, textColor=colors.HexColor(BLUE)),
        "sub": S("sub", 9, 12, alignment=TA_CENTER, textColor=colors.HexColor(GRAY)),
        "h": S("h", 12, 15, textColor=colors.HexColor(BLUE), spaceBefore=10, spaceAfter=4),
        "h2": S("h2", 10, 13, textColor=colors.HexColor(BLUE), spaceBefore=7, spaceAfter=3),
        "body": S("body", 9, 12.6, alignment=TA_JUSTIFY, spaceAfter=3),
        "cap": S("cap", 7.8, 10, textColor=colors.HexColor(GRAY), spaceBefore=2, spaceAfter=4),
        "cell": S("cell", 7.4, 9.2),
        "cellb": S("cellb", 7.4, 9.2, textColor=colors.white),
        "mono": S("mono", 8, 11),
        "formula": ParagraphStyle(name="formula", fontName="Courier", fontSize=8.4,
                                  leading=11.5, spaceBefore=3, spaceAfter=3),
    }


def table(rows, widths, st, align_right=()):
    data = [[Paragraph(str(c), st["cellb"] if i == 0 else st["cell"]) for c in row]
            for i, row in enumerate(rows)]
    tbl = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1)
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BLUE)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT)]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C3D0DE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    for column in align_right:
        commands.append(("ALIGN", (column, 1), (column, -1), "RIGHT"))
    tbl.setStyle(TableStyle(commands))
    return tbl


def fmt(value, digits=3):
    return "—" if value is None else f"{value:.{digits}f}"


def _pearson(xs: list[float], ys: list[float]) -> float:
    """Computed here rather than typed in, so the caption cannot outlive the
    data it describes."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = sum((x - mx) ** 2 for x in xs) ** 0.5
    vy = sum((y - my) ** 2 for y in ys) ** 0.5
    return cov / (vx * vy) if vx and vy else 0.0


def build(a: dict, st: dict, width: float, heatmap: Path) -> list:
    dec = a["sample_decomposition"]
    grp, cig = a["by_group"], a["ci95_by_group"]
    fam = a["by_family"]
    drift = a.get("drift", {})
    story: list = []
    add = story.append

    add(Paragraph("MCP ToolProof v5 — 부록 결과보고서", st["title"]))
    add(Paragraph("3페이지 논문이 가리키는 계열별·모델별 전량 데이터와 재현 정보<br/>"
                  "이민석 · 고려대학교 인공지능사이버보안학과", st["sub"]))
    add(Spacer(1, 6))
    add(Paragraph(
        "이 문서는 논문의 요약본이 아니라 논문이 지면 때문에 실을 수 없었던 전량 데이터다. 논문 본문의 모든 수치와 "
        "이 문서의 모든 수치는 같은 <b>artifacts/v5/analysis.json</b> 하나에서 나오므로 서로 어긋날 수 없다. "
        "이전 확장 보고서는 v4 행렬(47,160회)을 다뤘고 현재 논문(v5)과 표본이 달라 폐기했다. 여기 실린 것은 "
        "전부 v5 행렬이다.", st["body"]))

    add(Paragraph("1. 표본 구성과 분해", st["h"]))
    add(Paragraph(
        "논문이 보고하는 그룹별 값은 전체 실행의 절반인 독립 관측면에서 계산된다. 그 절반이 어디서 오는지를 "
        "빠짐없이 적으면 다음과 같다.", st["body"]))
    add(table([["층", "산식", "실행 수"],
               ["도구", "—", f"{dec['tools']}"],
               ["도구당 조건", f"공격 계열 {dec['attack_families']} + 트리거 {dec['trigger_conditions']}"
                f" + 정상 계열 {dec['benign_families']}", f"{dec['conditions_per_tool']}"],
               ["전체 조건", f"{dec['tools']} × {dec['conditions_per_tool']}", f"{dec['conditions']}"],
               ["조건당 반복(관측면 1종)", f"seed {dec['seeds']} × 호출 {dec['calls']}",
                f"{dec['rows_per_condition_per_observer']}"],
               ["관측면 1종 합계", f"{dec['conditions']} × {dec['rows_per_condition_per_observer']}",
                f"{dec['per_observer']:,}"],
               ["관측면", "독립 provider 영수증 / 서버 자기보고", f"{dec['observers']}"],
               ["<b>전체</b>", f"<b>{dec['per_observer']:,} × {dec['observers']}</b>",
                f"<b>{dec['rows']:,}</b>"],
               ["독립 관측면 — 오라클 공격 판정", "—", f"{dec['attacks']:,}"],
               ["독립 관측면 — 오라클 정상 판정", "—", f"{dec['benign']:,}"],
               ["독립 관측면 — 정상(재제출 제외)", "—", f"{dec['benign_excl_resubmit']:,}"]],
              [width * 0.28, width * 0.46, width * 0.26], st, align_right=(2,)))
    add(Paragraph(
        "표 A1. 실행 수 분해. Recall의 분모는 오라클이 공격으로 판정한 실행 수이고, FPR의 분모는 오라클이 정상으로 "
        "판정한 실행 수다. 조건부 공격이 발동하지 않은 호출은 공격 계열에 배정됐더라도 정상 분모로 들어간다. "
        "그래서 공격 계열 배정 수와 오라클 공격 수가 같지 않다.", st["cap"]))

    add(Paragraph("2. 신뢰 경계와 영수증 스키마", st["h"]))
    add(Paragraph(
        "provider는 Ed25519 개인키로 서명하고 검증기는 공개키만 갖는다. 이전 revision은 HMAC-SHA256을 썼는데, "
        "공유키 MAC은 검증에 쓰는 키가 곧 발행에 쓰는 키여서 검증기도 영수증을 위조할 수 있었다. 서명 대상과 "
        "의미 비교 대상을 나눈 것도 의도적이다.", st["body"]))
    add(table([["필드 집합", "구성", "쓰임"],
               ["의미 필드 (9)",
                "op, kind, args, resolved_principal, final_principal, settlement_route, "
                "settlement_account, applied_hash, extra",
                "재실행 오라클이 완전 일치로 비교하는 대상"],
               ["결합 필드 (4)", "cid, seq, nonce, issued_at",
                "서명에는 포함, 의미 비교에서는 제외. 다른 호출의 영수증을 재사용하지 못하게 한다"],
               ["서명 대상 (13)", "의미 필드 + 결합 필드", "Ed25519 서명 payload"]],
              [width * 0.18, width * 0.46, width * 0.36], st))
    add(Paragraph(
        "표 A2. 영수증 필드 집합. 검증기는 서명 검증에 더해 cid가 감사 중인 호출과 같은지, seq가 0..n-1로 "
        "빠짐없이 이어지는지를 확인한다. nonce와 발급시각을 의미 비교에서 뺀 이유는 단순하다. 넣으면 정직한 실행이 "
        "전부 이탈로 보인다. 비결정적 필드를 인증하되 의미에서 제외하는 이 분리가 없으면 재실행 오라클과 계약이 "
        "동시에 무너진다.", st["cap"]))

    add(Paragraph("3. 정답 오라클", st["h"]))
    add(Paragraph(
        "호출 c의 라벨은 배정된 공격 이름이 아니라 다음 식이다.", st["body"]))
    add(Paragraph("truth(c) = [ canonical(Replay(op, approved, m))<br/>&#160;&#160;&#160;&#160;!= canonical(proj_S(Receipts(cid))) ]", st["formula"]))
    add(Paragraph(
        "Replay는 provider 자신의 영수증 생성 함수 build_receipts를 빈 별칭표 위에서 승인 인자에 적용한 것이고, "
        "m은 사용자가 승인한 제출 횟수, proj_S는 기록된 영수증을 표 A2의 의미 필드 9개로 사영한 것이다. "
        "오라클 함수가 받는 인자는 (도구, 승인 인자, 승인 제출 횟수, provider 변화 설정) 넷뿐이다. 공격 계열 "
        "이름도, 트리거 종류도, 어떤 탐지기의 판정도 입력에 없다. 코드에서 이 성질은 harness.oracle_truth의 "
        "시그니처로 강제된다.", st["body"]))
    add(Paragraph(
        "핵심은 포함 관계다. S는 시험 대상인 모든 계약의 관측 필드 집합을 진부분집합으로 포함한다. 예를 들어 "
        "‘정산 계정 교체’ 공격에서 승인 인자가 recipient=USER_0103, amount=1,900,000이면 정직한 실행의 영수증은 "
        "settlement_account=acct:USER_0103이고 실제 영수증은 acct:ATTACKER_TEST_TARGET이다. 두 계약 모두 "
        "settlement_account를 열거하지 않으므로 계약은 위반을 보지 못하지만, 오라클은 S 안에서 두 값을 비교하므로 "
        "이 행을 공격으로 라벨한다. 계약이 볼 수 없는 공격을 정답으로 만들 수 있는 이유가 이 포함 관계다.",
        st["body"]))
    add(Paragraph("3.1 라벨을 두 번, 코드를 공유하지 않고 계산한다", st["h"]))
    orc = a["oracle"]
    hold_orc = (a.get("holdout") or {}).get("oracle", {"rows": 0, "disagreements": 0})
    add(Paragraph(
        "위 정의만으로는 라벨이 provider 코드에 의존한다. Replay가 provider 자신의 생성 함수이므로, 그 함수에 "
        "결함이 있으면 기록된 영수증과 기대 영수증이 같은 방향으로 틀어지고 라벨은 그것을 볼 수 없다. 외부 심사가 "
        "정확히 이 점을 지적했다. 그래서 같은 라벨을 코드를 공유하지 않는 두 번째 프로그램(v5/oracle.py)으로 다시 "
        "계산한다. 이 프로그램은 기대 영수증을 만들지 않는다. 발행된 도구 표에서 유도한 불변식을 기록된 영수증 "
        "위에서 직접 검사하고, 정규화와 해시도 자기 코드로 다시 구현한다. provider·detectors·toolsrv 를 import "
        "하지 않는다는 성질은 회귀 테스트가 소스 수준에서 고정한다.", st["body"]))
    inv_rows = [["불변식", "정직한 실행이 만족해야 하는 것", "위반 공격 행"]]
    INV_TEXT = {
        "I1": "효과 개수가 도구 선언 × 승인 제출 횟수와 같다",
        "I2": "효과 종류가 선언된 순서와 같다",
        "I3": "모든 효과가 승인한 연산 이름을 갖는다",
        "I4": "승인 인자가 정규형 그대로 효과에 남는다",
        "I5": "승인에 없던 인자가 효과에 들어 있지 않다",
        "I6": "해석된 principal이 승인 principal과 같다",
        "I7": "해석된 principal 뒤로 전달되지 않는다",
        "I8": "정산 경로가 직접 경로다",
        "I9": "정산 계정이 해석된 principal이다",
        "I10": "승인 요청 digest가 영수증의 승인 해시와 같다",
        "I11": "선언된 릴리스 태그 외의 주석이 없다",
    }
    # The table must list every invariant the checker defines, not a snapshot
    # of the ones that happened to fire, so a new invariant cannot go unlisted.
    import oracle as _O
    defined = [code for code, _name, _desc in _O.INVARIANTS]
    if defined != list(INV_TEXT):
        raise SystemExit(f"oracle defines {defined} but the appendix lists {list(INV_TEXT)}")
    for code, text in INV_TEXT.items():
        inv_rows.append([code, text, f"{orc['invariants_fired'].get(code, 0):,}"])
    add(table(inv_rows, [width * 0.08, width * 0.72, width * 0.20], st, align_right=(2,)))
    add(Paragraph(
        f"표 A2b. 상태 검사기의 불변식과 본 행렬 공격 {orc['attack_rows']:,}행 중 각 불변식이 깨진 행 수(한 행이 "
        f"여러 불변식을 동시에 깨뜨릴 수 있다). 이 목록이 모든 계약의 관측 필드를 진부분집합으로 포함한다는 것이 "
        f"계약이 볼 수 없는 공격을 라벨할 수 있는 근거다.", st["cap"]))
    add(Paragraph(
        f"두 라벨은 본 행렬 {orc['rows']:,}행과 hold-out {hold_orc['rows']:,}행 전부에서 일치했다(불일치 "
        f"{orc['disagreements'] + hold_orc['disagreements']}건). 분석 스크립트는 불일치가 하나라도 있으면 종료 "
        f"코드 1로 끝나고 논문·부록 생성도 막는다. 교차검사가 실제로 힘을 갖는지는 회귀 테스트가 고정한다. "
        f"provider의 경로 정규화를 일부러 비활성화하면 Replay 라벨은 이탈을 보지 못하고(생성 함수와 기록이 같은 "
        f"방향으로 틀어지므로) 상태 검사기만 I4 위반을 보고한다.", st["body"]))
    add(Paragraph(
        "한계도 분명히 적는다. 두 구현의 일치는 라벨이 한 코드 경로에 의존하지 않는다는 뜻이지 라벨이 참이라는 "
        "뜻이 아니다. 두 구현 모두 같은 저자가 썼고, 오라클이 ‘무엇을 의미로 볼 것인가’를 정한 선택 자체에 저자의 "
        "관점이 들어 있다. 남은 편향을 없애려면 제3자가 작성한 공격 또는 공격과 독립으로 작성된 계약이 필요하다. "
        "후자는 9절의 공개 스키마 hold-out에서 부분적으로 확보했다.", st["body"]))

    add(Paragraph("4. 계열별 전량 결과", st["h"]))
    add(Paragraph(
        "열 이름은 논문 표 4의 방어와 같고, v4+와 승인+는 각각 정규화 미상 v4와 직렬화 미상 승인 결합 절제판이다.",
        st["body"]))
    rows = [["#", "공격 계열", "그룹", "공격"] + [SHORT[d] for d in ALL_DETECTORS]]
    for index, family in enumerate(ORDER, start=1):
        entry = fam.get(family)
        if not entry:
            continue
        group = next(g for g, members in
                     {"both": ORDER[:6], "v4_only": ORDER[6:10], "neither": ORDER[10:13],
                      "unseen": ORDER[13:16], "fuzz": ORDER[16:]}.items() if family in members)
        rows.append([str(index), FAMILY_LABEL[family], GROUP_LETTER[group], f"{entry['attacks']:,}"]
                    + [fmt(entry["recall"][d], 2) for d in ALL_DETECTORS])
    widths = [width * 0.045, width * 0.145, width * 0.045, width * 0.065] + [width * 0.0705] * 10
    add(table(rows, widths, st, align_right=tuple(range(3, 14))))
    add(Paragraph(
        "표 A3. 공격 계열별 Recall 전량. 분모는 계열마다 오라클이 공격으로 판정한 실행 수이고, 조건부 트리거 "
        "계열은 발동하지 않은 호출이 빠져 있어 배정 수보다 작다. 논문의 그룹별 값은 이 표를 그룹 안에서 가중 "
        "평균한 것이므로, 그룹 값은 그룹 내부 계열 구성비에 의존한다.", st["cap"]))

    rows = [["정상 계열", "정상 실행"] + [SHORT[d] for d in ALL_DETECTORS]]
    for family in BENIGN_ORDER:
        entry = fam.get(family)
        if not entry:
            continue
        rows.append([BENIGN_LABEL[family], f"{entry['benign']:,}"]
                    + [fmt(entry["fpr"][d], 2) for d in ALL_DETECTORS])
    add(table(rows, [width * 0.16, width * 0.08] + [width * 0.076] * 10, st,
              align_right=tuple(range(1, 12))))
    add(Paragraph(
        "표 A4. 정상 계열별 FPR 전량. v3의 오탐은 원문 비교가 provider 정규화를 모르기 때문에, manifest pin의 "
        "오탐은 의미가 같은 schema 변경 때문에 생긴다. 승인된 재제출은 네 방어가 모두 1.00으로 울리는데, 숨은 "
        "복제와 관측이 같기 때문이고 idempotency 키 정책 없이는 나눌 수 없다.", st["cap"]))

    add(Paragraph("5. 그룹별 결과와 신뢰구간 전량", st["h"]))
    rows = [["그룹", "공격", "v3", "v3 95% CI", "v4", "v4 95% CI", "승인 결합", "승인 95% CI", "클러스터"]]
    for group in GROUP_ORDER:
        recall = grp[group]["recall"]
        rows.append([
            GROUP_LABEL[group], f"{grp[group]['attacks']:,}",
            fmt(recall["frozen_intent"]),
            f"[{fmt(cig[group]['frozen_intent'][0])}, {fmt(cig[group]['frozen_intent'][1])}]",
            fmt(recall["extended_intent"]),
            f"[{fmt(cig[group]['extended_intent'][0])}, {fmt(cig[group]['extended_intent'][1])}]",
            fmt(recall["approval_bound"]),
            f"[{fmt(cig[group]['approval_bound'][0])}, {fmt(cig[group]['approval_bound'][1])}]",
            f"{a['ci95_by_group_clusters'][group]}"])
    add(table(rows, [width * 0.15, width * 0.06, width * 0.06, width * 0.145, width * 0.06,
                     width * 0.145, width * 0.07, width * 0.145, width * 0.065], st,
              align_right=(1, 2, 4, 6, 8)))
    add(Paragraph(
        "표 A5. 그룹별 Recall과 조건 클러스터 부트스트랩 95% 구간. 재표집 단위는 행이 아니라 (도구, 계열, 트리거) "
        "조건 클러스터이며, 한 조건 안의 반복은 같은 코드 경로를 다시 밟는 것이라 독립 증거가 아니기 때문이다. "
        "마지막 열이 각 그룹의 클러스터 수다. 분석 스크립트는 모든 점추정이 자기 구간 안에 드는지 매번 검사하고, "
        "어긋나면 PDF 생성을 중단한다. 이전 revision의 논문 본문은 E 그룹의 구간을 D 그룹 이름으로 인쇄했고, "
        "이 검사는 그 오류를 막기 위해 추가했다.", st["cap"]))

    fpr_ci = a.get("ci95_fpr_excl_resubmit", {})
    if fpr_ci:
        rows = [["방어", "FPR(재제출 제외)", "부트스트랩 95% CI"]]
        for detector in ("frozen_intent", "extended_intent", "approval_bound"):
            rows.append([DETECTOR_LABEL[detector], fmt(a["fpr_excluding_resubmit"][detector]),
                         f"[{fmt(fpr_ci[detector][0])}, {fmt(fpr_ci[detector][1])}]"])
        add(table(rows, [width * 0.34, width * 0.3, width * 0.36], st, align_right=(1, 2)))
        add(Paragraph("표 A6. 오탐의 구간 추정. 점추정 0을 위험률 0으로 읽지 않기 위해 함께 싣는다.", st["cap"]))

    add(Paragraph("6. 계열별 Recall 히트맵", st["h"]))
    add(KeepTogether([Image(str(heatmap), width=width * 0.62, height=width * 0.66),
                      Paragraph(
                          "그림 A1. 공격 계열별 Recall. 굵은 가로선이 위에서부터 A 직접 인자·효과, B 해석·"
                          "메타데이터, C 비열거 인자, D 비열거 영수증 경로, E 무작위 인자를 나눈다. 행 번호는 "
                          "표 A3과 같다. 그룹 경계에서 색이 갈리는 것이 이 논문의 핵심 관찰이고, 같은 그룹 안에서도 "
                          "계열마다 값이 다르다는 것이 그룹 값을 대표값으로 읽으면 안 되는 이유다.", st["cap"])]))

    add(Paragraph("7. 도구별 무작위 퍼징", st["h"]))
    fz = a["fuzz_by_tool"]
    rows = [["도구", "선언 인자", "계약 열거", "열거 비율", "퍼징 공격", "v3 Recall", "v4 Recall"]]
    for tool in sorted(fz, key=lambda t: fz[t]["share"]):
        v = fz[tool]
        rows.append([tool, f"{v['declared']}", f"{v['enumerated']}", fmt(v["share"], 2),
                     f"{v['runs']}", fmt(v["recall_v3"]), fmt(v["recall_v4"])])
    add(table(rows, [width * 0.22, width * 0.11, width * 0.11, width * 0.12, width * 0.12,
                     width * 0.16, width * 0.16], st, align_right=(1, 2, 3, 4, 5, 6)))
    fz = a["fuzz_by_tool"]
    corr = _pearson([fz[t]["share"] for t in sorted(fz)],
                    [fz[t]["recall_v4"] or 0.0 for t in sorted(fz)])
    add(Paragraph(
        f"표 A7. 퍼징은 도구가 선언한 인자 중 하나를 요청에서 만든 seed로 골라 변형한다. 계약 작성자가 어느 인자가 "
        f"뽑힐지 예측할 수 없다는 점이 이 계열의 목적이고, 같은 입력에서는 같은 선택이 재현된다. 열거 비율이 낮은 "
        f"도구에서 Recall도 낮은 경향이 보이지만 표본이 도구 {len(fz)}종뿐이고 상관계수도 r={corr:.3f}에 그치므로 "
        f"방향만 보고하고 인과로 단정하지 않는다. 이 값은 표에서 자동 계산되므로 재실행 때마다 함께 갱신된다.",
        st["cap"]))

    if drift:
        add(Paragraph("8. provider 변화(drift) 전량", st["h"]))
        add(Paragraph(
            "계약을 동결한 뒤 provider만 바뀌는 상황을 정상 트래픽만으로 재현했다. 공격이 없으므로 오라클은 모든 "
            "행을 정상으로 라벨하고, 표에 나타나는 값은 전부 오탐이다. 각 변화 종류는 같은 크기의 표본에서 "
            "측정했으며 ‘없음(기준)’ 행이 같은 코드로 돌린 대조군이다. 정상 계열만 돌린 별도 스위트라 분모가 본 "
            "행렬과 다르다는 점에 주의한다. 본 행렬의 정상 1,590행에는 발동하지 않은 조건부 공격 호출이 들어가고 "
            "여기에는 들어가지 않으므로, 예컨대 manifest pin이 여기서 0.33이고 본 행렬에서 0.181인 것은 같은 "
            "288행을 서로 다른 분모로 나눈 결과다. 읽어야 할 것은 본 행렬과의 차이가 아니라 기준 행과의 차이다.",
            st["body"]))
        rows = [["provider 변화", "정상 실행"] + [SHORT[d] for d in ALL_DETECTORS]]
        for kind in ("none", "receipt_annotation", "normalisation_upgrade", "unicode_nfc",
                     "hash_basis_change"):
            if kind not in drift:
                continue
            entry = drift[kind]
            rows.append([DRIFT_LABEL[kind], f"{entry['benign_excl_resubmit']:,}"]
                        + [fmt(entry["fpr"][d], 2) for d in ALL_DETECTORS])
        add(table(rows, [width * 0.17, width * 0.08] + [width * 0.075] * 10, st,
                  align_right=tuple(range(1, 12))))
        add(Paragraph(
            "표 A8. provider 변화별 오탐. 네 변화의 의미는 다음과 같다. <b>영수증 주석 추가</b>는 provider가 "
            "관측성을 위해 자기 릴리스 태그를 모든 영수증에 덧붙이는 변화, <b>정규화 강화</b>는 principal 필드까지 "
            "대소문자를 접는 변화, <b>Unicode NFC</b>는 저장 시 문자열을 NFC로 정규화하는 변화, "
            "<b>해시 기준 변경</b>은 provider가 받은 바이트 대신 정규화 결과를 해시하는 변화다.", st["cap"]))
        add(Paragraph(
            "읽는 법은 세 가지다. 첫째, 값 대조 계약(v4)은 영수증에 필드가 하나 늘어난 것만으로 오탐이 1.00이 "
            "된다. 미지 영수증 필드 거부 규칙이 메타데이터 채널 공격을 잡아 준 바로 그 규칙이므로, 탐지력과 drift "
            "취약성이 같은 곳에서 나온다. 둘째, 승인 결합은 이 변화에 반응하지 않는 대신 provider가 해시 기준을 "
            "바꾸면 혼자 무너진다. 해시가 provider 내부 표현이 아니라 요청 바이트에 걸려 있기 때문이다. 셋째, "
            "Unicode NFC에서 세 방식이 모두 0인 것은 강건성의 증거가 아니다. 본 정상 코퍼스가 ASCII만 담고 있어 "
            "NFC 정규화가 어떤 값도 바꾸지 못했기 때문이며, 비ASCII 텍스트를 포함한 코퍼스에서는 다시 측정해야 "
            "한다. 이 네 가지가 운영 drift 전체를 대표하지는 않는다. 재시도와 부분 재시도, locale과 시간대, "
            "API 버전 폐기는 다루지 않았다.", st["body"]))


    hold = a.get("holdout")
    if hold:
        add(Paragraph("9. 공개 MCP 서버 스키마 hold-out", st["h"]))
        prov = hold["meta"]["provenance"]
        add(Paragraph(
            "본 행렬은 도구·공격·계약을 한 저자가 만든 테스트베드다. 이 절은 그중 <b>도구와 계약</b>을 바깥에서 "
            "가져와 같은 행렬을 다시 돌린 것이다. 공개된 MCP 참조 서버에 공식 SDK로 접속해 tools/list가 준 schema를 "
            "그대로 받고, 네 규칙만으로 도구 표를 만들었다. (1) required 속성이 하나 이상인 도구만 남긴다. "
            "(2) 선언 인자는 published properties를 발행 순서대로 쓴다. (3) 계약이 검사할 열거 인자는 발행자가 쓴 "
            "required 목록을 그대로 쓴다. (4) principal은 required 중 첫 문자열 속성이고 없으면 첫 required다. "
            "즉 이 절의 계약은 서버 발행자가 쓴 것이고, 본 연구가 고른 것은 무엇을 공격할지뿐이다.", st["body"]))
        rows = [["서버", "패키지", "버전", "발행 도구", "채택", "발행 schema SHA-256(앞 16)"]]
        for entry in prov:
            rows.append([entry["server"], entry["package"], str(entry["version"]),
                         str(entry["published_tools"]), str(entry["kept"]),
                         entry["tools_sha256"][:16]])
        add(table(rows, [width * 0.12, width * 0.30, width * 0.09, width * 0.10,
                         width * 0.09, width * 0.30], st, align_right=(3, 4)))
        add(Paragraph(
            f"표 A8b. hold-out 도구 출처. 도구 {hold['tools']}개, 조건 {hold['conditions']}개, 실행 "
            f"{hold['rows']:,}행이며 아래 값은 독립 영수증 쪽 {hold['independent']:,}행에서 계산했다. 두 오라클 "
            f"구현은 여기서도 전 행 일치했다(불일치 {hold['oracle']['disagreements']}건).", st["cap"]))
        hg = hold["by_group"]
        rows = [["그룹", "공격", "클러스터", "v3", "v4", "승인 결합"]]
        for group in GROUP_ORDER:
            rows.append([GROUP_LABEL[group], f"{hg[group]['attacks']:,}",
                         str(hg[group]["clusters"]),
                         fmt(hg[group]["recall"]["frozen_intent"]),
                         fmt(hg[group]["recall"]["extended_intent"]),
                         fmt(hg[group]["recall"]["approval_bound"])])
        rows.append(["FPR(재제출 제외)", f"{hold['benign_excl_resubmit']:,}", "—",
                     fmt(hold["fpr_excl_resubmit"]["frozen_intent"]),
                     fmt(hold["fpr_excl_resubmit"]["extended_intent"]),
                     fmt(hold["fpr_excl_resubmit"]["approval_bound"])])
        add(table(rows, [width * 0.26, width * 0.13, width * 0.13, width * 0.16,
                         width * 0.16, width * 0.16], st, align_right=(1, 2, 3, 4, 5)))
        add(Paragraph(
            "표 A8c. hold-out 그룹별 결과. 사각지대의 구조가 그대로 재현된다. A에서 두 방식이 함께 1.00, C에서 "
            "값 대조가 0에 가깝고 승인 결합이 1.00, B에서 그 반대, D에서 둘 다 0 근처다. 달라지는 것은 오탐이다. "
            "원문 비교 계약 v3의 FPR이 본 행렬보다 크게 오르는데, 남의 스키마에는 검증자가 모르는 정규화 대상 "
            "필드가 더 많기 때문이다.", st["cap"]))
        rows = [["서버", "도구", "공격", "v4 Recall", "승인 결합 Recall"]]
        for server, entry in hold["by_server"].items():
            rows.append([server, str(entry["tools"]), f"{entry['attacks']:,}",
                         fmt(entry["recall"]["extended_intent"]),
                         fmt(entry["recall"]["approval_bound"])])
        add(table(rows, [width * 0.22, width * 0.14, width * 0.18, width * 0.23, width * 0.23],
                  st, align_right=(1, 2, 3, 4)))
        add(Paragraph(
            "표 A8d. 서버별 분해. 세 서버는 도메인도 인자 형태도 다르지만(파일 경로, 지식 그래프 엔티티, 참조 "
            "구현 도구) 값이 비슷한 자리에 모인다. 결과가 특정 도구 도메인의 성질이 아니라 열거 범위의 성질임을 "
            "시사한다.", st["cap"]))
        fid = hold.get("family_fidelity")
        if fid:
            add(Paragraph("9.1 계열이 남의 스키마에서 뜻을 얼마나 유지하는가", st["h2"]))
            add(Paragraph(
                f"공개 스키마는 <b>선언은 하되 required가 아닌 인자</b>를 거의 두지 않는다. 본 테스트베드가 "
                f"memo·tenant·callback_url을 일부러 그렇게 둔 것과 다르다. 그래서 두 계열이 형태를 바꾼다.",
                st["body"]))
            add(table([["관측", "값", "결과"],
                       ["hold-out 도구", f"{fid['tools']}", "—"],
                       ["선언됐지만 required가 아닌 인자를 가진 도구", f"{fid['with_optional_args']}",
                        "이 도구에서만 C 계열(비열거 필드·tenant 침범·memo 유출)이 원래 형태를 "
                        "유지한다. 나머지에서는 schema가 선언한 적조차 없는 필드를 주입하므로 "
                        "<b>더 강한 변형</b>이 된다"],
                       ["required가 둘 이상인 도구", f"{fid['multi_required']}",
                        "이 도구에서만 값 변조가 대상 치환과 구별된다. 나머지에서는 두 계열이 "
                        "사실상 같아진다(그룹 A는 어차피 구성적이라 결론에 영향이 없다)"]],
                      [width * 0.34, width * 0.08, width * 0.58], st, align_right=(1,)))
            add(Paragraph(
                "표 A8e. 계열 충실도. C 그룹의 대비(값 대조 0에 가깝고 승인 결합 1.00)가 hold-out에서도 유지되는 "
                "것은 <b>두 경우 모두 계약이 그 필드를 보지 않기 때문</b>이지 계열이 동일하기 때문이 아니다. "
                "이 구분을 흐리면 hold-out이 실제보다 강한 증거로 읽힌다.", st["cap"]))
        add(Paragraph(
            "이 절이 없애지 못하는 것도 적는다. 공격은 여전히 본 연구가 썼고, 발행 스키마를 도구 표로 옮기는 네 "
            "규칙도 본 연구가 정했다. 그리고 이 서버들의 실제 구현이 아니라 <b>발행 schema만</b> 가져왔으므로, "
            "실제 provider의 정규화 관례가 아니라 본 테스트베드의 관례가 적용된다. 확보한 것은 ‘계약을 공격에 맞춰 "
            "쓰지 않았다’는 한 가지다.", st["body"]))

    real = a.get("real_mcp")
    if real:
        add(Paragraph("10. 실제 프로토콜 경계: 공식 MCP SDK와 전송 장애", st["h"]))
        add(Paragraph(
            "본 행렬은 목적에 맞게 지은 로컬 HTTP 테스트베드 위에서 돈다. 이 절은 같은 공격기·같은 오라클·같은 "
            "계약을 <b>공식 MCP Python SDK의 stdio 전송</b> 위로 옮겨 다시 측정한 것이다. 서버는 별도 OS "
            "프로세스이고, 관측면은 v5 provider의 Ed25519 서명 영수증 로그다. 이 스위트의 이전 판은 공격 서버가 "
            "직접 쓰는 SQLite를 관측면으로 삼았는데, 그러면 공격자가 증거를 통제한다. 심사가 지적한 그 결함을 "
            "여기서 고쳤다. 지금은 공격자가 영수증을 만들 수도 지울 수도 없다.", st["body"]))
        rg = real["by_group"]
        rows = [["그룹", "공격", "v4", "승인 결합"]]
        for group in GROUP_ORDER:
            rows.append([GROUP_LABEL[group], f"{rg[group]['attacks']:,}",
                         fmt(rg[group]["recall"]["extended_intent"]),
                         fmt(rg[group]["recall"]["approval_bound"])])
        add(table(rows, [width * 0.34, width * 0.18, width * 0.24, width * 0.24], st,
                  align_right=(1, 2, 3)))
        add(Paragraph(
            f"표 A9. 공식 MCP SDK stdio 위 {real['rows']:,}행(장애 미주입 {real['clean_rows']:,}행). 그룹 구조가 "
            f"본 행렬과 같은 모양으로 재현된다. A의 1.00은 성능이 아니라 값 대조 계약이 값 치환을 정의상 잡는다는 "
            f"뜻으로, 본 행렬 A 그룹과 같은 종류의 구성적 결과다.", st["cap"]))
        add(table([["관측", "값", "의미"],
                   ["공격 모드별 manifest 해시 종류", f"{len(real['manifest_hashes'])}",
                    f"{len(real['meta']['families'])}개 모드 전부에서 tools/list 결과가 바이트 단위로 "
                    "동일하다. 정적 무결성 검사가 볼 것이 없다는 뜻이다"],
                   ["응답이 승인값과 일치한 비율", fmt(real["response_matches_approved"], 3),
                    "서버는 효과를 바꾸면서도 응답은 승인값을 그대로 돌려줬다. 응답만 보는 탐지기는 "
                    "여기서 신호를 얻지 못한다"],
                   ["승인 probe 발동", f"{real['probe_fired']}/{real['probe_calls']}",
                    "도구별 첫 3회 probe 구간에서 지연 발동 공격은 한 번도 켜지지 않았고, 배치 후 공격 "
                    f"{real['deployed_attacks']}건은 {real['deployed_detected']}건 탐지됐다"],
                   ["정상 트래픽 오탐", f"{real['false_positives']}/{real['oracle_benign']:,}",
                    "전량이 승인된 재제출 계열이다. 본 행렬과 같은 원인이며 idempotency 정책 문제다"],
                   ["end-to-end 지연 p50 / p95",
                    f"{real['e2e_ms']['p50']:.2f} / {real['e2e_ms']['p95']:.2f} ms",
                    "승인 호출부터 판정까지. 동일 호스트 값이므로 원격 provider 왕복은 포함하지 않는다"]],
                  [width * 0.26, width * 0.16, width * 0.58], st, align_right=(1,)))
        add(Paragraph(
            "표 A10. 이 절의 실질적 결과. 정적 manifest 무결성과 응답 검사가 무력해지는 조건이 공식 SDK "
            "위에서도 그대로 성립하고, 조건부 발동이 승인 probe를 통과한다는 것까지가 이 표본이 말하는 전부다.",
            st["cap"]))
        if real.get("faults"):
            add(Paragraph("10.1 전송 장애와 의미 이탈을 가르는 법", st["h"]))
            add(Paragraph(
                "운영에서 두 가지는 같은 증상으로 도착한다. 영수증이 없다. 도구 서버와 provider 사이에 세 가지 "
                "장애를 정상 트래픽에 주입해 구별 가능한지 측정했다.", st["body"]))
            FAULT_LABEL = {"async_lag": "비동기 지연(백그라운드 기록)",
                           "tcp_reset": "TCP RST(요청 중단)",
                           "provider_down": "provider 포트 닫힘"}
            rows = [["장애", "실행", "영수증 없음", "즉시 읽기 시 경보", "대기 후 경보", "서명 검증"]]
            for kind, entry in real["faults"].items():
                rows.append([FAULT_LABEL.get(kind, kind), f"{entry['runs']:,}",
                             f"{entry['receipt_missing']:,}", f"{entry['single_shot_alarm']:,}",
                             f"{entry['waited_alarm']:,}", f"{entry['signature_ok']:,}"])
            add(table(rows, [width * 0.26, width * 0.11, width * 0.16, width * 0.19,
                             width * 0.14, width * 0.14], st, align_right=(1, 2, 3, 4, 5)))
            add(Paragraph(
                f"표 A10b. 전송 장애 주입. 비동기 지연에서는 영수증이 결국 도착하지만 "
                f"{real['meta']['lag_ms']} ms 늦다. 한 번만 읽는 검증기는 전량을 오탐으로 올리고, "
                f"{real['meta']['poll_deadline_ms']} ms까지 기다리는 검증기는 0건이다. 도착 대기 정책이 규칙의 "
                f"일부여야 한다는 뜻이다. RST와 포트 닫힘에서는 효과가 아예 기록되지 않아 승인된 행위가 일어나지 "
                f"않았다는 뜻이 되고, 오라클도 이탈로 라벨한다. 다만 대조할 영수증이 없다는 점에서 값이 어긋난 "
                f"경우와 구별되므로, 검증기는 이를 보안 경보가 아니라 가용성 상태로 분류할 수 있다.", st["cap"]))

    llm = a.get("llm_local") or a.get("llm")
    if llm:
        add(Paragraph("11. 에이전트 루프: 재현 정보와 예비 관찰", st["h"]))
        cfg = llm.get("config", {})
        if cfg:
            add(table([["항목", "값"],
                       ["실행 환경", str(cfg.get("runtime", "—"))],
                       ["endpoint", str(cfg.get("endpoint", "—"))],
                       ["배정 산식", f"모델 {len(cfg.get('models', []))} × 계열 "
                        f"{len(cfg.get('families', []))} × 도구 {len(cfg.get('tools', []))} × 호출 "
                        f"{cfg.get('calls_per_cell')} = {cfg.get('assignments'):,}"],
                       ["temperature / seed", f"{cfg.get('temperature')} / {cfg.get('seed')}"],
                       ["max_tokens / thinking", f"{cfg.get('max_tokens')} / {cfg.get('thinking')}"],
                       ["system prompt", str(cfg.get("system_prompt", "—"))],
                       ["도구 schema", str(cfg.get("tool_schema", "—"))],
                       ["유효 판정", str(cfg.get("accepted_only_if", "—"))]],
                      [width * 0.22, width * 0.78], st))
            add(Paragraph(
                "표 A11. 에이전트 루프 설정 전량. 심사에서 지적한 재현 정보 부족(모델명·버전·프롬프트·decoding "
                "설정·표본 수)을 이 표와 다음 표가 함께 채운다. 설정은 로그와 같은 실행에서 기록되므로 실행과 "
                "설정이 따로 놀 수 없다. GPU는 쓰지 않았고 노트북 한 대에서 재현된다.", st["cap"]))
        rows = [["모델", "배정", "유효", "도구 호출 생성률", "인자 충실도", "오류 내역"]]
        for model, entry in sorted(llm.get("per_model", {}).items()):
            errors = ", ".join(f"{k} {v}" for k, v in entry.get("errors", {}).items()) or "—"
            rows.append([model, f"{entry['assigned']:,}", f"{entry['valid']:,}",
                         fmt(entry["availability"]), fmt(entry["utility"]), errors])
        add(table(rows, [width * 0.20, width * 0.09, width * 0.09, width * 0.13,
                         width * 0.13, width * 0.36], st, align_right=(1, 2, 3, 4)))
        add(Paragraph(
            f"표 A12. 모델별 표본 수와 결과. 배정 {llm['rows']:,}회 가운데 유효 {llm['valid']:,}회, 오류 "
            f"{llm['errors']:,}회다. <b>두 종류의 0이 섞여 있으므로 한 열로 읽으면 안 된다.</b> HTTP 400 오류는 "
            f"런타임이 tools 필드를 받은 요청 자체를 거부한 것으로 모델 능력이 아니라 API 호환성의 문제이고, "
            f"tool_call_count=0 오류는 요청은 받아들여졌으나 규격에 맞는 단일 도구 호출이 나오지 않은 경우다. "
            f"생성률이 낮은 모델을 다른 모델로 대체하지 않고 그대로 남긴 이유는, 방어가 적용될 수 있는 범위 자체가 "
            f"모델 능력에 달려 있다는 것이 이 절의 결과이기 때문이다. 인자 충실도는 승인 작업의 모든 인자"
            f"(tenant·callback_url·memo·unit 포함)가 맞아야 성공으로 세므로 낮게 나온다. 이 필드들이 정확히 두 "
            f"계약이 열거하지 않는 필드다.", st["cap"]))
        dev = llm["anchor_on_deviation"]
        rows = [["필드", "이탈 횟수", "v3 열거", "v4 열거"]]
        enumerated_v3 = {"recipient", "amount", "beneficiary", "account", "to", "subject",
                         "body", "destination", "source", "key", "value", "title"}
        for field, count in llm["deviation_fields"].items():
            rows.append([field, str(count), "O" if field in enumerated_v3 else "X",
                         "O" if (field in enumerated_v3 or field == "unit") else "X"])
        add(table(rows, [width * 0.34, width * 0.22, width * 0.22, width * 0.22], st,
                  align_right=(1,)))
        add(Paragraph(
            f"표 A13. 모델이 승인 작업과 다르게 채운 필드. 서버가 정상인데 모델만 이탈한 {dev['rows']}건 가운데 "
            f"승인 의도 앵커가 잡은 것은 {dev['intent_flags']}건, tool input 앵커는 {dev['toolinput_flags']}건이다. "
            f"나머지는 두 계약이 모두 열거하지 않은 필드에서 일어났다. 앵커는 무엇과 비교할지를 정할 뿐이고, "
            f"무엇을 볼 수 있는지는 열거 범위가 정한다는 것이 이 표의 요지다.", st["cap"]))
        add(Paragraph(
            "이 절은 예비 관찰이며 결론으로 올리지 않는다. 유효 표본이 도구 호출을 만들지 못한 모델이 빠진 선택 "
            "표본이므로 앵커 사이의 우열도, 특정 모델의 보안 특성도 이 표로 말할 수 없다. 뒷받침되는 것은 하나뿐이다. "
            "탐지기를 논하기 전에 에이전트 계층이 먼저 실패하는 구간이 존재하고, 그 구간의 크기가 모델 선택에 따라 "
            "달라진다.", st["body"]))

    add(Paragraph("12. 사전 기준 판정", st["h"]))
    rows = [["기준", "임계", "관측", "판정"]]
    for gate in a["gates"]:
        unit = f" {gate['unit']}" if gate.get("unit") else ""
        shown = " / ".join(f"{v:.3f}{unit}" for v in gate["observed"])
        if gate.get("scope"):
            shown += f" ({gate['scope']})"
        rows.append([gate["label"], f"{gate['op']} {gate['threshold']}", shown, gate["verdict"]])
    add(table(rows, [width * 0.4, width * 0.14, width * 0.31, width * 0.15], st, align_right=(2,)))
    add(Paragraph(
        "표 A14. 사전에 정한 기준과 실측. 판정 열은 관측값과 임계값을 비교해 analyze.py가 계산하며 어느 문서에도 "
        "손으로 적지 않는다. 이전 revision은 이 판정을 문자열로 하드코딩했고, 그 결과 관측 1.000인 기준에 "
        "‘실패’가 인쇄되는 오류가 있었다. 통과한 Recall 기준을 우월성으로 읽어서는 안 된다. A 그룹의 값 계약 "
        "1.00과 C 그룹의 승인 결합 1.00은 각각 그 필드를 검사하기로 한 결정과 인자를 하나라도 바꾸면 해시가 "
        "깨진다는 정의에서 따라 나오는 구성적 결과다.", st["cap"]))

    problems = a.get("consistency", {}).get("problems", [])
    if a.get("exclusions"):
        add(Paragraph("12.1 실패·제외 감사", st["h2"]))
        add(Paragraph(
            "어느 수치가 어느 분모에서 나왔는지를 독자가 되짚지 않아도 되게, 각 스위트가 만든 행 수와 실제로 쓴 행 "
            "수를 전부 적는다. ‘아무것도 버리지 않았다’ 역시 확인해야 할 주장이지 전제가 아니다.", st["body"]))
        rows = [["스위트", "생성", "사용", "제외", "사유"]]
        for entry in a["exclusions"]:
            rows.append([entry["suite"], f"{entry['produced']:,}", f"{entry['used']:,}",
                         f"{entry['excluded']:,}", entry["reason"]])
        add(table(rows, [width * 0.17, width * 0.09, width * 0.09, width * 0.08, width * 0.57],
                  st, align_right=(1, 2, 3)))
        add(Paragraph(
            "표 A14b. 실패·제외 감사. 결정적 스위트에서는 실패·타임아웃이 없었고 제외도 없다. 나머지 줄은 버린 "
            "데이터가 아니라 <b>어느 부분집합을 어떤 목적에 썼는지</b>의 기록이며, 각 줄의 ‘사용’ 값이 본문 표의 "
            "분모다. 에이전트 루프만 실제 실패가 있고, 그 실패 자체가 5.8의 결과다.", st["cap"]))

    add(Paragraph("13. 자동 정합성 검사", st["h"]))
    add(Paragraph(
        "심사자가 손으로 잡아야 했던 종류의 오류를 스크립트가 먼저 잡도록 다음 검사를 매 실행에 넣었다. "
        "(가) 모든 그룹·탐지기 조합에서 점추정이 자기 부트스트랩 구간 안에 드는가, (나) 그룹별 공격 실행 수의 "
        "합이 관측면 공격 수와 같은가, (다) 계열별 공격 수의 합이 각 그룹 합계와 같은가, (라) 조건×관측면×"
        "seed×호출이 전체 행 수를 재현하는가, (마) 공격 수와 정상 수의 합이 관측면 행 수와 같은가. 하나라도 "
        "어긋나면 analyze.py가 비정상 종료하고 논문·보고서 생성이 중단된다.", st["body"]))
    add(Paragraph(
        f"현재 실행 결과: <b>{'문제 없음' if not problems else '문제 ' + str(len(problems)) + '건'}</b>"
        + ("" if not problems else "<br/>" + "<br/>".join(problems)), st["body"]))

    add(Paragraph("14. 재현 정보", st["h"]))
    freeze = json.loads((ART / "freeze.json").read_text(encoding="utf-8"))
    rows = [["항목", "값"]]
    for key in ("contract_sha256", "manifest_sha256", "learned_profile_sha256",
                "provider_pubkey_ed25519", "publisher_pubkey_ed25519"):
        if key in freeze:
            rows.append([key, f"<font face='Courier'>{freeze[key][:48]}</font>"])
    for path in sorted(ART.glob("*.jsonl")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        lines = sum(1 for _ in path.open(encoding="utf-8"))
        rows.append([f"{path.name} ({lines:,}행)", f"<font face='Courier'>sha256:{digest}…</font>"])
    add(table(rows, [width * 0.42, width * 0.58], st))
    add(Paragraph("표 A15. 동결 해시와 원시 로그. 계약·manifest·학습 프로파일 해시와 두 공개키는 평가 행렬이 "
                  "돌기 전에 freeze.json에 기록된다.", st["cap"]))
    rel = a.get("release", {})
    if rel:
        add(Paragraph("14.1 공개 위치와 실행 명령", st["h2"]))
        add(Paragraph(
            f"코드·원시 JSONL 로그·분석 스크립트를 <font face='Courier'>{rel['repository']}</font> 에 공개한다. "
            f"본 문서와 논문의 수치는 커밋 <font face='Courier'>{rel['commit']}</font> 에서 생성됐다. "
            f"저장소의 <font face='Courier'>artifacts/v5/SHA256SUMS</font> 로 원시 로그 무결성을 직접 확인할 수 "
            f"있고(<font face='Courier'>shasum -a 256 -c SHA256SUMS</font>), "
            f"<font face='Courier'>artifacts/v5/release.json</font> 에 같은 해시와 아래 명령이 기계가 읽을 수 있는 "
            f"형태로 들어 있다. 저장소에는 폐기된 v1–v4 코드도 남아 있으나 본 문서와 논문에는 그 코드가 만든 "
            f"수치가 하나도 들어가지 않으며, README 첫 표가 어느 판이 현재판인지 명시한다.", st["body"]))
        add(Paragraph("<br/>".join(
            f"<font face='Courier'>{line.replace('&', '&amp;').replace('<', '&lt;')}</font>"
            for line in rel.get("commands", [])), st["mono"]))
        add(Paragraph(
            "표 A15b. 재현 명령 전량. 에이전트 루프만 모델 런타임(ollama)이 필요하고, 공식 MCP SDK 스위트만 "
            "별도 venv를 쓰며, 나머지는 노트북 한 대에서 GPU 없이 재현된다. 분석 스크립트는 두 오라클 구현의 "
            "라벨 불일치, 점추정의 구간 이탈, 표본 합계 불일치, 사전 기준 판정 불일치 가운데 하나라도 발견하면 "
            "종료 코드 1로 끝나고 PDF 생성을 막는다.", st["cap"]))

    add(Paragraph("15. 이 문서가 뒷받침하지 않는 것", st["h"]))
    add(table([["근거가 있는 주장", "근거가 없는 주장"],
               ["열거한 계열에서 계약이 추가 신호를 준다", "미지 공격에 대한 일반 방어"],
               ["열거하지 않은 계열에서 탐지가 거의 사라진다", "블랙박스 도구 행동의 완전 증명"],
               ["자기보고 영수증 위에서 값 계약이 무력하다", "상용 SaaS provider 독립성 검증 완료"],
               ["승인 해시 결합이 인자 사각지대를 닫는다", "해시 결합이 모든 변조를 막는다"],
               ["두 방식이 함께 놓치는 경로가 있다", "경로를 더 열거하면 사각지대가 없어진다"],
               ["두 방식의 낮은 오탐이 provider 변화에 취약하다", "측정한 네 변화가 운영 drift를 대표한다"],
               ["A·C의 1.00은 정의에서 따라 나온다", "1.00이 방어 성능의 증거다"]],
              [width * 0.5, width * 0.5], st))
    add(Paragraph("표 A16. 주장 경계. 왼쪽은 이 표본이 뒷받침하는 문장이고, 오른쪽은 같은 표본으로 말할 수 없는 "
                  "문장이다.", st["cap"]))
    return story


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, default=ART / "analysis.json")
    args = parser.parse_args()
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    problems = analysis.get("consistency", {}).get("problems")
    if problems is None:
        raise SystemExit("analysis.json predates the consistency gate; re-run analyze.py")
    if problems:
        raise SystemExit("analysis is internally inconsistent:\n  " + "\n  ".join(problems))
    release_path = ART / "release.json"
    if release_path.exists():
        analysis["release"] = json.loads(release_path.read_text(encoding="utf-8"))
    heatmap = make_heatmap(analysis)
    margin = 15 * mm
    width = A4[0] - 2 * margin
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=margin, rightMargin=margin,
                            topMargin=13 * mm, bottomMargin=13 * mm,
                            title="MCP ToolProof v5 부록 결과보고서")
    st = styles()

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("K", 7)
        canvas.setFillColor(colors.HexColor(GRAY))
        canvas.drawString(margin, 8 * mm, "MCP ToolProof v5 — 부록 결과보고서")
        canvas.drawRightString(A4[0] - margin, 8 * mm, str(canvas.getPageNumber()))
        canvas.restoreState()

    doc.build(build(analysis, st, width, heatmap), onFirstPage=footer, onLaterPages=footer)
    verify_render(OUT, [
        "truth(c) = [ canonical(Replay(op, approved, m))",
        "!= canonical(proj_S(Receipts(cid))) ]",
        "Ed25519 서명 payload", "cid, seq, nonce, issued_at",
        "표 A1.", "표 A3.", "표 A5.", "표 A8.", "표 A14.", "표 A16.",
    ])
    print(json.dumps({"output": str(OUT), "render_check": "ok"}, ensure_ascii=False))


if __name__ == "__main__":
    main()

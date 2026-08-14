# MCP ToolProof — MCP 도구 외부효과 검증의 사각지대 분해

> Decomposing the Blind Spots of MCP Tool-Effect Verification:
> Observer Independence, Argument Commitment, and Receipt Semantic Coverage

KIISC 3쪽 논문 「MCP 도구 외부효과 검증의 사각지대 분해」의 코드·원시 로그·분석 스크립트 전체다.
논문에 인쇄된 모든 수치는 이 저장소의 JSONL 로그에서 `v5/analyze.py`가 자동 집계한 값이며, 손으로
옮겨 적은 숫자는 없다.

승인된 MCP 도구 서버가 manifest와 응답을 정상으로 유지한 채 실제 외부 효과만 바꿀 때, 세 가지 검증
축(관측면 독립성 · 승인 인자의 해시 결합 · 계약이 열거한 영수증 의미 범위)이 만드는 사각지대가 서로를
어떻게 보완하고 어디서 함께 무너지는지를 같은 workload에서 분해해 측정한다.

---

## 무엇이 현재판인가

**`v5/`만 논문의 근거다.** 저장소 루트의 `run_*.py`, `evaluate_*.py`, `make_final_pdfs.py` 등은
v1–v4 실험 코드이며 **폐기됐다**. 논문에는 이 코드가 만든 수치가 **하나도 들어가지 않는다**.

| 판 | 상태 | 이유 |
|---|---|---|
| v1–v2 | 폐기 | 정답 라벨이 배정된 공격 이름이었다 |
| v3–v4 (47,160회 행렬 포함) | 폐기 | 탐지 결과가 실험이 아니라 코드 정의에서 나왔다. `execute()`가 변형한 dict을 `contract_violations()`가 같은 args와 비교했고, 방어 네 가지가 `False` 리터럴이었으며, 조건부 발동이 구현되지 않았다 |
| **v5** | **현재판** | provider 프로세스 분리, Ed25519 영수증, 조건부 발동 실구현, 정답 라벨의 이중 구현 |

감사 목적으로 이전 코드를 지우지 않고 남겼다. 어느 판의 수치를 인용해야 하는지 헷갈릴 여지를 없애기
위해 이 표를 맨 앞에 둔다.

---

## 재현

GPU는 필요 없고 노트북 한 대에서 전 과정이 재현된다. CPython 3.14.6(macOS arm64)에서 검증했다.

```bash
pip install -r requirements.txt                    # 결정적 스위트·분석·문서 생성
python3 -m venv runtime/mcp-sdk-venv               # 공식 MCP SDK 스위트만 별도 인터프리터
runtime/mcp-sdk-venv/bin/pip install -r requirements-mcp.txt
```

에이전트 루프(4번)만 [ollama](https://ollama.com)가 추가로 필요하다.

```bash
# 1. 본 행렬 13,824행 + provider 변화(drift) 5종
v5/run_suites.sh

# 2. 공개 MCP 서버 스키마 hold-out (도구 26종, 계약은 발행자의 required 목록)
python3 v5/holdout.py --seeds 3 --calls 12

# 3. 공식 MCP Python SDK stdio 전송 + 전송 장애 주입
runtime/mcp-sdk-venv/bin/python v5/real_mcp.py --repeats 12

# 4. 에이전트 루프 (ollama 로컬 모델)
python3 v5/llm_layer.py --models qwen3:4b qwen2.5:7b gemma3:4b gemma4:12b \
    llama3.1:8b llama3.2:3b mistral:7b --calls 3 \
    --out artifacts/v5/llm-local-suite.jsonl

# 5. 분석 (일관성 게이트가 하나라도 깨지면 종료 코드 1)
python3 v5/analyze.py --main artifacts/v5/main-suite.jsonl \
    --llm-local artifacts/v5/llm-local-suite.jsonl \
    --drift artifacts/v5/drift-*.jsonl \
    --real-mcp artifacts/v5/real-mcp-sdk-suite.jsonl \
    --holdout artifacts/v5/holdout-suite.jsonl \
    --out artifacts/v5/analysis.json

# 6. 회귀 테스트
python3 -m pytest tests/test_v5.py -q

# 7. 동결 기록 + 논문·부록 PDF
python3 v5/make_release.py && python3 v5/make_paper.py && python3 v5/make_report.py
```

원시 로그 무결성 확인:

```bash
cd artifacts/v5 && shasum -a 256 -c SHA256SUMS
```

`artifacts/v5/release.json` 에 저장소 URL, 커밋 해시, 실행 명령, 모든 산출물의 SHA-256이 들어 있다.

---

## 구조

```
v5/
  toolspec.py    도구 표(선언). TOOLPROOF_TOOLTABLE 로 외부 스키마 교체 가능
  provider.py    독립 프로세스 provider. Ed25519 영수증 발행, 개인키 단독 보유
  toolsrv.py     공격자 통제 MCP 스타일 도구 서버. 17개 공격 계열 + 조건부 트리거
  oracle.py      정답 라벨 (2/2) — provider 코드를 쓰지 않는 불변식 상태 검사기
  detectors.py   방어 6종 + 절제판 4종. 모두 실제로 계산된다
  harness.py     본 행렬. 라벨을 두 구현으로 계산하고 불일치를 기록한다
  holdout.py     공개 MCP 서버 스키마 → 도구 표 기계 변환 → 같은 행렬 재실행
  mcp_server.py  공식 MCP SDK 서버(공격자 측). 전송 장애 3종 주입
  real_mcp.py    공식 MCP SDK 클라이언트 + 독립 provider 관측면
  llm_layer.py   에이전트 루프 (모델이 도구·인자를 직접 고른다)
  analyze.py     집계 + 사전 기준 판정 + 자기일관성 게이트
  make_paper.py  3쪽 논문 PDF (analysis.json 에서 직접 생성)
  make_report.py 부록 결과보고서 PDF
  make_release.py 커밋·해시·실행 명령 동결
tests/test_v5.py 회귀 테스트 26종
artifacts/v5/    원시 JSONL 로그, 동결 기록, 분석 결과
```

논문이 어느 로그에서 나왔는지는 `artifacts/v5/release.json` 의 `artifacts` 목록이 정한다. 그 목록에
없는 파일은 논문의 근거가 아니다. 특히 `artifacts/v5/llm-suite.jsonl` 은 A100 노드에서 돌린 에이전트
루프 로그인데, **정답 라벨을 이중 계산하기 이전 코드**에서 나왔으므로 논문·부록 어디에도 쓰지 않는다.
감사 목적으로만 남긴다. 에이전트 루프의 근거는 `llm-local-suite.jsonl`(노트북 재실행분)뿐이다.

## 정답 라벨을 두 번 계산하는 이유

라벨을 만드는 코드가 관측 대상과 같으면, 그 코드의 결함은 라벨을 같은 방향으로 움직여 보이지 않게
된다. 그래서 두 프로그램이 각각 라벨을 만든다.

- **생성형(replay)** — `provider.faithful_receipts`. 승인 인자에 provider 자신의 의미론을 적용해
  정직한 영수증 순열을 만들고 기록된 영수증과 전량 대조한다.
- **선언형(state checker)** — `oracle.py`. 기대 영수증을 만들지 않고, 발행된 도구 표에서 유도한
  불변식 11개를 기록된 영수증 위에서 직접 검사한다. `provider`·`detectors`·`toolsrv` 를 import
  하지 않는다(회귀 테스트가 고정).

두 라벨은 본 행렬 13,824행과 hold-out 44,928행 전부에서 일치했다. 일치 자체가 라벨의 참을 보장하지는
않지만(두 구현 모두 같은 저자), 라벨이 한 코드 경로에 의존하지 않는다는 뜻이다. 교차검사가 실제로
힘을 갖는지는 `tests/test_v5.py::IndependentStateChecker` 가 고정한다 — provider의 정규화를 일부러
망가뜨리면 replay 라벨은 변화를 보지 못하고 상태 검사기만 위반을 보고한다.

## 안전과 윤리

결제는 0원 가상 원장, 메일은 외부 발송이 없는 로컬 mailbox, 파일은 임시 작업 공간, HTTP는 localhost
sink만 사용한다. 공개 MCP 참조 서버에는 `tools/list` 조회만 했고 그 서버로 효과를 만들지 않았다.
공격 표식은 `ATTACKER_TEST_TARGET` 과 canary 문자열로 한정했으며 실제 계정·개인정보·금전 피해는
만들지 않는다.

## 인용

```
이민석, "MCP 도구 외부효과 검증의 사각지대 분해: 관측면 독립성 · 인자 결합 · 영수증 의미 범위",
한국정보보호학회, 2026.
```

## 라이선스

MIT (`LICENSE`). 원시 로그와 분석 산출물은 CC BY 4.0.

# MCP ToolProof Experiment

정상 manifest와 정상 응답을 유지하면서 외부 효과만 조건부로 바꾸는 MCP-style 도구 서버를 실제 Ollama tool-calling loop로 검증한다.

## 안전성

- 결제는 0원 가상 ledger다.
- 메일은 메모리 mailbox에만 기록한다.
- 파일은 메모리 filesystem만 사용한다.
- 외부 전송, 실제 계좌, 실제 메일, 개인정보를 사용하지 않는다.

## 실행

```bash
python3 -m unittest discover -s tests -v
python3 run_experiment.py --phase pilot
python3 evaluate.py artifacts/raw/pilot.jsonl
```

모든 결과는 `artifacts/raw/*.jsonl`에서 계산한다. 논문 수치를 직접 입력하지 않는다.

## 확장 검증

```bash
# 모델별 3,744회(12도구·6공격·확장 변형·정상 대조)
python3 run_gpu.py --model qwen3:8b --endpoint http://127.0.0.1:11434 \
  --extended --output artifacts/extended/qwen3-8b.jsonl

# 계약 규칙 적대 테스트, 프로세스/TCP 경계, 공식 MCP SDK 경계
python3 run_adversarial_contract_suite.py
python3 run_network_boundary_suite.py
runtime/mcp-sdk-venv/bin/python run_real_mcp_suite.py

# PP·보수적 ITT·paired McNemar 및 최종 PDF
python3 analyze_final.py artifacts/gpu-final/combined-v2.jsonl artifacts/extended/gpu-*.jsonl \
  --output artifacts/final/analysis.json \
  --adversarial artifacts/adversarial-contract-suite.jsonl \
  --network artifacts/network-boundary-suite.jsonl \
  --mcp artifacts/real-mcp-sdk-suite.jsonl
python3 make_final_pdfs.py
```

LLM agent loop, 합성 계약 단위 테스트, TCP/SQLite 경계, MCP SDK 경계는 서로 다른 모집단이다. 실행 수는 공개하되 하나의 F1로 합산하지 않는다. 호출 오류는 원본에서 삭제하지 않고 PP와 ITT를 함께 보고한다.

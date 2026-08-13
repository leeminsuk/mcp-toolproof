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


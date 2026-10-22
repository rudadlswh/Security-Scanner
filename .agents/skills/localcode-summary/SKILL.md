---
name: localcode-summary
description: LocalCode Review MCP로 이미 완료된 합성 C 4건의 평가 요약을 조회한다. 과거 실험의 관찰·규칙 결과와 설명·인용 축을 확인할 때 사용한다.
---

# 완료 평가 요약

`localcode_review` MCP의 `get_synthetic_evaluation_summary`를 인자 없이 호출한다. 반환된 사례별 관찰·규칙 분류와 설명·인용 결과를 구분해 한국어로 요약한다.

합성 4건 각 1회, AI 단독 라벨, 독립 사람 검토 없음이라는 한계를 함께 적는다. 전체 정확도·일반화·코드 안전을 주장하지 않는다. 완료된 실험 재실행이나 새 Ollama 호출은 하지 않는다.

연결된 도구가 없으면 MCP 연결을 확인하도록 안내하고 결과를 추측하지 않는다.

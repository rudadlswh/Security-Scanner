---
name: localcode-check
description: LocalCode Review MCP로 고정 Java 예제의 보안 동작 검사를 실행한다. CVE 조회 없는 로컬 예제 검사를 요청할 때 사용한다.
---

# 예제 보안 검사

`localcode_review` MCP의 `run_sample_security_check`를 `{"check_runtime_cves": false}`로 한 번 호출한다. 서버 시작 시 고정한 Java 예제만 검사하며 임의 프로젝트 경로를 받지 않는다.

실제 반환값에서 검사 완료 여부, 재현된 결함, 회귀 테스트, 원본 변경 여부와 `report_id`를 한국어로 요약한다. 검사 완료를 코드 안전으로 표현하지 않는다. 실패하면 자동 재시도하지 않는다.

연결된 도구가 없으면 MCP 연결을 확인하도록 안내하고 검사 결과를 만들어 내거나 다른 검사기로 대체하지 않는다. 이 명령은 CVE 공지 조회와 Ollama 생성을 실행하지 않는다.

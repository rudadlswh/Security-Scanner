---
name: localcode-cve
description: LocalCode Review MCP로 고정 Java 예제 검사와 Oracle 공지의 JDK 영향 버전 대조를 실행한다. 예제의 CVE 조회 포함 검사를 요청할 때 사용한다.
---

# CVE 조회 포함 예제 검사

`localcode_review` MCP의 `run_sample_security_check`를 `{"check_runtime_cves": true}`로 한 번 호출한다. 고정 Java 예제를 실행하고 공개 Oracle 2026년 4월 공지를 조회한다. 소스 원문을 외부로 보내거나 Ollama를 호출하지 않는다.

실제 반환값의 결함 재현과 JDK 영향 버전 일치를 분리해 한국어로 설명하고 `report_id`를 남긴다. 버전 일치는 CVE 악용 검증이 아니며 최신 전체 CVE 또는 전체 의존성 검사가 아니다.

실패하면 자동 재시도하지 않는다. 연결된 도구가 없으면 MCP 연결을 확인하도록 안내하고 결과를 추측하거나 다른 검사기로 대체하지 않는다.

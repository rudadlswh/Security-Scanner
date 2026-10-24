# MCP 연결

저장소 루트에서 Python 의존성과 Java 브리지를 준비한 뒤 MCP 클라이언트에 STDIO 서버를 등록한다. `client-config.example.json`은 일반 JSON 형식 예시, `codex.config.example.toml`은 TOML 설정 예시다. 자신의 Python·저장소 절대 경로로 바꾼다. 실제 로컬 설정을 Git에 올리지 않는다.

서버 진입점은 `python -u /absolute/path/Security-Scanner/mcp_server.py --config /absolute/path/localcode-review.json`이다. 표준 출력은 MCP 메시지 전용이다. 도구는 `get_product_capabilities`로 확인하고, 폴더 검사는 `scan_project`에 절대 경로를 전달한다.

현재 `/6`은27개 도구·4개 프롬프트를 제공한다. 전체 도구 목록은 [README](../README.md#mcp-도구-목록)에 있다. 감사 후보 검증은 `verify_audit_candidates(report_id, grant_id)`로 시작하고 반환된 job_id로 `get_audit_verification_status`/`cancel_audit_verification`을 호출한다. grant와 별도 모델 opt-in은 로컬 운영자가 먼저 준비해야 한다. [감사 계약](../docs/audit-contract.md)을 따른다.

모델·외부 네트워크·일회용 서버는 기본 연결만으로 승인되지 않는다. [실행 설정](../docs/folder-scan.md)을 별도로 준비한다. 기존 연결이 유지 중이면 새 프로세스가 실제 수정 코드를 읽었는지 구분한다.

`.agents/skills`의 네 명령은 고정 Java 예제 검사·그 공지 대조·보고서 조회·과거 합성 요약용 호환 기능이다. 예제 대상 경로나 과거 요약 자료가 없으면 해당 명령을 사용할 수 없다. 새 폴더의 통합 검사는 이 명령들과 구분해 `scan_project`를 사용한다.

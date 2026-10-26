# Python 검사와 근거 연결

product-workflow/7은 Python 표준 라이브러리 `http.server`의 **리터럴 dispatch 지원 구간**을 검사한다. Flask/Django/FastAPI/ASGI 전체 지원이나 완전한 Python 실행 해석을 뜻하지 않는다.

## 단일 검사

등록한 Python 대상은 MCP `scan_project` 또는 CLI로 검사할 수 있다. `PROJECT_PATH`는 실제 대상의 절대 경로로 바꾼다. 게시본은 사용자의 프로젝트·실행 프로필을 자동 등록하지 않는다.

```powershell
python -m localcode_review_mcp scan PROJECT_PATH --max-ai-endpoints 0 --no-remediation
```

검사는 새 실행이다. 이미 저장한 결과를 조회하려면 [검증 안내](verification.md)의 ID/경로를 사용한다. 정상 완료된 검증을 단순 조회 목적으로 다시 실행하지 않는다.

## 검사 출처

- **LocalCode Python AST:** 직접 선언된 `BaseHTTPRequestHandler`와 GET 등의 리터럴 경로 분기, query reader, 직접 self 호출 최대8단계, 선택 SQL/HTML/객체 조회/파일 읽기 후보를 연결한다. 명시적 비교·공개 루트 검사 인식은 제한된 문법 규칙이며 호출자 신뢰나 전체 권한 정책 증명이 아니다.
- **Bandit:** 운영자가 지정한 인터프리터/고정 버전을 사용한다. 읽은 소스의 임시 복사본만 분석하고 프로젝트 모듈을 import하지 않는다. 프로젝트 설정/`nosec`에 탐지 생략을 맡기지 않는다. 파일·줄·규칙·CWE·버전·소스 해시를 정규화하고 원문 코드/비밀번호가 들어갈 수 있는 발췌는 저장하지 않는다.
- **PyPI:** 운영자 프로필에서 켠 경우에만 고정 pip-audit로 정확한 requirements 핀을 조회한다. 패키지를 설치하거나 전이 의존성을 해결하지 않는다. 원시 항목과 alias로 합친 패키지별 공지 수를 구별한다. 기존 OSV 전역 허용 설정과 별개이며 기본 자동 승인은 없다.

같은 SQL 후보가 AST와 Bandit에 중복될 수 있다. 후보 합계를 서로 다른 실제 취약점 수로 표시하지 않는다. 분석 엔진과 실제 HTTP 관찰은 별도 필드다.

## 소스·HTTP·브라우저

운영자 `scan_profiles`의 `python_validation`에 프로젝트 밖 계획 파일과 정규화 JSON SHA-256을 등록한다. `python-http-validation/1`은 소스 해시, 허용 경로, GET 요청, 기대 상태/본문·헤더 비교, 명시한 음성 사례, 선택적 소스 sink 바인딩을 가진다. 임의 명령이나 URL은 MCP 입력에서 받지 않는다.

서버는 기존 DisposableServer의 복사본·Windows Job·소유 루프백 확인을 사용한다. 실행 전에 계획에 묶인 **복사된 소스 바이트**까지 대조한다. 파일이 다르면 실행을 거부한다. 이는 호스트 프로세스 보호이며 OS 보안 샌드박스는 아니다. 정리 상태와 작업 인스턴스/PID/시각/제품 코드 해시를 보존한다.

HTTP 보고서는 실제 상태 코드·응답 해시·리터럴 비교 boolean을 저장하고 인증 토큰/본문은 저장하지 않는다. GET 자체가 부작용 없다는 보장은 없으므로 운영자가 승인한 일회용 대상에만 쓴다. 실습 신원 수집은 등록한 고정 엔드포인트에서 메모리로만 한다.

선택형 Playwright/Edge 검사는 별도 headless 컨텍스트에서 지정 title 표식의 실행 여부를 확인한다. 외부 요청·서비스 워커·WebSocket을 막고 브라우저를 Job에 묶는다. **예상 HTTP 응답도 일치해야** 차단으로 판정한다. 네트워크 오류/404를 XSS 차단으로 세지 않는다.

## 대표 의존성 전후 검증

`python_dependency_runtime`은 운영자가 미리 준비한 두 가상환경, 고정 계획/버전, 공지 근거 파일 해시를 사용한다. 제품이 패키지를 설치/업그레이드하거나 수정 버전을 선택하지 않는다.

등록 가능한 두 고정 probe는 로컬 자체 서명 TLS 서버의 Requests 검증 상태와 Jinja custom filter에 넘긴 format의 **가짜 객체 속성 노출**만 시험한다. 호스트 파일·명령 실행 payload는 사용하지 않는다. 버전·모듈 바이트·기본 정상 API·정리 결과를 기록한다. 표본 서버는 해당 두 패키지를 사용하지 않으므로 이 전후 시험은 표본 앱의 배포 호환성이나 모든 CVE 해결을 뜻하지 않는다.

## 제한과 승인

Python 소스는 로컬 분석용이다. 비밀번호 후보가 있는 파일도 로컬 탐지 대상에 포함하지만 기존 Java AI 계약으로 전송하는 경로는 거부한다. Python AI 설명/자동 수정은 구현하지 않았다. 새 모델 예산을 만들거나 기존 닫힌 예산을 재사용하지 않는다.

독립 검토자가 실제로 참여하기 전에는 의미 검토/독립성 상태를 올리지 않는다. 개발 환경의 내부12사례와 실습46사례는 같은 조수가 설계한 범위 검증이며 실무 일반화의 증거가 아니다.

도구 동작 근거: [Bandit CLI](https://bandit.readthedocs.io/en/latest/man/bandit.html), [Playwright 브라우저](https://playwright.dev/python/docs/browsers). 실제 검사 출처·버전·범위는 저장 보고서를 따른다.

## 게시본에서의 선택 도구 준비

기본 AST 분석과 MCP 서버는 기존 requirements-mcp.txt를 사용한다. 선택 검사 도구는 별도 가상환경에 설치한다. 대상의 requirements.txt를 검사 도구 환경에 설치하지 않는다.

```powershell
python -m venv .venv-python-tools
.venv-python-tools/Scripts/python.exe -m pip install -r requirements-python-tools.txt
```

실제 브라우저 검사는 Windows의 설치된 Microsoft Edge와 별도 headless 컨텍스트를 사용한다. 브라우저/대표 의존성 worker는 Windows Job 보호를 요구한다. 다른 OS 지원을 주장하지 않는다. 각 인터프리터 경로·버전·계획 해시는 운영자가 등록해야 한다. [프로필 예시](../mcp/python-scan-profile.example.json)는 자리표시자이며 그대로 실행하지 않는다. 실제 소스/진단/로컬 설정/가상환경/과거 실행 결과는 게시하지 않는다.

# Java/Spring 폴더 검사 사용법

MCP `scan_project(project_path)` 또는 CLI `scan`에 프로젝트의 절대 경로를 전달한다. 폴더 조사 → 정적 후보 → 승인된 AI 관찰 → CVE → 등록된 HTTP → 안내 → 선택한 복사본 수정 검증 → JSON/Markdown 보고서 순서다. 설정이 없거나 지원하지 않는 단계는 미실행으로 보고한다.

## 설정과 진입점

`python -m localcode_review_mcp configure`로 프로젝트를 등록한다. 기본 설정은 `localcode-review.json`이며 Git에서 제외한다. 초기 형식은 루트의 `localcode-review.example.json`을 참고한다. 다른 파일을 쓰면 명령 앞에 `--config 실제경로`를 지정한다.

| 도구 | 기능 |
| --- | --- |
| `scan_project` | 폴더 통합 검사 시작 |
| `get_project_scan_status`, `read_project_scan_report` | 실행 상태·보고서 조회 |
| `cancel_project_scan` | 취소와 해당 서버·복사본 정리 |
| `inspect_project`, `collect_endpoint_evidence` | 조사와 엔드포인트 근거 수집 |
| `inspect_dependencies`, `scan_dependency_cves` | 의존성 목록과 CVE 대조 |
| `run_http_security_check` | 등록된 일회용 HTTP 검사 |
| `verify_project_fix` | 승인된 복사본 수정·빌드·전후 검사 |
| `get_fix_verification_status`, `cancel_fix_verification` | 수정 검증 조회·취소 |

MCP는 ID를 반환하고 상태 도구로 완료를 조회한다. CLI 통합 검사는 완료까지 기다린다. ID 문자열 자체는 PowerShell 명령이 아니다. 보고서 디렉터리는 검사 대상 폴더 밖이어야 한다.

## 소스와 AI 관찰

`prepareProductRuntime`으로 JDK AST 브리지를 빌드한다. 대상 빌드나 annotation processor를 자동 실행하지 않는다. 엔드포인트 기본 상한100, AI 상한20이며 누락 수량을 기록한다.

AI를 쓰려면 루프백 Ollama 주소·설치 모델 이름·전체 digest와 새 로컬 호출 예산이 필요하다. `authorize-model --calls N --minutes N`은 실제 생성을 허용하는 운영자 명령이다. 검증되지 않은 외부 주소나 열린 수신 환경은 전송을 차단한다. 기본 원문 로그는 OFF이며 진단 저장은 명시적으로 허용해야 한다.

모든 AI를 끄려면 MCP의 `max_ai_endpoints=0`, `include_remediation=false`를 함께 지정한다. CLI는 `--max-ai-endpoints 0 --no-remediation`이다. 정책은 모델 입력에 넣지 않고 하네스 규칙으로 비교한다. 응답 enum의 진실성까지 규칙이 검증하지는 못한다.

작은 요청은 보수적인 UTF-8 바이트 상한으로 컨텍스트를 검사한다. 큰 요청용 특정 Qwen 토큰 측정 프로필의 과거 보정 파일은 이 게시본에 없다. 해당 경로는 측정 불가로 차단되며, 큰 입력이나 다른 환경의 정확한 토큰 측정을 일반 지원한다고 표시하지 않는다.

## 의존성 CVE

온라인 조회는 `allow_osv_network=true`일 때만 OSV API를 사용한다. 기본은 로컬 캐시만 확인하며 캐시 없음·만료·조회 실패는 불명이다. 공개 패키지 이름과 버전만 조회한다. JDK 런타임 공지는 별도 범위다.

`lcr-resolved-inventory/1`은 소스 입력·앱 JAR·runtime 디렉터리의 정확한 JAR 집합과 해시를 대조한다. 일반 SBOM/운영자 목록은 `PROVIDED_COMPONENTS_ONLY`, 선언만 읽으면 전이 의존성의 완전성을 주장하지 않는다.

승인된 Gradle 복사본에서 `tools/dependency-inventory.init.gradle`과 `localcodeInventory` 태스크를 사용하면 runtime 목록을 내보낼 수 있다. Gradle 빌드는 프로젝트 코드를 실행하므로 자동으로 승인하지 않는다. Maven은 외부 해결 목록/SBOM을 받는다.

CVE 공지는 패키지 안에서 ID/별칭이 겹치면 묶는다. 패키지별 그룹 수 합계를 고유 CVE 수나 악용 가능한 취약점 수로 해석하지 않는다. 수정 후보는 `selected_version=null`, `compatibility_verified=false`를 유지하며 브랜치·BOM·JDK 호환성 확인을 대신하지 않는다.

## 일회용 서버와 Docker

운영자가 설정한 `scan_profiles`의 명령만 실행한다. 대상 README나 대상 폴더의 설정에 적힌 명령을 자동 실행하지 않는다. `mcp/scan-profile.example.json`, `http-target.example.json`, `http-plan.example.json`은 형식 예시이며 실제 실행 승인이 아니다.

대상 경로·실행 파일·인자 배열·폐기 가능한 DB·테스트 신원·허용 경로·준비/조회/요청/정리 시나리오를 확인한 뒤 등록한다. 본문·인증 헤더·서버 원문 출력은 기본 저장하지 않는다. 상태 probe는 boolean만 명시 저장한다.

기본 `local_process`는 Windows Job과 소유 루프백 수신을 확인한다. **OS 샌드박스는 아니다.** `require_os_isolation=true`면 로컬 실행을 거부한다.

`isolation_backend=docker`는 로컬 Linux Docker 엔진, 운영자가 사전 설치한 `이름@sha256:전체digest` 이미지, 이미지 안의 `/bin/bash`·`/bin/cat`이 필요하다. 엔진이나 이미지가 없으면 호스트 실행으로 강등하지 않는다.

비관리자·읽기 전용 루트/복사본·capability 제거·no-new-privileges·자원 제한·내부 네트워크·로그 driver none을 설정하고 검사한다. Docker 포트를 게시하지 않고 소유한 호스트 `127.0.0.1` 소켓에서 Docker exec의 stdin/stdout을 통해 컨테이너 내부 루프백으로 연결한다. 요청을 셸 명령에 보간하지 않는다.

중계 설정 상한은 동시16연결·방향별16MiB·연결당300초다. 이 숫자는 모든 상한 초과·만료·부하 시험의 완료 주장이 아니다. IPv6·모든 호스트 통신 경로·컨테이너 탈출 방어는 검증 범위 밖이다. 종료 시 중계 연결·서버·네트워크·복사본을 정리한다.

## 복사본 수정 검증

프로필의 `fix_verification`에 `authorized_copy_only_verification`, `acknowledge_build_execution`, 해시 고정 수정 묶음, 빌드 명령과 수정 전후 기대값을 등록한다. 묶음은 `version=1`, `edits=[{path,before_sha256,old,new}]`다.

경로 이탈·중복·해시 불일치·유일하지 않은 교체를 거부하고 복사본만 수정한다. `run_fix_verification_after_scan=true`를 지정하면 통합 실행 마지막에 연결한다. 원본 자동 적용·배포는 하지 않는다.

빌드는 호스트 프로세스 경계다. 강한 격리가 필요한 프로필이면 호스트 빌드로 우회하지 않는다. `MATCHES_FROZEN_CHECKS`는 등록한 정적 규칙과 HTTP 기대 조건의 충족이며 전체 호환성·보안 승인이 아니다.

실패·취소·시간 초과는 자동 재시도하지 않는다. 원격 완료나 정리가 불명확하면 해당 잠금을 유지하며, 운영자가 상태를 확인해야 한다. 소진한 호출을 복구하거나 예산을 자동 증액하지 않는다.

## Python /7

표준 http.server 리터럴 dispatch 지원 구간과 선택 도구를 추가했다. [Python 설정과 제한](python-analysis.md)을 따른다. 프레임워크 전체 지원·원문 AI 전송·배포 호환성 보증은 제공하지 않는다.

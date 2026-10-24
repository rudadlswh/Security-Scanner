# LocalCode Review

Java/Spring 프로젝트를 읽기 전용으로 조사하고 AST 보안 후보·승인된 로컬 AI 관찰·의존성 공지·등록 HTTP 검사·복사본 수정 검증을 연결한다. 현재 개발 버전은 **product-workflow/6**, 기본 HTTP 점검 영역 계약은 **security-remediation/17**, MCP는 **27개 도구/4개 프롬프트**다.

현재 기능과 게시용 검증 범위는 [검증 안내](docs/verification.md)를 따른다. 전체 보안·독립 검토·모든 프로젝트 정확성을 보증하지 않는다.

## 사용

- 폴더 통합 검사: MCP `scan_project(project_path)` 또는 `python -m localcode_review_mcp scan PROJECT_PATH`.
- AI 없는 검사: `scan PROJECT_PATH --max-ai-endpoints 0 --no-remediation`.
- 새 수집 평가: `freeze-benchmark`, `benchmark`.
- 선택형 소스 기반 AI 가설: `analyze-source`; 프로젝트 opt-in·별도 활성 예산·진단 저장 승인 필요.
- 저장 AI 가설 근거 대조: `validate-source-proposal`.
- 독립 검토자 선언·판정 기록: `record-independent-review`. 검토자를 자동 생성하거나 신원을 인증하지 않는다.
- 범위·후보 감사 원장: 통합 보고서의 `audit`와 로컬 `record-audit-review`. [입력 계약과 한계](docs/audit-contract.md).
- 새 감사 검토는 등록 Ed25519 키 서명을 요구한다. 선택형 `verify_audit_candidates`는 별도 모델·새 검증 전용 승인만 사용하며 자동 확정하지 않는다.
- 기존 `/` 명령 `localcode-check`, `localcode-cve`, `localcode-reports`, `localcode-summary`는 고정 예제/과거 결과용이다.

[폴더 검사](docs/folder-scan.md) · [새 평가·소스 분석·CVE 수정 검증](docs/assurance-workflows.md) · [MCP 연결](mcp/README.md)

## MCP 도구 목록

현재 연결에 노출된 도구는 27개다. 아래 이름은 MCP 도구 이름이며, 채팅용 슬래시 명령은 다음 절에 정리했다.

| 도구 | 기능 |
| --- | --- |
| `get_capabilities` | 기본 기능·예제 경로·지원 범위 조회 |
| `get_product_capabilities` | 제품 버전·설정·실행 코드 해시·재시작 필요 여부 조회 |
| `list_projects` | 등록된 프로젝트 목록 조회 |
| `inspect_project` | 프로젝트 구조와 엔드포인트 조사 |
| `collect_endpoint_evidence` | 엔드포인트 AST 근거 메타데이터 수집 |
| `scan_project` | 폴더 통합 검사 시작 |
| `get_project_scan_status` | 통합 검사 진행 상태 조회 |
| `read_project_scan_report` | 통합 보고서 조회 |
| `cancel_project_scan` | 통합 검사 취소 및 소유 서버 정리 |
| `review_endpoint` | 승인된 예산으로 AI 관찰 시작 |
| `get_review_status` | AI 관찰 상태와 원격 완료 여부 조회 |
| `cancel_review` | AI 관찰 취소 |
| `inspect_dependencies` | 의존성 목록 조사 |
| `scan_dependency_cves` | 의존성 버전과 CVE 공지 대조; 기본은 캐시 조회 |
| `run_http_security_check` | 등록·허용된 일회용 루프백 환경의 HTTP 검사 |
| `verify_project_fix` | 복사본에 수정 묶음 적용·빌드·전후 검증 시작 |
| `get_fix_verification_status` | 복사본 수정 검증 상태 조회 |
| `cancel_fix_verification` | 수정 검증 취소 및 소유 자원 정리 |
| `verify_audit_candidates` | 별도 모델·검증 전용 grant로 감사 후보 검증 시작 |
| `get_audit_verification_status` | 감사 검증 작업 상태 조회 |
| `cancel_audit_verification` | 감사 검증 작업 취소 |
| `list_product_reports` | 제품 보고서 목록 조회 |
| `read_review_report` | 제품·감사·검증 보고서 조회 |
| `run_sample_security_check` | 고정 Java 예제 검사·선택적 Oracle JDK 영향 버전 대조 |
| `list_security_reports` | 예제 검사 보고서 목록 조회 |
| `read_security_report` | 예제 검사 보고서 조회 |
| `get_synthetic_evaluation_summary` | 완료된 합성 C 평가 요약 조회 |

감사 검증은 `verify_audit_candidates(report_id, grant_id)`로 시작하면 `job_id`를 반환한다. 해당 ID로 상태를 조회하거나 취소하고, 완료된 보고서는 `read_review_report`로 읽는다. 공개키 서명 검토·신규 검증 예산 승인 CLI와 입력 조건은 [감사 계약](docs/audit-contract.md)을 따른다.

## 채팅용 슬래시 명령

고정 예제 검사와 저장된 결과 조회에 사용하는 스킬 명령이다.

| 명령 | 기능 |
| --- | --- |
| `/localcode-check` | CVE 조회 없이 고정 Java 예제 검사 |
| `/localcode-cve` | 고정 Java 예제 검사와 Oracle JDK 영향 버전 대조 |
| `/localcode-reports` | 기존 예제 보고서 목록·상세 조회 |
| `/localcode-summary` | 완료된 합성 C 4건의 평가 요약 조회 |

## 빌드와 검증

JDK17·Python3.12·requirements-mcp.txt 환경이 필요하다. 설치/네트워크 변경은 작업별로 정한다. 제품 브리지는 과거 동결 JAR와 분리한다.

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-17.0.18'
# 기존 제품 라이브러리가 준비된 환경의 오프라인 빌드 및 입력/산출물 해시 영수증
python scripts/build_product_runtime.py --jdk $env:JAVA_HOME
python -m unittest discover -s scripts -p 'test_*.py' -v
python scripts/smoke_mcp_product.py
# 감사 검증 도구의 시작·상태·오류 거부까지 합성 입력으로 확인; 실제 모델 호출 없음
python scripts/smoke_mcp_adoption.py
```

새 환경에서 제품 라이브러리 준비는 `gradlew.bat prepareProductRuntime`으로 하고, 해시 연결 영수증은 위 빌더로 생성한다. 원래 installDist와 완료 실험/생성 명령은 재실행하지 않는다. 기존 닫힌 모델 예산을 초기화하지 않는다.

## 실행 경계

대상 README의 명령을 자동 실행하지 않는다. 명시된 운영자 프로필만 복사본에서 실행한다. 기본 프로세스 경계는 OS 샌드박스가 아니다. Docker 선택 시 digest 고정 이미지·비관리자·읽기 전용·자원 제한·기본 network none·IPv6 비활성화를 검사한다. 컨테이너 탈출 전체 방어는 미검증이다.

실행마다 코드/런타임 해시·PID·UTC 영수증을 저장한다. 실행 중 제품 코드 변경을 감지한 서버는 새 작업을 거부하고 재시작을 요구한다. 재연결 후 `get_product_capabilities`의 `runtime_provenance`에서 코드 해시 일치와 `restart_required=false`를 확인한다. 자동 hot reload는 제공하지 않는다.

실제 검사 대상 소스·진단 원문·승인·실행 결과는 로컬에 보존하고 공개 커밋에 포함하지 않는다. 이 저장소에는 제품 코드·합성 테스트·사용법을 포함한다. 개발 환경의 과거 실험 기록과 로컬 설정은 게시하지 않는다.

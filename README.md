# Security Scanner · LocalCode Review

Java/Spring 프로젝트 폴더를 조사하고 소스 보안 후보, 의존성 CVE, 승인된 HTTP 시나리오를 통합 보고서로 제공하는 로컬 MCP 서버다. Python CLI로도 실행할 수 있다. 실험적인 도구이며 검사 완료가 코드 전체의 안전을 뜻하지 않는다.

## 기능

| 기능 | 범위 |
| --- | --- |
| 폴더 조사 | Java/Spring 엔드포인트와 관련 코드를 수집하고 누락·미지원 범위를 표시 |
| 정적 분석 | JDK AST를 이용한 SQL 삽입·HTML 출력·SSRF 후보 탐지 |
| 의존성 CVE | Maven 의존성/인벤토리의 버전과 OSV 공지 대조, 소스·앱 JAR·runtime JAR 해시 연결 |
| 동적 검사 | 운영자가 등록한 일회용 서버와 허용된 HTTP·상태 조회 시나리오 실행 |
| AI 안내 | 로컬 Ollama가 확인된 HTTP 근거의 점검 영역을 선택. 안내 문구·절차는 하네스가 표시 |
| 수정 검증 | 승인한 수정 묶음을 복사본에만 적용·빌드해 같은 조건으로 전후 비교 |
| 격리 | 선택형 Docker Linux 실행 제한, 소유 루프백 중계, 취소·서버·복사본 정리 |

MCP 도구는 24개, 프롬프트는 4개다. 폴더 통합 진입점은 `scan_project`다. 다른 언어는 미지원으로 표시한다. AI 생성·외부 CVE 조회·서버 실행은 설정과 승인이 있는 단계만 수행하며 나머지는 미실행으로 기록한다.

## 준비

Python 3.12, JDK 17, Gradle wrapper를 사용한다. 최초 Python/Gradle 의존성 설치에는 네트워크가 필요할 수 있다. Docker와 Ollama는 해당 기능을 쓸 때만 필요하다.

PowerShell에서 **이 저장소 루트로 이동한 다음** 실행한다. `Read-Host`에는 실제 경로를 입력한다. 코드 블록 표시용 백틱은 명령에 포함하지 않는다.

```powershell
$env:JAVA_HOME = Read-Host 'JDK 17 설치 폴더'
python -m pip install -r requirements-mcp.txt
.\gradlew.bat --no-daemon prepareProductRuntime
python -m localcode_review_mcp doctor
```

Gradle 캐시가 준비됐다면 `--offline`을 추가할 수 있다. macOS/Linux는 `sh ./gradlew prepareProductRuntime`을 사용한다. 실제 동적 실행의 주 검증 환경은 Windows이며, 모든 OS 동작을 검증한 것은 아니다.

## 폴더 검사

처음에는 모델 호출 없이 조사·정적 검사와 이용 가능한 로컬 기록만 확인할 수 있다. 온라인 CVE와 일회용 서버 설정은 기본 비활성 상태다.

```powershell
$projectFolder = Read-Host '검사할 Java/Spring 프로젝트 절대 경로'
python -m localcode_review_mcp configure --project demo --root $projectFolder --jdk $env:JAVA_HOME
python -m localcode_review_mcp scan $projectFolder --max-ai-endpoints 0 --no-remediation
```

결과는 기본 `results/product/scan-…/report.json`과 `report.md`에 저장한다. `PARTIAL`은 지원 범위만 수행했다는 뜻이며, 전체 보안 판정은 `NOT_ASSESSED`다. 모델 응답은 `NOT_REVIEWED`/`REVIEW_REQUIRED` 상태를 유지한다.

자세한 설정은 [폴더 검사 사용법](docs/folder-scan.md), 검증 명령은 [테스트 안내](docs/testing.md), MCP 연결 예시는 [mcp](mcp/README.md)를 참고한다.

게시용 복사본에서 Java 브리지 빌드·Python90회·MCP24도구/4프롬프트를 확인했다. [확인 범위와 한계](docs/verification.md)를 함께 읽는다.

## 포함 범위와 한계

이 저장소는 제품 코드, 자체 테스트, 합성 샘플과 사용법을 게시한 것이다. 실제 프로젝트 소스·진단 원문·로컬 설정·설치 파일·과거 승인/예산·실험 결과는 포함하지 않는다. 원본 개발 환경에서 기록한 Python 202회/Java 178개 결과를 이 게시본의 테스트 통과 횟수로 주장하지 않는다.

- 정적 분석은 제한된 메서드 내부 흐름의 **후보** 탐지다. 서비스 간 흐름·반사·비동기의 완전한 해석은 제공하지 않는다.
- CVE 버전 일치는 악용 가능성이나 배포 서버 빌드 일치의 증거가 아니다.
- HTTP는 등록한 시나리오만 실행한다. 범용 공격 탐색이나 브라우저 기반 취약점 검사가 아니다.
- Docker 설정 검사는 모든 네트워크 우회·컨테이너 탈출 방어를 보증하지 않는다. 복사본 빌드는 별도 호스트 실행 경계이며 강한 격리가 필수면 우회하지 않고 거부한다.
- AI의 근거 선택은 오판정할 수 있다. 원본 자동 수정·배포·안전 승인은 하지 않는다.
- 큰 입력의 정확한 로컬 토큰 측정은 특정 Windows/Ollama/DLL/모델 및 비공개 과거 보정 자료에 의존한다. 해당 자료는 게시하지 않았으며 측정 불가 시 요청을 차단한다. 입력을 명시적으로 줄여야 하며 암묵 절단하지 않는다.
- 과거 합성 평가 요약·고정 Java 예제 호환 도구는 별도 자료/예제 경로가 없으면 이용할 수 없다. 폴더 검사와 구분한다.

`tools/spring-*-fixture`는 의도한 결함과 재현용 구버전을 포함한다. 폐기 가능한 로컬 환경에서만 사용하며 운영에 배포하지 않는다. 실제 소스·진단·자격증명은 Git에 추가하지 않는다.

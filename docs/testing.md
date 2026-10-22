# 게시본 테스트 안내

과거 실제 응답·진단·실험 동결 자료는 게시하지 않는다. 이에 의존하는 과거 테스트 대신 이 게시본에는 독립 실행 가능한 제품 경계·통합·격리·정적 규칙 테스트를 포함한다. 원래 개발 환경의 Python202회·Java178개 기록을 이 게시본의 통과 수치로 옮기지 않는다.

저장소 루트에서 실행한다.

```powershell
$env:JAVA_HOME = Read-Host 'JDK 17 설치 폴더'
python -m pip install -r requirements-mcp.txt
.\gradlew.bat --no-daemon prepareProductRuntime
python -m unittest discover -s scripts -p 'test_*.py' -v
python scripts/smoke_mcp_product.py
python scripts/smoke_mcp_prompts.py --receipt results/prompts-NEW.json
```

단위 테스트는 모델 생성·온라인 OSV 조회를 하지 않는다. 일부는 로컬 임시 HTTP 서버를 실행한다. Java AST 테스트는 `JAVA_HOME`과 제품 브리지 빌드가 없으면 건너뛴다. Docker 제한 테스트는 기본적으로 대역 엔진을 사용하며 실제 격리 검증으로 세지 않는다.

자체 Spring 샘플과 실제 Docker 검증은 별도 준비·실행 작업이다. `smoke_mcp_assurance.py`·`verify_container_*.py`는 명시한 테스트 서버를 실제 실행한다. 소스·결과가 폐기 가능한지 확인하고 `--help`와 샘플 빌드 태스크를 읽은 뒤 별도로 실행한다. 설치·이미지 pull·새 AI 호출은 기본 테스트가 수행하지 않는다.

테스트 통과는 지원하는 경로와 등록된 기대 조건의 확인이다. 새로운 프로젝트의 코드 안전성이나 보안 원인의 독립 검증을 대신하지 않는다.

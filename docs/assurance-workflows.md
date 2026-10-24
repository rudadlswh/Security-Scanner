# 평가·소스 가설·검토 기록

`product-workflow/6`은 기존 HTTP 점검 영역 계약 `security-remediation/17`을 유지한다. 소스 기반 자유문 가설은 별도 CLI opt-in이며 자동 적용하지 않는다. 등록 키 서명과 검증 전용 예산은 [감사 계약](audit-contract.md), 게시용 확인 범위는 [검증 안내](verification.md)를 따른다.

## 수집 평가

`mcp/benchmark-plan.example.json`의 프로젝트 ID, 정확한 엔드포인트, 필수 심볼, 실제 작성자와 사전 노출 여부를 채운다. 프로젝트는 로컬 설정에 등록해야 한다. 예시 placeholder를 그대로 실행하지 않는다.

```powershell
python -m localcode_review_mcp --config CONFIG.json freeze-benchmark --plan PLAN.json --output FROZEN.json
python -m localcode_review_mcp --config CONFIG.json benchmark --frozen FROZEN.json
```

소스 스냅샷·기대값을 사전 고정하고 변경 시 거부한다. 수집 시간과 고정 regex 검색 시간은 의미가 다르므로 속도 향상 증명으로 사용하지 않는다. 독립 검토와 오탐 판정은 별도다.

## 소스 가설

프로젝트의 `allow_source_proposals:true`, 고정 모델과 활성 생성 예산, 진단 저장의 명시 승인이 있어야 `analyze-source PROJECT_ID COLLECTION_ID`를 실행할 수 있다. 이 경로는 선택한 소스 근거를 로컬 모델에 보낸다. 기본 HTTP 선택 전용 흐름과 구분한다.

`validate-source-proposal COLLECTION_ID --proposal PROPOSAL.json`은 저장된 가설의 소스/수집 해시·근거 ID·형식을 대조한다. 자유문 의미나 취약점을 확정하지 않으며 원본 코드를 수정하지 않는다.

## 검토 영수증

`mcp/independent-review.example.json` 형식의 검토를 `record-independent-review REPORT_ID --review REVIEW.json`으로 기록한다. 모든 항목·정규 ID·현재 소스 바인딩·보고서 해시를 대조한다. 이 구형 평가/가설 검토의 검토자 신원은 로컬 선언이다.

새 통합 검사에 대한 `record-audit-review`는 `audit-ledger/2`와 등록 Ed25519 공개키 서명을 요구한다. 원래 보고서는 변경하지 않는다. 키 보유 확인은 실명과 실제 미참여의 증명이 아니다. 자세한 필드와 검증 모델 작업은 [감사 계약](audit-contract.md)을 따른다.

## 실행 영수증

제품 Python 소스와 Java 런타임 파일의 해시·PID·UTC를 작업별 `execution-start.json`에 저장한다. 코드가 바뀐 실행 중 서버는 새 작업을 거부한다. 재연결 후 `get_product_capabilities.runtime_provenance`를 확인한다. 이것은 서명된 원격 증명이 아니다.

기존 라이브러리를 `build/product/lib`에 준비한 뒤 `scripts/build_product_runtime.py --jdk JDK_PATH`로 오프라인 제품 빌드 영수증을 만들 수 있다. 원래 개발 환경의 실험 결과·키·소스·승인 파일은 필요하지 않으며 저장소에 포함하지 않는다.

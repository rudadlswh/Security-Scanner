# 감사 원장 계약

`product-workflow/6`의 새 검사는 `audit-ledger/2`를 사용한다. 기존 검사 실행 결과와 감사 검토 상태를 분리하며, MCP `read_project_scan_report`로 조회한다. 과거 `/1` 보고서는 그대로 읽고 소급 승격하지 않는다. 기본 AI 계약 `security-remediation/17`은 그대로다.

원장은 **검사 단계·수집 파일·HTTP 입력 경계·지원 source-to-sink 후보**를 포함한다. 모든 공격 표면·신뢰 경계의 완전한 목록은 아니다. 파일/HTTP/제외 범위는 최대1,500행이며 초과 개수는 명시한다. sink는 최대500개 기존 후보에서 추가한다. 미해결 호출, 미지원 수집, 누락 범위는 보류한다. 실행이 완료된 단계도 `unreviewed`, 발견도 `unverified`로 시작한다. `execution_state=COMPLETED`여도 감사는 자동 완료하지 않는다.

## 검토 영수증

프로젝트가 로컬 설정에 등록돼 있고 검사 생성 당시 `projects.PROJECT_ID.proposal_authors`에 작성자 ID가 있어야 한다. 작성자 정보가 없는 과거 검사는 감사 완료로 승격할 수 없다. 작성자나 검토자 ID를 대신 만들어 독립 검토로 표시해서는 안 된다.

```powershell
python -m localcode_review_mcp --config CONFIG.json record-audit-review SCAN_ID --review REVIEW.json
```

검토 문서는 다음 필드를 정확히 사용한다. 해시는 `workspace.digest`와 같은 정규 JSON(UTF-8, 키 정렬, 공백 없는 구분자)의 SHA-256이다. 소스 해시는 저장 보고서의 `source_snapshot_sha256`을 참조하며 기록 시 현재 스냅샷과 다시 대조한다.

| 필드 | 값 |
| --- | --- |
| `contract` | 새 검사는 `audit-ledger/2`, 과거 보고서만 `/1` |
| `report_sha256`, `source_sha256` | 검토 대상 보고서/소스 해시 |
| `reviewer_id` | 작성자 목록과 다른 정규 ID |
| `not_involved_in_implementation_or_expected_results` | 검토자의 실제 미참여 선언 `true` |
| `state` | `complete` 또는 `incomplete` |
| `evidence` | `{report_id, sha256}` 배열. 같은 저장소의 다른 보고서이고 같은 프로젝트·소스 스냅샷에 연결돼야 함 |
| `scopes` | 원장의 모든 단계에 대한 `{id, state, evidence_sha256, evidence_ids, rationale}` |
| `candidates` | 모든 후보에 대한 동일 필드. `validated`에만 선택적 `severity` 허용 |
| `signature` | `/2` 필수. `{key_id, value}`; value는 Ed25519 서명의 base64 |

행의 `evidence_sha256`은 원장의 해당 값이고 `evidence_ids`는 `evidence`에 등록한 보고서 ID다. 근거 보고서는 `project_id`와 `snapshot_sha256`/`source_snapshot_sha256` 또는 `source_bindings[project_id]`가 필요하다. 소스·보고서·항목·근거 해시가 달라지면 거부한다. 새로운 영수증만 저장하고 원래 결과는 덮어쓰지 않는다. MCP `list_product_reports`와 `read_review_report`로 영수증을 조회한다. 검토 기록은 로컬 CLI로만 받는다.

범위 상태는 `covered/unreviewed/deferred`, 후보 상태는 `validated/refuted/unverified/deferred`다. `covered/validated/refuted`에는 근거와 이유가 필수다. 실행하지 않은 범위는 `covered`로 만들 수 없다. 후보나 미검토 범위, 누락 제한, 실행 오류, 감지된 미지원 언어가 남으면 `complete`를 거부한다. `severity`는 `validated`에만 `low/medium/high/critical` 중 하나로 허용한다.

ID는 NFC 정규형, 공백·제어문자 없는 1~128자이며 대소문자를 무시한 충돌을 거부한다. 비정규 입력을 자동 수정하지 않는다. 저장 보고서 ID는 기존 ASCII 80자 제한을 유지한다. 상대 경로는 루트 탈출·절대 경로·Windows 장치명·ADS·제어문자·끝 공백/점을 거부한다. JSON은 기본 4MiB, 깊이64, 총 노드100,000, 배열/객체 항목10,000 제한이며 중복 키와 비유한 수를 거부한다. 이는 파일 교체 경합 전체를 막는 OS 보안 경계는 아니다.

## 보장 범위

`/2`는 운영자가 등록한 공개키로 서명을 확인한다. **등록 키 보유 확인**이며 실명·미참여·조직적 독립성을 증명하지 않는다. 근거 내용의 진실성·취약점 확정·심각도 교정도 자동 보증하지 않는다. 같은 사람을 운영자가 서로 다른 principal로 등록하는 행위까지 판별하지 않는다. `security_verdict=NOT_ASSESSED`는 유지한다. `/1` 과거 영수증은 로컬 선언으로 구분한다.

기존 `record-independent-review`도 정규 ID, 추가 필드 거부, 바인딩된 현재 소스 대조를 적용한다. 소스 바인딩 없는 과거 벤치마크는 `LEGACY_UNBOUND_NOT_CURRENT_SOURCE_VALIDATION`으로 구분하며 현재 소스 검증으로 세지 않는다.

예산이 소진되면 기존 사전 차단 경로가 모델 호출 전에 멈추고 새 원장은 `deferred`로 기록한다. `/6`의 별도 검증 모델·검증 전용 예약 예산은 아래처럼 명시적으로 선택한다. 닫힌 예산을 전용·초기화·증액하지 않는다. `/17`의 선택 결과와 기존 보고서·원문은 보존한다.

## 공개키 등록과 검토 서명

로컬 설정의 `audit_policy.trusted_reviewers`에 검토자의 **공개키만** 등록한다. 항목은 `KEY_ID: {principal_id, public_key}`이며 public_key는 32바이트 Ed25519 raw 공개키의 base64다. 실제 작성자의 `proposal_authors`도 등록된 principal ID를 사용한다. 개인키는 설정·MCP 인자·서버로 전달하지 않는다. 제품이 사용자 대신 신원을 만들거나 공개키를 신뢰하도록 등록하지 않는다.

새 검사는 공개키 등록부의 해시를 저장한다. 등록부가 변경되면 과거 검사에 새 신뢰를 소급 적용하지 않고 거부한다. 한 공개키를 다른 이름으로 중복 등록하는 것도 거부한다. 같은 작성자가 키를 여러 개 가지고 있어도 같은 principal로 등록돼 있으면 검토를 거부한다. 서명 없는 요청, 서명 후 내용 변경, `/1`로의 다운그레이드를 거부한다.

서명 메시지는 `audit_identity.signing_bytes(review)`다. `signature`를 제외한 정규 JSON SHA-256의 32바이트 앞에 `LocalCodeReview/audit-review/2`와 NUL 바이트를 붙인다. 검토자는 자신의 신뢰된 서명 환경에서 이 바이트를 서명하고 `signature={key_id, value}`를 추가한다. `value`는 서명 바이트의 base64다. 검증은 설치된 `cryptography==46.0.5`의 [Ed25519 verify](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)를 사용한다. 기존 환경의 설치된 라이브러리를 확인했고 이번 작업에서 설치하지 않았다.

## 별도 모델 검증과 전용 예산

로컬 설정 `audit_policy.verifier`에 `enabled:true`, `allow_source:true`, `name`, 전체 `digest`, 리터럴 루프백 `base_url`을 명시한다. 지원 이름은 기존 Qwen 입력 프로필의 `qwen3.5:9b`와 `qwen3-coder:30b`다. 검증 모델 digest는 검사 보고서에 기록된 발견 모델 digest와 달라야 한다. digest가 없거나 같으면 거부한다. 이름만 다른 동일 digest도 거부한다. 모델을 설치하거나 설정/동의를 자동 생성하지 않는다.

검증기는 STATIC_SECURITY_CANDIDATE의 지정 위치 ±12줄을 **로컬 모델에만** 보낸다. 작성자의 설명·심각도·수정안은 요청에 포함하지 않는다. 다른 파일·런타임·미확인 호출 관계를 추정하지 않도록 안내한다. 입력이 제한을 넘으면 전송하지 않는다. 모델 응답은 `candidate_id`, `decision`(supported/refuted/unresolved), `evidence_ids`만 허용하고 원문 요청/응답은 보존·MCP 반환하지 않는다. 근거 위치·해시와 제안 판정은 남긴다.

```powershell
# 운영자가 실제로 새 검증 예산을 승인할 때만 실행한다. 기존 예산과 별개인 새 grant가 생성된다.
python -m localcode_review_mcp --config CONFIG.json authorize-audit-verifier SCAN_ID --calls N --minutes MINUTES
# 반환받은 GRANT_ID를 사용한다. CLI는 완료까지 기다린다.
python -m localcode_review_mcp --config CONFIG.json verify-audit-candidates SCAN_ID GRANT_ID
```

MCP `verify_audit_candidates(report_id, grant_id)`는 작업을 시작하고 `job_id`를 즉시 반환한다. `get_audit_verification_status(job_id)`로 상태를 조회하고 `cancel_audit_verification(job_id)`로 취소한다. 완료된 작업의 `job_id`를 `read_review_report`에 전달하면 결과와 상세 검증 보고서 ID를 읽는다. 작업 서버가 종료돼도 자동 재개·재전송하지 않는다. 상태 조회와 별개로 원격 완료 불명의 grant 잠금은 명시적인 확인 전까지 유지한다.

이 예산은 **검증 전용**이며 발견 작업이 사용할 수 없다. 지원 후보 전체에 필요한 호출 수를 모델 조회 전에 예약한다. 부족하면 모든 후보를 deferred로 반환하고 모델 조회·호출·예산 변경0회다. grant는 보고서/소스/검증 모델 설정 해시에 묶이고 단일 사용이며 기존 생성 예산을 공유하지 않는다. 각 POST 전에 차감하고 재시도·환급하지 않는다. 서버 모델 digest, 입력량, 매 호출 전후의 소스/보고서, 만료와 승인 변경을 대조한다. 다른 모델 작업과 같은 잠금을 사용한다.

성공해도 `COMPLETED_FOR_SELECTED_CANDIDATES`/`review_required`이며 **사람의 최종 판정이 아니다**. 미지원 HTTP/CVE 종류는 deferred로 남긴다. 모든 종류의 AI 검증이나 실제 악용 확인을 구현한 것이 아니다. supported가 취약점 확정은 아니고 refuted 제안도 자동으로 후보를 닫지 않는다. 서명한 사람의 검토에서 근거 보고서로 사용할 수 있다.

원격 완료가 불명확하면 예산을 닫고 잠금을 남긴다. 프로세스 종료/원격 유휴를 실제로 확인한 운영자만 아래 명령을 실행한다. 실행 중인 RESERVED 소유자는 거부하고, 이전 호출은 환급하지 않는다.

```powershell
python -m localcode_review_mcp --config CONFIG.json acknowledge-audit-failure GRANT_ID --remote-idle-confirmed
```

서로 다른 digest와 분리된 요청은 상관된 모델 오류까지 제거하는 독립성 증명은 아니다. 실제 검증 모델 응답 품질과 실제 검토자 등록은 별도 확인 대상이다. 이번 구현 검증은 임시 키·합성 입력·모의 모델로 수행했다.

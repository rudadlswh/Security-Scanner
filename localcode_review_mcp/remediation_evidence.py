"""하네스가 HTTP/CVE 근거에서 검증 조건·수정 범위를 결정한다. 모델 값을 대신 쓰지 않는다."""
import json
import re


def literal_route_matches(template: str, path: str) -> bool:
    """단순 Spring 경로 변수만 대조한다. 정규식·wildcard·인코딩·query는 추정하지 않는다."""
    if not all(isinstance(v, str) and v.startswith("/") for v in (template, path)):
        return False
    if any(c in template + path for c in "*?%\\#"):
        return False
    left, right = template.split("/"), path.split("/")
    if len(left) != len(right):
        return False
    return all((bool(b) and re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", a))
               or (a == b and not any(c in a for c in "{}"))
               for a, b in zip(left, right))


def route_bindings(request: dict, endpoints: list[dict]) -> list[dict]:
    """동일 메서드의 유일한 수집 매핑만 연결한다. 실제 서버 라우팅을 증명하지 않는다."""
    matches = [e for e in endpoints
               if e.get("mapping_status") == "AST_LITERAL"
               and e.get("http_method") == request.get("method")
               and literal_route_matches(e.get("http_path"), request.get("path"))]
    if len(matches) != 1:
        return []
    endpoint = matches[0]
    return [{"template": endpoint["http_path"], "method": endpoint["http_method"],
             "endpoint_id": endpoint.get("endpoint_id"), "source": "COLLECTED_AST_LITERAL",
             "runtime_dispatch_verified": False}]


def observation_summary(item: dict) -> str:
    """인증 여부/다른 행위자/사고를 추가하지 않는 고정 설명."""
    if item["kind"] == "DEPENDENCY_VERSION_MATCH":
        return "조회 근거의 의존성 버전 영향 일치입니다. 실제 악용 가능성은 확인하지 않았습니다."
    actors = sorted({str(t.get("actor")) for t in observed_targets(item)})
    return ("등록된 검사 요청자 " + json.dumps(actors, ensure_ascii=False)
            + "의 HTTP/상태 결과가 사전 기대 조건과 달랐습니다. "
            "역할 이름만으로 인증 상태나 다른 요청자의 접근 가능성을 확정하지 않습니다.")

def action_context(action: dict) -> dict:
    """과거 hash/matches로 값을 복원하지 않고 새 boolean 계약만 읽는다."""
    value = {key: action[key] for key in ("method", "path", "actor", "status_code", "status_matches", "state_matches") if key in action}
    expected = action.get("expected_status_codes")
    if isinstance(expected, list) and expected and all(type(x) is int and 100 <= x <= 599 for x in expected):
        value.update(expected_status_codes=expected, expectation_availability="AVAILABLE")
    else:
        value["expectation_availability"] = "UNAVAILABLE_LEGACY_RECORD"
    probe = action.get("state_probe")
    if isinstance(probe, dict) and probe.get("value_visibility") == "BOOLEAN_ONLY" and type(probe.get("expected")) is bool:
        clean = {"value_visibility": "BOOLEAN_ONLY", "expected": probe["expected"],
                 "actual_availability": probe.get("actual_availability", "UNAVAILABLE")}
        pointer = probe.get("json_pointer")
        if isinstance(pointer, str) and len(pointer) <= 256 and (pointer == "" or pointer.startswith("/")):
            clean["json_pointer"] = pointer
        if type(probe.get("actual")) is bool and probe.get("actual_availability") == "AVAILABLE":
            clean["actual"] = probe["actual"]
        elif probe.get("actual_availability") == "AVAILABLE":
            clean["actual_availability"] = "WITHHELD_NON_BOOLEAN" if "actual" in probe else "UNAVAILABLE"
        value["state_probe"] = clean
    elif "state_matches" in action or isinstance(probe, dict):
        value["state_probe"] = {"value_visibility": "UNAVAILABLE_OR_WITHHELD", "actual_availability": "UNAVAILABLE"}
    return value


def observed_targets(item: dict, evidence_ids: list[str] | None = None) -> list[dict]:
    """사후 조회용 GET을 수정 대상으로 승격하지 않고 원래 검사 요청만 바인딩한다."""
    refs = set(evidence_ids or item["evidence_ids"])
    if item["kind"] == "DEPENDENCY_VERSION_MATCH":
        return [{"kind": "DEPENDENCY", **item["package"]}]
    return [{"kind": "HTTP_REQUEST", "evidence_id": row["evidence_id"],
             **{key: row["request"].get(key) for key in ("method", "path", "actor")}}
            for row in item.get("http_observations", []) if row["evidence_id"] in refs]


def observed_facts(item: dict, evidence_ids: list[str]) -> list[dict]:
    """변경 전/요청/후를 섞지 않고 저장 근거의 경로·응답·boolean만 표시한다. 실제 구현을 추론하지 않는다."""
    if item["kind"] == "DEPENDENCY_VERSION_MATCH":
        package = item["package"]
        return [{"text": f"버전 영향 일치: {package['ecosystem']} {package['name']} {package['version']}. 악용 가능성은 미확인.",
                 "evidence_ids": evidence_ids, "source": "HARNESS_EVIDENCE"}]
    facts = []
    for row in item.get("http_observations", []):
        if row["evidence_id"] not in evidence_ids:
            continue
        for phase, title in (("before", "변경 전 조회"), ("request", "검사 요청"), ("after", "변경 후 조회")):
            action = row.get(phase, {})
            if not action:
                continue
            details = {key: action[key] for key in ("method", "path", "actor", "status_code", "expected_status_codes") if key in action}
            probe = action.get("state_probe", {})
            for key in ("json_pointer", "actual", "expected"):
                if key in probe:
                    details["state_" + key] = probe[key]
            facts.append({"text": title + ": " + json.dumps(details, ensure_ascii=False, separators=(",", ":")),
                          "phase": phase, "evidence_ids": [row["evidence_id"]], "source": "HARNESS_EVIDENCE"})
    return facts


def verification_plan(items: list[dict]) -> dict:
    """AI 호출 유무와 무관하게 원래 기대 조건을 고정 출력한다. 테스트를 자동 실행하지 않는다."""
    cases = []
    for item in items:
        if item["kind"] == "DEPENDENCY_VERSION_MATCH":
            fixes = sorted({version for row in item.get("advisories", []) for version in row.get("fixed_versions_from_matching_package", [])})
            cases.append({"finding_id": item["finding_id"], "evidence_ids": item["evidence_ids"],
                "kind": "DEPENDENCY_COMPATIBILITY_REVIEW", "source": "HARNESS_EVIDENCE", "package": item["package"],
                "candidate_versions": fixes, "status": "MANUAL_COMPATIBILITY_AND_REGRESSION_REQUIRED",
                "candidate_provenance": [{"advisory_id": row.get("id"), "source": row.get("source"),
                    "candidate_versions": list(row.get("fixed_versions_from_matching_package", []))}
                    for row in item.get("advisories", [])],
                "candidate_availability": "PROVIDED" if fixes else "NOT_PROVIDED",
                "candidate_semantics": "EXACT_ADVISORY_CANDIDATES_NOT_OPEN_ENDED_SAFE_RANGE",
                "selected_version": None, "compatibility_verified": False,
                "checklist": [
                    "현재 해석된 의존성 목록에서 해당 패키지의 실제 버전과 직접·전이 유입 경로를 확인한다. 선언만으로 실행 버전을 확정하지 않는다.",
                    "버전을 결정하는 직접 선언·상위 의존성·사용 중인 BOM·잠금 파일을 식별한다. 최신 BOM으로 바꿀 필요가 있다고 가정하지 않는다.",
                    "공지별 수정 후보와 현재 브랜치·JDK·프레임워크 호환성을 대조한다. 후보는 해당 공지의 개별 값이며 그 이상 모든 버전의 안전을 뜻하지 않는다.",
                    "호환성 검토 후 변경할 선언이나 상위 의존성을 결정한다. 후보가 없거나 적합성이 불명확하면 버전 선택을 보류하고 공지를 확인한다.",
                    "변경 후 해석된 의존성 목록을 다시 확인해 실제 적용 버전을 대조하고 빌드·회귀 테스트를 수행한다.",
                    "별도 승인된 취약 버전 조회로 다시 확인한다. 이 목록은 실행 결과나 악용 가능성 검증이 아니다."],
                "automatic_execution": False})
            continue
        for row in item.get("http_observations", []):
            request, after = row["request"], row["after"]
            probe = after.get("state_probe", {})
            missing = []
            for field in ("method", "path", "actor"):
                if not isinstance(request.get(field), str) or not request[field]:
                    missing.append("request." + field)
            if request.get("expectation_availability") != "AVAILABLE" or not request.get("expected_status_codes"):
                missing.append("expected_status_codes")
            if probe.get("value_visibility") != "BOOLEAN_ONLY" or type(probe.get("expected")) is not bool:
                missing.append("expected_state")
            if not isinstance(probe.get("json_pointer"), str):
                missing.append("state_json_pointer")
            cases.append({"finding_id": item["finding_id"], "evidence_ids": [row["evidence_id"]], "kind": "HTTP_EXPECTATION",
                "source": "HARNESS_OPERATOR_EXPECTATION", "status": "READY_FROM_RECORDED_EXPECTATIONS" if not missing else "UNAVAILABLE_EXPECTATIONS",
                "request": {key: request.get(key) for key in ("method", "path", "actor")},
                "expected_status_codes": request.get("expected_status_codes") if "expected_status_codes" not in missing else None,
                "state_json_pointer": probe.get("json_pointer"),
                "expected_state": probe.get("expected") if "expected_state" not in missing else None,
                "actual_status_code": request.get("status_code"), "actual_state": probe.get("actual"),
                "missing_fields": missing, "automatic_execution": False})
    return {"contract_version": "harness-verification/1", "source": "HARNESS_NOT_MODEL", "cases": cases,
            "automatic_execution": False, "meaning": "기존 기대 조건의 재검증 목록이며 수정 완료를 증명하지 않는다."}


def presentation(item: dict) -> dict:
    """검사로 확인하지 않은 누출·심각도·사고 제목은 AI가 정하지 않는다."""
    dynamic = item["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY"
    return {"title": "등록된 HTTP 기대 조건과 실제 결과 불일치" if dynamic else "의존성 버전 영향 일치(악용 미확인)",
            "confirmed_impact": "등록된 요청/상태 관찰의 기대 조건 불일치" if dynamic else "조회 근거의 패키지 버전 영향 일치",
            "severity": "NOT_ASSESSED", "exploitability": "NOT_ASSESSED", "presentation_source": "HARNESS_EVIDENCE",
            "confirmed_targets": observed_targets(item)}



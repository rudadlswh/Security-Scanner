"""해결 제안 /8: 출처 사용 금지와 사용 제안을 구분하고 추가 점검의 근거도 검토한다."""
from typing import Annotated, Literal
import re
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from .remediation_evidence import action_context, observed_targets, observed_facts, observation_summary, literal_route_matches
from .remediation_claims import hypothesis_fact_issues, role_words
from .remediation_language import proposed_statuses, actor_alias_requires_review, response_source_requires_review, storage_exclusion_requires_review

VERSION = "security-remediation/11"
Text = Annotated[str, StringConstraints(min_length=1, max_length=1000)]
Ref = Annotated[str, StringConstraints(pattern=r"^E-F[0-9]{3}-[HC][1-9][0-9]*$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CitedText(Strict):
    text: Text
    evidence_ids: list[Ref] = Field(min_length=1, max_length=8)


class Hypothesis(CitedText):
    confirmation_needed: Text


class OwnershipCheck(Strict):
    caller_identity_verification: Text
    resource_owner_lookup: Text
    comparison_rule: Text
    execution_order: Literal["BEFORE_MUTATION"]
    owner_source: Literal["SERVER_AUTHORITATIVE_STORE", "SERVER_AUTHORIZED_LOOKUP_SERVICE", "UNRESOLVED"]
    source_confirmation: Text
    owner_lookup_order: Literal["BEFORE_MUTATION"]
    lookup_failure_action: Literal["DENY_WITHOUT_MUTATION"]
    caller_source: Literal["SERVER_VERIFIED_PRINCIPAL", "UNRESOLVED"]
    mismatch_action: Literal["DENY_WITHOUT_MUTATION"]


class ChangeBase(CitedText):
    scope: Literal["OBSERVED_TARGET_ONLY"]
    assumptions: list[Text] = Field(max_length=4)


class OwnershipChange(ChangeBase):
    focus: Literal["RESOURCE_OWNERSHIP"]
    ownership_check: OwnershipCheck


class OtherChange(ChangeBase):
    focus: Literal["CALLER_AUTHENTICATION", "DEPENDENCY_UPDATE", "OTHER"]
    ownership_check: None = None


class Advice(Strict):
    finding_id: str = Field(pattern=r"^F[0-9]{3}$")
    observed_evidence_ids: list[Ref] = Field(min_length=1, max_length=8)
    cause_hypotheses: list[Hypothesis] = Field(max_length=4)
    recommended_changes: list[OwnershipChange | OtherChange] = Field(min_length=1, max_length=6)
    policy_questions: list[CitedText] = Field(max_length=4)
    additional_checks: list[CitedText] = Field(max_length=6)
    cautions: list[Text] = Field(min_length=1, max_length=4)


class AdviceResponse(Strict):
    contract_version: Literal["security-remediation/11"]
    recommendations: list[Advice] = Field(min_length=1, max_length=20)


def actor_scope_issues(text: str, item: dict, evidence_ids: list[str] | None = None) -> list[str]:
    """익명/미인증이라는 명시적 표현의 범위만 확인한다. 부정/가정도 오탐할 수 있어 사실 오류로 확정하지 않는다."""
    if item["kind"] != "DYNAMIC_BEHAVIOR_DISCREPANCY":
        return []
    actors = {str(t.get("actor", "")).lower() for t in observed_targets(item, evidence_ids)}
    # 역할 이름(non_owner 등)만으로 인증 상태나 익명 접근 가능성을 추론하지 않는다.
    anonymous_ids = {"anonymous", "unauthenticated", "unauthenticated_user", "비인증", "비로그인", "익명"}
    if actors & anonymous_ids:
        return []
    if re.search(r"비인증|비로그인|미인증|익명|로그인\s*(?:하지\s*않|없이)|\b(?:unauthenticated|anonymous)\b", text, re.I):
        return ["UNOBSERVED_ACTOR_MENTION_REVIEW_REQUIRED"]
    return []


def ownership_role_issues(change: dict) -> list[str]:
    """필드 역할의 최소 문자 근거만 검사한다. 실제 인증/조회/비교 코드의 정확성을 증명하지 않는다."""
    if change["focus"] != "RESOURCE_OWNERSHIP" or not change.get("ownership_check"):
        return []
    detail = change["ownership_check"]
    caller = role_words(detail["caller_identity_verification"])
    lookup = role_words(detail["resource_owner_lookup"])
    compare = role_words(detail["comparison_rule"])
    codes = []
    if not (re.search(r"호출자|사용자|주체|\b(?:caller|user|principal)\b", caller, re.I)
            and re.search(r"인증|검증|신뢰|\b(?:trusted|verified|authenticated)\b", caller, re.I)):
        codes.append("CALLER_IDENTITY_ROLE_REVIEW_REQUIRED")
    if not (re.search(r"소유자|\bowner\b", lookup, re.I)
            and re.search(r"조회|검색|가져오|찾|\b(?:lookup|query|fetch|select|retrieve)\b", lookup, re.I)):
        codes.append("RESOURCE_OWNER_LOOKUP_ROLE_REVIEW_REQUIRED")
    noncomparison = re.search(r"적용\s*(?:하지\s*않|안|없)|해당\s*없|비교\s*(?:하지\s*않|없|안)|필요\s*없|\b(?:not\s+applicable|n/?a|skip|unnecessary)\b", compare, re.I)
    if noncomparison or not (re.search(r"호출자|사용자|주체|\b(?:caller|user|principal)\b", compare, re.I)
            and re.search(r"소유자|\bowner\b", compare, re.I)
            and re.search(r"비교|일치|동일|다르|같|\b(?:compare|match|equal|different)\b", compare, re.I)):
        codes.append("OWNER_COMPARISON_ROLE_REVIEW_REQUIRED")
    return codes


def ownership_source_issues(change: dict) -> list[str]:
    """enum 선언을 신뢰성 입증으로 읽지 않는다. 이전 출력도 원문 그대로 감사한다."""
    detail = change.get("ownership_check")
    if change.get("focus") != "RESOURCE_OWNERSHIP" or not detail:
        return []
    codes = []
    if detail.get("owner_source") not in {"SERVER_AUTHORITATIVE_STORE", "SERVER_AUTHORIZED_LOOKUP_SERVICE"}:
        codes.append("OWNER_SOURCE_UNCONFIRMED")
    if not detail.get("source_confirmation"):
        codes.append("OWNER_SOURCE_CONFIRMATION_MISSING")
    if detail.get("owner_lookup_order") != "BEFORE_MUTATION":
        codes.append("OWNER_LOOKUP_ORDER_UNCONFIRMED")
    if detail.get("lookup_failure_action") != "DENY_WITHOUT_MUTATION":
        codes.append("OWNER_LOOKUP_FAILURE_ACTION_UNCONFIRMED")
    if detail.get("caller_source") != "SERVER_VERIFIED_PRINCIPAL":
        codes.append("CALLER_SOURCE_UNCONFIRMED")
    if detail.get("mismatch_action") != "DENY_WITHOUT_MUTATION":
        codes.append("OWNER_MISMATCH_ACTION_UNCONFIRMED")
    lookup = detail.get("resource_owner_lookup", "")
    # 응답 출처는 신뢰된 조회 서비스일 수도 있다. 오류 확정 대신 검토 보류한다.
    if response_source_requires_review(lookup):
        codes.append("OWNER_RESPONSE_SOURCE_REQUIRES_REVIEW")
    caller = detail.get("caller_identity_verification", "")
    if actor_alias_requires_review(caller):
        codes.append("CALLER_ACTOR_ALIAS_REQUIRES_REVIEW")
    if re.search(r"목록|화이트리스트|\b(?:list|allowlist|whitelist)\b", caller, re.I):
        codes.append("CALLER_MEMBERSHIP_NOT_IDENTITY_PROOF")
    if (re.search(r"요청|클라이언트|\b(?:request|client)\b", caller, re.I)
            and re.search(r"본문|헤더|파라미터|\b(?:body|header|parameter)\b", caller, re.I)):
        codes.append("CALLER_REQUEST_VALUE_TRUST_REQUIRES_REVIEW")
    texts = [change["text"], *change.get("assumptions", []),
             *(detail.get(key, "") for key in ("caller_identity_verification", "resource_owner_lookup",
                                               "comparison_rule", "source_confirmation"))]
    if any(storage_exclusion_requires_review(text) for text in texts):
        codes.append("UNSUPPORTED_STORAGE_EXCLUSION_REVIEW_REQUIRED")
    return codes


def literal_scope_issues(change: dict, item: dict) -> list[str]:
    """명시된 HTTP 메서드/URI/숫자와 범위 표현만 대조한다. 의미 판별기나 안전성 증명이 아니다."""
    if item["kind"] != "DYNAMIC_BEHAVIOR_DISCREPANCY":
        return []
    text = "\n".join([change["text"], *change.get("assumptions", []),
        *[str(v) for v in (change.get("ownership_check") or {}).values()]])
    codes = set()
    targets = observed_targets(item, change["evidence_ids"])
    if change["scope"] == "OBSERVED_TARGET_ONLY":
        methods = {target.get("method") for target in targets}
        paths = {target.get("path") for target in targets}
        for row in item.get("http_observations", []):
            if row["evidence_id"] not in change["evidence_ids"]:
                continue
            for binding in row.get("route_bindings", []):
                if (binding.get("source") == "COLLECTED_AST_LITERAL"
                        and binding.get("method") == row["request"].get("method")
                        and literal_route_matches(binding.get("template"), row["request"].get("path"))):
                    paths.add(binding["template"])
        if set(re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", text)) - methods:
            codes.add("HTTP_METHOD_OUTSIDE_OBSERVED_TARGET")
        mentioned = {p.rstrip(".,;:)") for p in re.findall(r"(?<![\w/])/(?:[A-Za-z0-9._~%{}?=&:+-]+/?)+", text)}
        if mentioned - paths:
            codes.add("HTTP_PATH_OUTSIDE_OBSERVED_TARGET")
        if re.search(r"모든|전체|\b(?:all|every|project-wide)\b", text, re.I) and re.search(r"요청|엔드포인트|\b(?:GET|POST|PUT|PATCH|DELETE|requests?|endpoints?)\b", text, re.I):
            codes.add("POSSIBLE_SCOPE_EXPANSION")
        rows = [r for r in item.get("http_observations", []) if r["evidence_id"] in change["evidence_ids"]]
        expected = {code for r in rows for code in r["request"].get("expected_status_codes", [])}
        # 사전 기대가 있을 때만 대조한다. 숫자 인용의 문맥 오탐 가능성은 보류 사유로 공개한다.
        actual = {r["request"].get("status_code") for r in rows if type(r["request"].get("status_code")) is int}
        if expected and proposed_statuses(text, actual) - expected:
            codes.add("HTTP_STATUS_OUTSIDE_RECORDED_EXPECTATION")
    return sorted(codes)


def check_advice(rows: list[dict], items: list[dict]) -> dict:
    """구조·인용과 제한된 문자 대조를 검사한다. /3 과거 출력의 오프라인 감사도 가능하다."""
    contexts = {item["finding_id"]: item for item in items}
    issues = []
    for row in rows:
        item = contexts[row["finding_id"]]
        known = set(item["evidence_ids"])
        observed_ids = row.get("observed_evidence_ids", [])
        if len(observed_ids) != len(set(observed_ids)) or not set(observed_ids) <= known:
            issues.append({"finding_id": row["finding_id"], "code": "INVALID_EVIDENCE_REFERENCE", "field": "observed_evidence_ids"})
        for code in actor_scope_issues(row.get("rationale", ""), item):
            issues.append({"finding_id": row["finding_id"], "code": code, "field": "rationale"})
        for field in ("observed_facts", "cause_hypotheses", "recommended_changes", "policy_questions", "additional_checks"):
            for entry in row.get(field, []):
                ids = entry["evidence_ids"]
                if len(ids) != len(set(ids)) or not set(ids) <= known:
                    issues.append({"finding_id": row["finding_id"], "code": "INVALID_EVIDENCE_REFERENCE", "field": field})
        for index, question in enumerate(row.get("policy_questions", [])):
            issues.append({"finding_id": row["finding_id"], "code": "ADDITIONAL_POLICY_CONFIRMATION_REQUIRED", "field": f"policy_questions[{index}]"})
        for index, hypothesis in enumerate(row.get("cause_hypotheses", [])):
            if str(hypothesis.get("confirmation_needed", "")).strip().lower() in {"true", "false", "yes", "no", "null", "n/a", "확인 필요"}:
                issues.append({"finding_id": row["finding_id"], "code": "HYPOTHESIS_CONFIRMATION_NOT_ACTIONABLE", "field": f"cause_hypotheses[{index}]"})
            for code in [*hypothesis_fact_issues(hypothesis, item),
                         *actor_scope_issues(hypothesis["text"], item, hypothesis["evidence_ids"])]:
                issues.append({"finding_id": row["finding_id"], "code": code, "field": f"cause_hypotheses[{index}]"})
        for index, extra in enumerate(row.get("additional_checks", [])):
            if storage_exclusion_requires_review(extra["text"]):
                issues.append({"finding_id": row["finding_id"], "code": "UNSUPPORTED_STORAGE_EXCLUSION_REVIEW_REQUIRED",
                               "field": f"additional_checks[{index}]"})
        for index, change in enumerate(row["recommended_changes"]):
            def issue(code):
                issues.append({"finding_id": row["finding_id"], "code": code, "field": f"recommended_changes[{index}]"})
            if change["scope"] == "ADDITIONAL_POLICY_REVIEW":
                issue("ADDITIONAL_POLICY_CONFIRMATION_REQUIRED")
            if change["focus"] == "RESOURCE_OWNERSHIP" and change["ownership_check"] is None:
                issue("RESOURCE_OWNER_CHECK_DETAILS_MISSING")
            if change["focus"] != "RESOURCE_OWNERSHIP" and change["ownership_check"] is not None:
                issue("OWNER_CHECK_FOCUS_MISMATCH")
            if item["kind"] == "DEPENDENCY_VERSION_MATCH" and change["focus"] not in {"DEPENDENCY_UPDATE", "OTHER"}:
                issue("CHANGE_KIND_NOT_SUPPORTED_BY_FINDING")
            if item["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY" and change["focus"] == "DEPENDENCY_UPDATE":
                issue("CHANGE_KIND_NOT_SUPPORTED_BY_FINDING")
            for code in literal_scope_issues(change, item):
                issue(code)
            for code in ownership_role_issues(change):
                issue(code)
            for code in ownership_source_issues(change):
                issue(code)
            if change["scope"] == "OBSERVED_TARGET_ONLY":
                for code in actor_scope_issues(change["text"] + "\n" + "\n".join(change.get("assumptions", [])), item, change["evidence_ids"]):
                    issue(code)
    return {"status": "REVIEW_REQUIRED" if issues else "NO_STRUCTURED_ISSUE_FOUND", "issues": issues,
            "fixed_tests_source": "HARNESS_NOT_MODEL", "semantic_review_status": "NOT_REVIEWED",
            "free_text_semantics_checked": False, "literal_scope_check": "LIMITED_PATTERNS_MAY_MISS_OR_OVERFLAG"}


def bind_advice(row: dict, item: dict) -> dict:
    """모델이 대상 URI/정책을 확장해도 적용 승인으로 보이지 않도록 실제 근거 범위를 따로 붙인다."""
    if "rationale" not in row:
        row["rationale"] = observation_summary(item)
        row["rationale_source"] = "HARNESS_EVIDENCE"
    row["observed_facts"] = observed_facts(item, row["observed_evidence_ids"])
    row["observed_facts_source"] = "HARNESS_EVIDENCE"
    issues = check_advice([row], [item])["issues"]
    rationale_issues = [i["code"] for i in issues if i["field"] == "rationale"] if row.get("rationale_source") != "HARNESS_EVIDENCE" else []
    row["rationale_review"] = {"disposition": "WITHHELD_FOR_REVIEW" if rationale_issues else "UNREVIEWED_TEXT", "reasons": rationale_issues}
    for question in row.get("policy_questions", []):
        question.update(disposition="POLICY_QUESTION_NOT_APPROVED", automatic_apply=False)
    for index, hypothesis in enumerate(row.get("cause_hypotheses", [])):
        local = [i["code"] for i in issues if i["field"] == f"cause_hypotheses[{index}]"]
        hypothesis.update(disposition="WITHHELD_FOR_REVIEW" if local else "UNREVIEWED_HYPOTHESIS",
                          withheld_reasons=local)
    for index, extra in enumerate(row.get("additional_checks", [])):
        local = [i["code"] for i in issues if i["field"] == f"additional_checks[{index}]"]
        extra.update(disposition="WITHHELD_FOR_REVIEW" if local else "UNREVIEWED_CHECK", withheld_reasons=local)
    for index, change in enumerate(row["recommended_changes"]):
        local = [i["code"] for i in issues if i["field"] == f"recommended_changes[{index}]"]
        change["disposition"] = "WITHHELD_FOR_REVIEW" if local else "UNREVIEWED_PROPOSAL"
        change["withheld_reasons"] = local
        if change.get("ownership_check"):
            change["owner_source_verification"] = "NOT_VERIFIED_BY_HARNESS"
        change["scope_binding"] = {"source": "HARNESS_EVIDENCE", "targets": observed_targets(item, change["evidence_ids"]),
            "status": "WITHHELD_FOR_REVIEW" if local and change["scope"] == "OBSERVED_TARGET_ONLY" else
                "OBSERVED_TARGET_ONLY_UNREVIEWED" if change["scope"] == "OBSERVED_TARGET_ONLY" else "POLICY_CONFIRMATION_REQUIRED_NOT_APPROVED"}
    return row

"""가설의 명시적 HTTP/boolean 재서술을 인용 근거와 대조한다. 자연어 의미 전체의 검증은 아니다."""
import re


def role_words(text: str) -> str:
    """snake_case/camelCase 심볼의 역할 단어를 인식하되 임의 부분 문자열은 단어로 만들지 않는다."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text).replace("_", " ")


def scoped_actions(rows: list[dict], prefix: str) -> list[dict]:
    """같은 문장의 명시적인 단계/메서드 표기만 사용한다. 생략된 지시 대상을 추론하지 않는다."""
    prefix = re.split(r"[.!?;\n]", prefix)[-1]
    phase_names = {"변경전": "before", "before": "before", "변경후": "after",
                   "after": "after", "검사요청": "request", "request": "request"}
    phases = re.findall(r"변경\s*전|변경\s*후|검사\s*요청|\b(?:before|after|request)\b", prefix, re.I)
    phase = phase_names[re.sub(r"\s+", "", phases[-1]).lower()] if phases else None
    actions = [r[p] for r in rows for p in ((phase,) if phase else ("before", "request", "after")) if r.get(p)]
    named = re.findall(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", prefix)
    return [a for a in actions if a.get("method") == named[-1]] if named else actions


def hypothesis_fact_issues(entry: dict, item: dict) -> list[str]:
    if item["kind"] != "DYNAMIC_BEHAVIOR_DISCREPANCY":
        return []
    text = entry["text"]  # confirmation_needed의 미래 테스트 조건을 관찰값으로 취급하지 않는다.
    rows = [r for r in item.get("http_observations", []) if r["evidence_id"] in entry["evidence_ids"]]
    actions = [r[p] for r in rows for p in ("before", "request", "after") if r.get(p)]
    codes = set()
    methods = {a.get("method") for a in actions}
    pairs = {(a.get("method"), a.get("path")) for a in actions}
    pairs.update((b["method"], b["template"]) for r in rows for b in r.get("route_bindings", [])
                 if b.get("source") == "COLLECTED_AST_LITERAL")
    paths = {p for _, p in pairs if p}
    pointers = {a.get("state_probe", {}).get("json_pointer") for a in actions}
    mentioned_paths = {p.rstrip(".,;:)") for p in re.findall(r"(?<![\w/])/(?:[A-Za-z0-9._~%{}?=&:+-]+/?)+", text)}
    mentioned_paths = {p for p in mentioned_paths if p.split("=")[0] not in pointers}
    if mentioned_paths - paths:
        codes.add("HYPOTHESIS_PATH_NOT_IN_CITED_EVIDENCE")
    if set(re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", text)) - methods:
        codes.add("HYPOTHESIS_METHOD_NOT_IN_CITED_EVIDENCE")
    for method, path in re.findall(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[A-Za-z0-9/._~%{}?=&:+-]+)", text):
        if (method, path.rstrip(".,;:)")) not in pairs:
            codes.add("HYPOTHESIS_METHOD_PATH_MISMATCH")

    # 코드 문맥에 있는 숫자만 검사한다. item240/240ms/패키지 버전의 숫자를 HTTP 코드로 보지 않는다.
    pattern = r"(?P<label>실제|기대|actual|expected)?\s*(?:HTTP(?:\s+status)?(?:\s+code)?|상태\s*코드|status(?:_code|\s+code)?)\s*[:=]?\s*(?P<code>[1-5]\d{2})(?!\d)"
    for match in re.finditer(pattern, text, re.I):
        candidates = scoped_actions(rows, text[:match.start()])
        actual = {a["status_code"] for a in candidates if type(a.get("status_code")) is int}
        expected = {c for a in candidates for c in a.get("expected_status_codes", []) if type(c) is int}
        label = (match["label"] or "").lower()
        known = actual if label in {"실제", "actual"} else expected if label in {"기대", "expected"} else actual | expected
        if not known:
            codes.add("HYPOTHESIS_STATUS_EVIDENCE_UNAVAILABLE")
        elif int(match["code"]) not in known:
            codes.add("HYPOTHESIS_STATUS_MISMATCH")

    # 명시된 pointer와 실제/기대 표기를 대조한다. 표기 없는 자연어의 참/거짓은 추론하지 않는다.
    for match in re.finditer(r"(?P<label>실제|기대|actual|expected)\s+(?P<pointer>/?[A-Za-z_][A-Za-z0-9_/-]*)\s*[:=]\s*(?P<value>true|false)\b", text, re.I):
        pointer = "/" + match["pointer"].lstrip("/")
        key = "actual" if match["label"].lower() in {"실제", "actual"} else "expected"
        known = {a["state_probe"][key] for a in scoped_actions(rows, text[:match.start()])
                 if a.get("state_probe", {}).get("json_pointer") == pointer
                 and type(a["state_probe"].get(key)) is bool}
        if not known:
            codes.add("HYPOTHESIS_STATE_EVIDENCE_UNAVAILABLE")
        elif (match["value"].lower() == "true") not in known:
            codes.add("HYPOTHESIS_STATE_MISMATCH")
    return sorted(codes)

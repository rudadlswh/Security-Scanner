"""한글 기능 설명: 명시 등록한 루프백 테스트 환경에서 HTTP 권한·상태 변경 시나리오를 실행한다.
본문/인증 헤더는 결과에 저장하지 않는다. 리다이렉트·프록시·자동 재시도는 허용하지 않는다.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import unquote, urlsplit

import httpx

from .network import loopback_url
from .workspace import IDENTIFIER, ProductConfig, ProductError, ProductStore, digest, load_json, now, save_json


def pointer(value, path: str):
    if path == "":
        return value
    if not path.startswith("/"):
        raise ProductError("JSON_POINTER_INVALID")
    for part in path[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def validate_path(path: str, allowed: set[str]):
    parsed = urlsplit(path)
    decoded = unquote(parsed.path)
    if path not in allowed or not path.startswith("/") or path.startswith("//") or parsed.scheme or parsed.netloc or parsed.fragment or "\\" in decoded or ".." in decoded.split("/") or re.search(r"[\r\n\x00]", path):
        raise ProductError("HTTP_PATH_NOT_ALLOWED")


def validate_plan(target: dict, plan: dict):
    if target.get("authorized_disposable_environment") is not True or plan.get("version") != 1:
        raise ProductError("DISPOSABLE_TEST_ENVIRONMENT_AUTHORIZATION_REQUIRED")
    loopback_url(target["base_url"])
    if urlsplit(target["base_url"]).port == 11434:
        raise ProductError("OLLAMA_IS_NOT_A_DAST_TARGET")
    paths = set(target.get("allowed_paths", []))
    if not paths:
        raise ProductError("HTTP_ALLOWED_PATHS_REQUIRED")
    actors = target.get("actors", {})
    if not isinstance(actors, dict) or not actors:
        raise ProductError("HTTP_ACTORS_REQUIRED")
    scenarios = plan.get("scenarios", [])
    if not 1 <= len(scenarios) <= 20 or len({s.get("id") for s in scenarios}) != len(scenarios):
        raise ProductError("HTTP_SCENARIO_COUNT_OR_IDS_INVALID")
    count = 0
    for scenario in scenarios:
        if not isinstance(scenario.get("id"), str) or not IDENTIFIER.fullmatch(scenario["id"]):
            raise ProductError("HTTP_SCENARIO_ID_INVALID")
        for name in ("before", "after"):
            probe = scenario.get(name, {})
            if probe.get("method", "GET") != "GET" or "expected" not in probe or "json_pointer" not in probe:
                raise ProductError("BEFORE_AND_AFTER_JSON_STATE_PROBES_REQUIRED")
        cleanup_probe = scenario.get("cleanup_verify", {})
        if not scenario.get("cleanup") or cleanup_probe.get("method", "GET") != "GET" or "expected" not in cleanup_probe or "json_pointer" not in cleanup_probe:
            raise ProductError("CLEANUP_AND_STATE_VERIFICATION_REQUIRED")
        actions = [*scenario.get("setup", []), scenario["before"], scenario["request"], scenario["after"], *scenario.get("cleanup", []), cleanup_probe]
        count += len(actions)
        for action in actions:
            validate_path(action["path"], paths)
            if action.get("method", "GET") not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or action.get("actor") not in actors:
                raise ProductError("HTTP_METHOD_OR_ACTOR_INVALID")
            statuses = action.get("expect_status", [200])
            if not isinstance(statuses, list) or not statuses or any(type(x) is not int or not 100 <= x <= 599 for x in statuses):
                raise ProductError("EXPECTED_HTTP_STATUS_INVALID")
            if len(json.dumps(action.get("json", {})).encode()) > 65_536:
                raise ProductError("HTTP_REQUEST_BODY_LIMIT")
            for key in ("body_must_contain", "body_must_not_contain"):
                values = action.get(key, [])
                if not isinstance(values, list) or len(values) > 20 or any(not isinstance(v, str) or not v or len(v) > 256 for v in values):
                    raise ProductError("HTTP_BODY_ASSERTION_INVALID")
    max_requests = target.get("max_requests", 40)
    if type(max_requests) is not int or not 1 <= max_requests <= 100 or count > max_requests:
        raise ProductError("HTTP_REQUEST_BUDGET_INVALID")
    seconds = target.get("timeout_seconds", 120)
    if type(seconds) not in {int, float} or not 1 <= seconds <= 180:
        raise ProductError("HTTP_TIME_BUDGET_INVALID")
    for actor in actors.values():
        for header, variable in actor.get("headers_env", {}).items():
            if not re.fullmatch(r"[A-Za-z0-9-]+", header) or header.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                raise ProductError("HTTP_HEADER_NOT_ALLOWED")
            if not isinstance(variable, str) or variable not in os.environ or re.search(r"[\r\n]", os.environ[variable]):
                raise ProductError("HTTP_ACTOR_SECRET_ENV_MISSING_OR_INVALID")
    return paths


async def run_http_checks(config: ProductConfig, target_id: str) -> dict:
    if target_id not in config.http_targets:
        raise ProductError("HTTP_TARGET_NOT_REGISTERED")
    target = config.http_targets[target_id]
    path = Path(target["plan_file"]).expanduser().resolve(strict=True)
    plan = load_json(path)
    validate_plan(target, plan)
    plan_hash = digest(plan)
    store = ProductStore(config.results)
    report_id = store.create("http", {"kind": "http-security", "target_id": target_id, "plan_sha256": plan_hash})
    folder = store.folder(report_id)
    control = config.results / "control"
    control.mkdir(parents=True, exist_ok=True)
    lock = control / "http-check.lock"
    # A crash retains this lock. There is no automatic re-run or assumed cleanup.
    with lock.open("x", encoding="utf-8") as stream:
        stream.write(report_id)
    report = {"report_id": report_id, "kind": "http-security", "target_id": target_id, "status": "RUNNING", "scenarios": [],
              "evidence_contract": "http-expectations/2",
              "requests_sent": 0, "model_calls": 0, "plan_sha256": plan_hash, "started_at": now(),
              "verification": "OPERATOR_DEFINED_HTTP_STATE_PROBES_NOT_DIRECT_DB_ACCESS", "automatic_retry": False}
    save_json(folder / "report.json", report)
    deadline = time.monotonic() + target.get("timeout_seconds", 120)
    actors = target["actors"]
    base_url = loopback_url(target["base_url"])

    async def perform_action(client, spec, *, cleanup=False):
        if report["requests_sent"] >= target.get("max_requests", 40) or (not cleanup and time.monotonic() >= deadline):
            raise ProductError("HTTP_BUDGET_EXHAUSTED")
        validate_path(spec["path"], set(target["allowed_paths"]))
        headers = {name: os.environ[env] for name, env in actors[spec["actor"]].get("headers_env", {}).items()}
        report["requests_sent"] += 1
        save_json(folder / "report.json", report, replace=True)
        raw = bytearray()
        async with client.stream(spec.get("method", "GET"), base_url + spec["path"], headers=headers,
                                 **({"json": spec["json"]} if "json" in spec else {})) as response:
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 1_048_576:
                    raise ProductError("HTTP_RESPONSE_SIZE_LIMIT")
            matched = response.status_code in spec.get("expect_status", [200])
            outcome = {"method": spec.get("method", "GET"), "path": spec["path"], "actor": spec["actor"],
                       "status_code": response.status_code, "status_matches": matched, "body_sha256": digest(bytes(raw)),
                       "expected_status_codes": spec.get("expect_status", [200])}
        if "body_must_contain" in spec or "body_must_not_contain" in spec:
            # 승인된 고정 리터럴 비교의 boolean만 보존한다. HTML 실행/브라우저 취약성 입증이 아니다.
            checks = [{"literal_sha256": digest(value.encode("utf-8")), "expected_present": expected,
                       "matches": (value.encode("utf-8") in raw) is expected}
                      for key, expected in (("body_must_contain", True), ("body_must_not_contain", False))
                      for value in spec.get(key, [])]
            outcome["body_assertions"] = checks
            outcome["body_assertions_match"] = all(c["matches"] for c in checks)
        if "json_pointer" in spec:
            # 상태 문자열/ID/숫자/본문은 저장하지 않는다. 승인된 계획의 boolean 상태만 드러낸다.
            boolean_probe = type(spec["expected"]) is bool
            probe = {"value_visibility": "BOOLEAN_ONLY" if boolean_probe else "WITHHELD_NON_BOOLEAN"}
            if boolean_probe:
                probe.update(json_pointer=spec["json_pointer"], expected=spec["expected"])
            outcome["state_probe"] = probe
            try:
                actual = pointer(json.loads(raw), spec["json_pointer"])
                outcome["state_matches"] = type(actual) is type(spec["expected"]) and actual == spec["expected"]
                outcome["state_value_sha256"] = digest({"value": actual})
                if boolean_probe:
                    if type(actual) is bool:
                        probe.update(actual=actual, actual_availability="AVAILABLE")
                    else:
                        probe["actual_availability"] = "WITHHELD_NON_BOOLEAN"
            except (ValueError, KeyError, IndexError, TypeError):
                outcome["state_matches"] = False
                outcome["state_error"] = "STATE_PROBE_UNREADABLE"
                if boolean_probe:
                    probe["actual_availability"] = "UNREADABLE"
        await asyncio.sleep(0.25)
        return outcome

    async def action(client, spec, *, cleanup=False):
        remaining = deadline + (20 if cleanup else 0) - time.monotonic()
        if remaining <= 0:
            raise ProductError("HTTP_TIME_BUDGET_EXHAUSTED")
        return await asyncio.wait_for(perform_action(client, spec, cleanup=cleanup), timeout=min(12, remaining))

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            for scenario in plan["scenarios"]:
                if digest(load_json(path)) != plan_hash:
                    raise ProductError("HTTP_PLAN_CHANGED")
                row = {"id": scenario["id"], "status": "RUNNING", "setup": [], "cleanup": []}
                report["scenarios"].append(row)
                mutation_started = False
                try:
                    for spec in scenario.get("setup", []):
                        mutation_started = True
                        result = await action(client, spec)
                        row["setup"].append(result)
                        if not result["status_matches"]:
                            raise ProductError("HTTP_SETUP_FAILED")
                    row["before"] = await action(client, scenario["before"])
                    if not row["before"]["status_matches"] or not row["before"].get("state_matches"):
                        raise ProductError("HTTP_PRECONDITION_FAILED_NO_TARGET_REQUEST")
                    mutation_started = True
                    row["request"] = await action(client, scenario["request"])
                    row["after"] = await action(client, scenario["after"])
                    matched = row["request"]["status_matches"] and row["request"].get("body_assertions_match", True) and row["after"]["status_matches"] and row["after"].get("state_matches", False)
                    row["status"] = "MATCHES_EXPECTED_BEHAVIOR" if matched else "BEHAVIOR_DISCREPANCY"
                except asyncio.CancelledError:
                    row.update(status="INTERRUPTED", remote_completion="UNKNOWN")
                    raise
                except (ProductError, httpx.HTTPError, TimeoutError) as error:
                    row.update(status="INCOMPLETE", error_code=str(error) if isinstance(error, ProductError) else type(error).__name__)
                finally:
                    if mutation_started:
                        try:
                            for spec in scenario.get("cleanup", []):
                                result = await asyncio.shield(action(client, spec, cleanup=True))
                                row["cleanup"].append(result)
                            row["cleanup_verify"] = await asyncio.shield(action(client, scenario["cleanup_verify"], cleanup=True))
                            clean = row["cleanup_verify"]["status_matches"] and row["cleanup_verify"].get("state_matches")
                            row["cleanup_status"] = "COMPLETED" if clean and all(x["status_matches"] for x in row["cleanup"]) else "INCOMPLETE"
                        except (Exception, asyncio.CancelledError):
                            row["cleanup_status"] = "INCOMPLETE"
                    else:
                        row["cleanup_status"] = "NOT_NEEDED"
                    save_json(folder / "report.json", report, replace=True)
                if row["status"] == "INCOMPLETE" or row["cleanup_status"] == "INCOMPLETE":
                    break
        report["status"] = "COMPLETED" if len(report["scenarios"]) == len(plan["scenarios"]) and all(s["status"] != "INCOMPLETE" and s["cleanup_status"] != "INCOMPLETE" for s in report["scenarios"]) else "INCOMPLETE"
    except asyncio.CancelledError:
        report.update(status="INTERRUPTED", remote_completion="UNKNOWN")
        raise
    except Exception as error:
        report.update(status="INCOMPLETE", error_code=str(error) if isinstance(error, ProductError) else type(error).__name__)
    finally:
        report["ended_at"] = now()
        report["unexecuted_scenarios"] = len(plan["scenarios"]) - len(report["scenarios"])
        save_json(folder / "report.json", report, replace=True)
        if report["status"] == "COMPLETED" and lock.exists() and lock.read_text(encoding="utf-8") == report_id:
            lock.unlink()
    return report


def acknowledge_http(config: ProductConfig, report_id: str, cleanup_and_idle_confirmed: bool) -> dict:
    if not cleanup_and_idle_confirmed:
        raise ProductError("HTTP_CLEANUP_AND_IDLE_CONFIRMATION_REQUIRED")
    report = ProductStore(config.results).read(report_id)
    if report.get("kind") != "http-security" or report.get("status") not in {"INCOMPLETE", "INTERRUPTED", "RUNNING"}:
        raise ProductError("HTTP_REPORT_NOT_INTERRUPTED")
    lock = config.results / "control/http-check.lock"
    if not lock.exists() or lock.read_text(encoding="utf-8") != report_id:
        raise ProductError("HTTP_LOCK_MISMATCH")
    lock.unlink()
    save_json(ProductStore(config.results).folder(report_id) / "operator-acknowledgement.json", {"confirmed_at": now(), "source": "LOCAL_OPERATOR_CLI", "cleanup_and_idle_confirmed": True})
    return {"acknowledged": report_id, "automatic_retry": False, "requests_refunded": 0}

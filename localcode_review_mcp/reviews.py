"""한글 기능 설명: 로컬 관찰 작업·영속 예산·취소/중단·기존 Java 정책 파이프라인 연결."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import re
import time

import httpx

from .collector import AREAS, bridge, evidence_text
from .network import access_boundary, json_request, loopback_url
from .observation import AUTH_SYSTEM, FLOW_SYSTEM, FlowObservation, Observation, metadata_observation, validate_observation
from .token_budget import measure_input
from .workspace import ProductConfig, ProductError, ProductStore, Snapshot, digest, load_json, now, save_json

TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}


def prepare_request(snapshot: Snapshot, collection: dict, model: dict) -> dict:
    """사전 실측과 실제 전송이 같은 바이트의 프롬프트/스키마를 사용한다."""
    delete = collection["endpoint"]["http_method"] == "DELETE"
    payload = {"observation_id": collection["endpoint"]["endpoint_id"],
               "endpoint": {k: collection["endpoint"][k] for k in ("http_method", "http_path")},
               "evidence": evidence_text(snapshot, collection), "call_edges": collection["edges"],
               "unresolved_calls": collection["unresolved_calls"]}
    return {"model": model["name"], "stream": False, "think": False,
            "format": (Observation if delete else FlowObservation).model_json_schema(),
            "messages": [{"role": "system", "content": AUTH_SYSTEM if delete else FLOW_SYSTEM},
                         {"role": "user", "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}],
            "options": {"temperature": 0, "seed": 42, "num_ctx": 16384, "num_predict": 2048}}


def preflight_review(config: ProductConfig, project_id: str, collection_id: str) -> dict:
    """호출·예산 변경·원문 저장 없이 현재 스냅샷과 입력 길이만 검증한다."""
    collection = ProductStore(config.results).read(collection_id)
    if collection.get("project_id") != project_id or collection.get("collection_id") != collection_id:
        raise ProductError("COLLECTION_PROJECT_MISMATCH")
    if digest({k: v for k, v in collection.items() if k != "collection_sha256"}) != collection["collection_sha256"]:
        raise ProductError("COLLECTION_INTEGRITY_FAILED")
    root, project = config.project(project_id)
    snapshot = Snapshot.read(root, project.get("commit"))
    if digest(snapshot.metadata()) != collection["snapshot_sha256"]:
        raise ProductError("PROJECT_CHANGED_SINCE_COLLECTION")
    request = prepare_request(snapshot, collection, config.model)
    measurement = measure_input(request, config.model)
    snapshot.verify()
    return {"status": "INPUT_PREFLIGHT_PASSED", "project_id": project_id, "collection_id": collection_id,
            "request_sha256": digest(request), "measurement": measurement,
            "network_calls": 0, "model_calls": 0, "authorization_changed": False,
            "limitations": ["LIVE_BOUNDARY_MODEL_DIGEST_AND_SERVER_VERSION_RECHECKED_AT_EXECUTION",
                            "COLLECTION_SEMANTIC_COMPLETENESS_NOT_ESTABLISHED"]}


def process_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5  # Access denied means unknown; never assume completion.
        try:
            code = wintypes.DWORD()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _authorize_model(config: ProductConfig, *, calls: int, minutes: int, diagnostic: bool = False) -> dict:
    """로컬 CLI 전용. MCP에서 예산을 만들거나 증액하지 않는다."""
    if not 1 <= calls <= 20 or not 1 <= minutes <= 720:
        raise ProductError("AUTHORIZATION_LIMIT_INVALID")
    model = config.model
    if model.get("name") not in {"qwen3.5:9b", "qwen3-coder:30b"} or not isinstance(model.get("digest"), str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", model["digest"]):
        raise ProductError("MODEL_AND_FULL_DIGEST_REQUIRED")
    loopback_url(model.get("base_url", "http://127.0.0.1:11434"))
    folder = config.results / "control"
    folder.mkdir(parents=True, exist_ok=True)
    state = folder / "model-authorization.json"
    previous = load_json(state) if state.exists() else None
    if previous and previous.get("blocked"):
        raise ProductError("ACKNOWLEDGE_PREVIOUS_FAILURE_FIRST")
    if previous:
        save_json(folder / ("authorization-history-" + str(time.time_ns()) + ".json"), previous)
    value = {"model": model["name"], "digest": model["digest"], "calls_cap": calls, "calls_consumed": 0,
             "prior_cumulative_calls": (previous.get("prior_cumulative_calls", 0) + previous.get("calls_consumed", 0)) if previous else 0,
             "authorized_at": now(), "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)).isoformat(),
             "diagnostic_save": diagnostic, "blocked": False, "source": "LOCAL_OPERATOR_CLI", "historical_experiment_budget_reused": False}
    save_json(state, value, replace=True)
    return value


def authorize_model(config: ProductConfig, *, calls: int, minutes: int, diagnostic: bool = False) -> dict:
    folder = config.results / "control"
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / "review.lock"
    try:
        with lock.open("x", encoding="utf-8") as stream:
            stream.write("LOCAL_AUTHORIZATION")
    except FileExistsError:
        raise ProductError("ACTIVE_OR_UNKNOWN_REVIEW_EXISTS") from None
    try:
        return _authorize_model(config, calls=calls, minutes=minutes, diagnostic=diagnostic)
    finally:
        if lock.exists() and lock.read_text(encoding="utf-8") == "LOCAL_AUTHORIZATION":
            lock.unlink()


def authorize_scope(config: ProductConfig, collection_id: str, declaration: dict) -> dict:
    store = ProductStore(config.results)
    collection = store.read(collection_id)
    if declaration.get("collection_sha256") != collection["collection_sha256"] or not declaration.get("reviewer"):
        raise ProductError("SCOPE_DECLARATION_IDENTITY_INVALID")
    areas = declaration.get("areas", [])
    ids = {e["id"] for e in collection["evidence"]}
    if len(areas) != len(AREAS) or {a.get("area") for a in areas} != set(AREAS):
        raise ProductError("SIX_SCOPE_AREAS_REQUIRED")
    for area in areas:
        if not area.get("evidenceIds") or not set(area["evidenceIds"]) <= ids or not area.get("note"):
            raise ProductError("SCOPE_AREA_EVIDENCE_AND_NOTE_REQUIRED")
        if not isinstance(area.get("unresolvedLinks"), list):
            raise ProductError("SCOPE_UNRESOLVED_LIST_REQUIRED")
    value = {"collection_sha256": collection["collection_sha256"], "reviewer": declaration["reviewer"], "areas": areas,
             "recorded_at": now(), "source": "LOCAL_OPERATOR_DECLARATION_NOT_MODEL_OUTPUT", "semantic_proof": False}
    save_json(store.folder(collection_id) / "scope-review.json", value)
    return value


def scope_for(store: ProductStore, collection: dict) -> dict:
    ledger = json.loads(json.dumps(collection["ledger"]))
    path = store.folder(collection["collection_id"]) / "scope-review.json"
    if path.exists():
        review = load_json(path)
        if review["collection_sha256"] != collection["collection_sha256"]:
            raise ProductError("SCOPE_REVIEW_CHANGED_COLLECTION")
        ledger["areas"] = review["areas"]
    return ledger


class ReviewJobs:
    def __init__(self, config: ProductConfig):
        self.config = config
        self.store = ProductStore(config.results)
        self.tasks: dict[str, asyncio.Task] = {}

    def status(self, job_id: str) -> dict:
        status = self.store.read(job_id, "status.json")
        if status["state"] not in TERMINAL and job_id not in self.tasks and not process_alive(status.get("owner_pid")):
            status.update(state="INTERRUPTED", reason="SERVER_RESTARTED_NO_AUTOMATIC_RESEND", remote_completion="UNKNOWN" if status.get("request_sent") else "NOT_SENT")
            save_json(self.store.folder(job_id) / "status.json", status, replace=True)
        return status

    async def start(self, project_id: str, collection_id: str, policy: str = "NOT_PROVIDED") -> dict:
        if policy not in {"owner_only", "owner_or_admin", "authenticated_anyone", "NOT_PROVIDED"}:
            raise ProductError("POLICY_UNSUPPORTED")
        collection = self.store.read(collection_id)
        if collection.get("project_id") != project_id or collection.get("collection_id") != collection_id:
            raise ProductError("COLLECTION_PROJECT_MISMATCH")
        checksum = collection["collection_sha256"]
        if digest({k: v for k, v in collection.items() if k != "collection_sha256"}) != checksum:
            raise ProductError("COLLECTION_INTEGRITY_FAILED")
        if collection["endpoint"]["http_method"] != "DELETE" and policy != "NOT_PROVIDED":
            raise ProductError("DELETE_POLICY_CANNOT_BE_APPLIED_TO_OTHER_METHODS")
        if collection["endpoint"]["mapping_status"] != "AST_LITERAL":
            raise ProductError("ENDPOINT_MAPPING_UNRESOLVED")
        job_id = self.store.create("review", {"kind": "endpoint-review", "project_id": project_id, "collection_id": collection_id})
        status = {"job_id": job_id, "state": "QUEUED", "request_sent": False, "remote_completion": "NOT_SENT", "created_at": now(), "owner_pid": os.getpid()}
        save_json(self.store.folder(job_id) / "status.json", status)
        task = asyncio.create_task(self._run(job_id, collection, policy))
        self.tasks[job_id] = task
        task.add_done_callback(lambda _: self.tasks.pop(job_id, None))
        return status

    async def cancel(self, job_id: str) -> dict:
        task = self.tasks.get(job_id)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            status = self.store.read(job_id, "status.json")
            if status["state"] not in TERMINAL:
                status.update(state="CANCELLED", remote_completion="UNKNOWN" if status.get("request_sent") else "NOT_SENT", updated_at=now())
                save_json(self.store.folder(job_id) / "status.json", status, replace=True)
        return self.status(job_id)

    async def _run(self, job_id: str, collection: dict, policy: str):
        directory = self.store.folder(job_id)
        state = self.store.read(job_id, "status.json")
        control = self.config.results / "control"
        control.mkdir(parents=True, exist_ok=True)
        lock = control / "review.lock"
        lease_owned, sent, completed, authorization = False, False, False, None
        started = time.monotonic()

        def update(**changes):
            state.update(changes, updated_at=now())
            save_json(directory / "status.json", state, replace=True)

        try:
            # An interrupted owner must be acknowledged locally. Never guess a stale lock is safe to remove.
            with lock.open("x", encoding="utf-8") as stream:
                stream.write(job_id)
            lease_owned = True
            authorization_path = control / "model-authorization.json"
            if not authorization_path.exists():
                raise ProductError("MODEL_AUTHORIZATION_REQUIRED: use local CLI authorize-model")
            authorization = load_json(authorization_path)
            model = self.config.model
            if authorization.get("blocked") or authorization["calls_consumed"] >= authorization["calls_cap"]:
                raise ProductError("MODEL_BUDGET_BLOCKED_OR_EXHAUSTED")
            expiry = dt.datetime.fromisoformat(authorization["expires_at"])
            if expiry.tzinfo is None or dt.datetime.now(dt.timezone.utc) >= expiry:
                raise ProductError("MODEL_AUTHORIZATION_EXPIRED")
            if (model.get("name"), model.get("digest")) != (authorization["model"], authorization["digest"]):
                raise ProductError("MODEL_AUTHORIZATION_MISMATCH")
            root, project = self.config.project(collection["project_id"])
            expected_path = project.get("expected_observation_file")
            expected_sha256 = digest(load_json(Path(expected_path))) if expected_path else None
            snapshot = await asyncio.to_thread(Snapshot.read, root, project.get("commit"))
            if digest(snapshot.metadata()) != collection["snapshot_sha256"]:
                raise ProductError("PROJECT_CHANGED_SINCE_COLLECTION")
            delete = collection["endpoint"]["http_method"] == "DELETE"
            request = prepare_request(snapshot, collection, model)
            schema = request["format"]
            measurement = await asyncio.to_thread(measure_input, request, model)
            save_json(directory / "input-measurement.json", measurement)
            url = loopback_url(model.get("base_url", "http://127.0.0.1:11434"))
            boundary = await asyncio.to_thread(access_boundary, url)
            async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False) as client:
                tags = await json_request(client, "GET", url + "/api/tags")
                installed = [m for m in tags.get("models", []) if m.get("name") == model["name"]]
                if len(installed) != 1 or installed[0].get("digest", "").removeprefix("sha256:") != model["digest"].removeprefix("sha256:"):
                    raise ProductError("INSTALLED_MODEL_DIGEST_MISMATCH")
                if measurement.get("required_server_version"):
                    version = await json_request(client, "GET", url + "/api/version")
                    if version.get("version") != measurement["required_server_version"]:
                        raise ProductError("TOKENIZER_SERVER_VERSION_MISMATCH")
                await asyncio.to_thread(snapshot.verify)
                if dt.datetime.now(dt.timezone.utc) >= expiry:
                    raise ProductError("MODEL_AUTHORIZATION_EXPIRED")
                save_json(directory / "request-metadata.json", {"request_sha256": digest(request), "schema_sha256": digest(schema),
                          "source_snapshot_sha256": collection["snapshot_sha256"], **measurement, "access_boundary": boundary})
                authorization["calls_consumed"] += 1
                authorization["last_job_id"] = job_id
                save_json(authorization_path, authorization, replace=True)
                sent = True
                update(state="RUNNING", request_sent=True, remote_completion="UNKNOWN")
                remaining = (expiry - dt.datetime.now(dt.timezone.utc)).total_seconds()
                async with asyncio.timeout(min(600, remaining)):
                    async with httpx.AsyncClient(timeout=httpx.Timeout(min(600, remaining)), follow_redirects=False, trust_env=False) as model_client:
                        response = await json_request(model_client, "POST", url + "/api/chat", payload=request)
            completed = response.get("done") is True
            if authorization.get("diagnostic_save"):
                save_json(directory / "request.diagnostic.json", request)
                save_json(directory / "response.diagnostic.json", response)
            if not completed or response.get("done_reason") not in {None, "stop"}:
                raise ProductError("MODEL_RESPONSE_NOT_NORMAL_COMPLETION")
            message = response.get("message", {})
            if message.get("thinking") or response.get("thinking") or "<think>" in message.get("content", ""):
                raise ProductError("THINKING_CONTRACT_VIOLATION")
            actual_tokens = response.get("prompt_eval_count")
            if not isinstance(actual_tokens, int) or isinstance(actual_tokens, bool) or actual_tokens <= 0 or actual_tokens + 2048 + 512 > 16384:
                raise ProductError("SERVER_INPUT_TOKEN_GATE_FAILED")
            if measurement["exact_local_token_count"] is not None and abs(actual_tokens - measurement["exact_local_token_count"]) > 32:
                raise ProductError("SERVER_INPUT_TOKEN_DELTA_EXCEEDED")
            content = message.get("content", "")
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ProductError("DUPLICATE_MODEL_JSON_KEY")
                    result[key] = value
                return result
            raw = validate_observation(json.loads(content, object_pairs_hook=unique), collection["endpoint"]["endpoint_id"], {e["id"] for e in collection["evidence"]}, delete)
            await asyncio.to_thread(snapshot.verify)
            if delete:
                pipeline = await asyncio.to_thread(bridge, self.config, {"operation": "compare", "root": str(root), "policy": policy,
                                                                        "observation": raw, "ledger": scope_for(self.store, collection)})
            else:
                pipeline = {"verdict": "POLICY_UNDETERMINED", "verdict_source": "NOT_PERFORMED_POST_OBSERVATION_ONLY", "gate_status": "NOT_APPLICABLE"}
            report = {"report_id": job_id, "kind": "endpoint-review", "project_id": collection["project_id"], "collection_id": collection["collection_id"],
                      "endpoint": collection["endpoint"], "observation": metadata_observation(raw, delete), "pipeline": pipeline,
                      "evidence": collection["evidence"], "semantic_review_status": "NOT_REVIEWED", "diagnostic_saved": authorization.get("diagnostic_save", False),
                      "raw_response_sha256": digest(response), "content_sha256": digest(content.encode("utf-8")), "recorded_at": now(),
                      "timing": {k: response.get(k) for k in ("load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration", "total_duration")},
                      "wall_seconds": time.monotonic() - started, "snapshot_files_unchanged": True, "model_calls": 1,
                      "expected_sha256_before_request": expected_sha256,
                      "limitations": ["UNTESTED_PRODUCT_IMPLEMENTATION", "SCHEMA_AND_ID_VALIDATION_DO_NOT_ESTABLISH_SEMANTIC_CORRECTNESS", "CONSISTENTLY_WRONG_OBSERVATIONS_CAN_PASS_RULES"]}
            save_json(directory / "report.json", report)
            update(state="COMPLETED", remote_completion="COMPLETED", report_available=True, semantic_review_status="NOT_REVIEWED")
        except asyncio.CancelledError:
            update(state="CANCELLED", request_sent=sent, remote_completion="COMPLETED" if completed else "UNKNOWN" if sent else "NOT_SENT", automatic_retry=False)
            if sent and authorization is not None:
                authorization.update(blocked=True, block_job_id=job_id)
                save_json(control / "model-authorization.json", authorization, replace=True)
            raise
        except Exception as error:
            update(state="FAILED", request_sent=sent, remote_completion="COMPLETED" if completed else "UNKNOWN" if sent else "NOT_SENT",
                   reason=str(error) if isinstance(error, ProductError) else type(error).__name__, automatic_retry=False)
            if sent and authorization is not None:
                authorization.update(blocked=True, block_job_id=job_id)
                save_json(control / "model-authorization.json", authorization, replace=True)
        finally:
            # If the request may still be running, retain the process-independent lock for explicit local acknowledgement.
            if lease_owned and (not sent or completed):
                if lock.exists() and lock.read_text(encoding="utf-8") == job_id:
                    lock.unlink()


def acknowledge_failure(config: ProductConfig, job_id: str, remote_idle_confirmed: bool) -> dict:
    if not remote_idle_confirmed:
        raise ProductError("REMOTE_IDLE_CONFIRMATION_REQUIRED")
    store = ProductStore(config.results)
    status = store.read(job_id, "status.json")
    if status["state"] not in {"FAILED", "CANCELLED", "INTERRUPTED"}:
        raise ProductError("JOB_NOT_STOPPED")
    control = config.results / "control"
    state_path = control / "model-authorization.json"
    state = load_json(state_path)
    if state.get("last_job_id") != job_id:
        raise ProductError("FAILURE_JOB_MISMATCH")
    lock = control / "review.lock"
    if lock.exists():
        if lock.read_text(encoding="utf-8") != job_id:
            raise ProductError("ANOTHER_JOB_HOLDS_LOCK")
        lock.unlink()
    state.update(blocked=False, acknowledged_job_id=job_id, acknowledged_at=now())
    save_json(state_path, state, replace=True)
    return {"acknowledged": job_id, "calls_consumed": state["calls_consumed"], "calls_cap": state["calls_cap"], "calls_refunded": 0}

"""한글 기능 설명: 폴더 하나의 소스·의존성·일회용 HTTP 검사를 연결하고 통합 보고서를 보존한다.

MCP는 시작/상태/취소/보고서만 제공하며 기존 로컬 승인·예산을 증액하거나 설정을 바꾸지 않는다.
미실행과 미지원은 검사 성공/안전으로 바꾸지 않는다. 서버 시작 명령은 운영자 설정만 신뢰한다.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import datetime as dt
import os
from pathlib import Path
import shutil

from .collector import collect, inventory
from .audit import project_ledger
from .audit_surface import surface_inventory
from .source_security import scan_source_security
from .dependencies import scan_cves
from .disposable import DisposableServer
from .container_server import ContainerServer
from .http_checks import run_http_checks
from .reviews import ReviewJobs, process_alive
from .remediation import finding_context, generate as generate_remediation
from .remediation_compact import cve_recommendations, VERSION as REMEDIATION_VERSION
from .remediation_evidence import verification_plan
from .workspace import ProductConfig, ProductError, ProductStore, SKIP_DIRS, digest, load_json, now, replace_local_file, save_json

TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}


def safe_error(error: Exception) -> str:
    return str(error) if isinstance(error, ProductError) else type(error).__name__


def folder_config(config: ProductConfig, project_path: str):
    requested = Path(project_path).expanduser()
    if not requested.is_absolute() or requested.is_symlink() or (hasattr(requested, "is_junction") and requested.is_junction()):
        raise ProductError("ABSOLUTE_NON_LINK_PROJECT_DIRECTORY_REQUIRED")
    root = requested.resolve(strict=True)
    if not root.is_dir():
        raise ProductError("PROJECT_DIRECTORY_REQUIRED")
    if config.results.resolve() == root or config.results.resolve().is_relative_to(root):
        raise ProductError("RESULTS_MUST_BE_OUTSIDE_SOURCE_ROOT")
    matching = [(key, value) for key, value in config.projects.items() if Path(value["root"]).expanduser().resolve() == root]
    if len(matching) > 1:
        raise ProductError("REGISTERED_PROJECT_PATH_AMBIGUOUS")
    identifier, settings = matching[0] if matching else ("folder-" + digest(str(root).encode())[:20], {"root": str(root)})
    return replace(config, projects={**config.projects, identifier: dict(settings)}), identifier, root


def profile_for(config: ProductConfig, root: Path):
    profiles = [(key, value) for key, value in config.scan_profiles.items()
                if isinstance(value.get("project_root"), str) and Path(value["project_root"]).is_absolute()
                and Path(value["project_root"]).expanduser().resolve() == root]
    if len(profiles) > 1:
        raise ProductError("PROJECT_SCAN_PROFILE_AMBIGUOUS")
    return profiles[0] if profiles else (None, None)


def ai_permission(config: ProductConfig) -> str | None:
    control = config.results / "control"
    if (control / "review.lock").exists():
        return "ACTIVE_OR_UNKNOWN_REVIEW_EXISTS"
    path = control / "model-authorization.json"
    if not path.exists():
        return "MODEL_AUTHORIZATION_REQUIRED"
    try:
        approval = load_json(path)
        if approval.get("blocked"):
            return "MODEL_BUDGET_BLOCKED"
        if approval["calls_consumed"] >= approval["calls_cap"]:
            return "MODEL_BUDGET_EXHAUSTED"
        expiry = dt.datetime.fromisoformat(approval["expires_at"])
        if expiry.tzinfo is None or dt.datetime.now(dt.timezone.utc) >= expiry:
            return "MODEL_AUTHORIZATION_EXPIRED"
        if (approval["model"], approval["digest"]) != (config.model.get("name"), config.model.get("digest")):
            return "MODEL_AUTHORIZATION_MISMATCH"
    except (KeyError, TypeError, ValueError):
        return "MODEL_AUTHORIZATION_INVALID"
    return None


def reserve_remediation_call(config: ProductConfig) -> bool:
    """관찰이 마지막 승인 호출까지 소진하지 않도록 한다. 승인 파일은 수정하지 않는다."""
    path = config.results / "control/model-authorization.json"
    if not path.exists():
        return False
    value = load_json(path)
    return value["calls_cap"] - value["calls_consumed"] <= 1


def languages_at(root: Path) -> dict:
    extensions = {".java": "Java", ".kt": "Kotlin", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
                  ".mjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".cs": "C#", ".go": "Go", ".php": "PHP", ".rb": "Ruby"}
    found, walked = set(), 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.startswith(".")
                   and not (Path(parent) / name).is_symlink()
                   and not (hasattr(Path(parent) / name, "is_junction") and (Path(parent) / name).is_junction())]
        for name in names:
            walked += 1
            if walked > 20_000:
                raise ProductError("PROJECT_FILE_INVENTORY_LIMIT")
            language = extensions.get(Path(name).suffix)
            if language:
                found.add(language)
    return {"detected": sorted(found), "supported_source": ["Java/Spring supported subset"],
            "unsupported_source": sorted(found - {"Java"}), "method": "FILE_EXTENSIONS_ONLY"}


def markdown(report: dict) -> str:
    def cell(value):
        text = str(value).replace("\n", " ").replace("\r", " ").replace("\\", "\\\\").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for symbol in "|[]()!*_~`":
            text = text.replace(symbol, "\\" + symbol)
        return text
    lines = ["# LocalCode Review 통합 검사 보고서", "", f"작업 ID: {cell(report['report_id'])}",
             f"실행 상태: {cell(report['execution_state'])} · 검사 범위: {cell(report['coverage_status'])}",
             f"감사 원장: {cell(report.get('audit', {}).get('state', 'LEGACY_NOT_RECORDED'))} · 실행 완료는 후보 검증 완료가 아닙니다.",
             "", "이 보고서는 코드의 안전을 보증하지 않는다. 미지원·미실행·의미 미검토를 별도로 읽어야 한다.",
             "", "| 검사 단계 | 상태 | 사유/범위 |", "| --- | --- | --- |"]
    for name, stage in report["checks"].items():
        lines.append(f"| {cell(name)} | {cell(stage['status'])} | {cell(stage.get('reason', stage.get('coverage', '')))} |")
    lines += ["", "| 엔드포인트 | AI 관찰 | 정책 판정 |", "| --- | --- | --- |"]
    for row in report["endpoints"]:
        lines.append(f"| {cell(row['http_method'] + ' ' + row['http_path'])} | {cell(row.get('ai_status', 'NOT_RUN'))} | {cell(row.get('verdict', 'NOT_PERFORMED'))} |")
    lines += ["", "| 발견/관찰 종류 | 식별 정보 | 확정 범위 |", "| --- | --- | --- |"]
    for finding in report["findings"]:
        lines.append(f"| {cell(finding['kind'])} | {cell(finding.get('identifiers', finding.get('endpoint', '')))} | {cell(finding['basis'])} |")
    static = [f for f in report["findings"] if f["kind"] == "STATIC_SECURITY_CANDIDATE"]
    if static:
        lines += ["", "## 소스 보안 후보와 수정 검증", "", "AST 입력 흐름 후보이며 실제 악용이나 보안 원인을 확정하지 않습니다.", ""]
        for f in static:
            lines += ["- " + cell(f"{f['rule_id']} {f['path']}:{f['line']}"),
                      "  - 탐지 엔진: " + cell(f.get('engine','LOCALCODE_JAVA_AST')),
                      "  - 추적 입력: " + cell(f["source_parameters"]),
                      "  - 조건부 수정: " + cell(f["remediation"]["change"]),
                      "  - 검증: " + cell(f["remediation"]["tests"])]
    fixed = report.get("checks", {}).get("fix", {})
    if fixed.get("report_id"):
        lines += ["", "## 복사본 수정 전후 검증", "", "결과: " + cell(fixed.get("verification")),
                  "원본 자동 적용: 없음", "전후 비교: " + cell({"before": fixed.get("before"), "after": fixed.get("after")}),
                  "상세 보고서 ID: " + cell(fixed["report_id"]), "", "등록된 규칙·시나리오의 결과이며 다른 경로의 안전이나 배포 승인을 뜻하지 않습니다."]
    advice = report.get("checks", {}).get("remediation", {})
    plan = report.get("verification_plan") or advice.get("verification_plan")
    if plan is not None:
        lines += ["", "## 하네스의 고정 검증 조건", "", "원래 기대 조건에서 생성한 목록입니다. AI가 만든 테스트나 수정 후 검증 완료 결과가 아닙니다.", ""]
        for test in plan.get("cases", []):
            lines += ["- " + cell(test["finding_id"] + ": " + test["status"])]
            if test["kind"] == "HTTP_EXPECTATION":
                lines += ["  - 요청: " + cell(test["request"]), "  - 기대 HTTP: " + cell(test["expected_status_codes"]),
                          "  - 기대 상태: " + cell({"json_pointer": test["state_json_pointer"], "expected": test["expected_state"]})]
                if test["missing_fields"]:
                    lines.append("  - 없는 조건(추정하지 않음): " + cell(test["missing_fields"]))
            else:
                lines += ["  - 패키지: " + cell(test["package"]), "  - 수정 후보(호환성 미확인): " + cell(test["candidate_versions"])]
                lines += ["  - " + cell(value) for value in test["checklist"]]
    lines += ["", "## 해결방안 — 하네스 절차와 AI 검토 제안", "", "출처를 구분해 표시합니다. 자동 적용·수정 완료·안전 승인이 아닙니다.", ""]
    if advice.get("status") != "COMPLETED":
        lines.append(cell(advice.get("reason", advice.get("status", "NOT_RUN"))))
    if advice.get("consistency_check"):
        lines += ["구조·근거 대조: " + cell(advice["consistency_check"]["status"]),
                  "", ("AI의 영역 선택은 의미 미검토입니다. 이 상태는 내용 품질 통과가 아닙니다."
                         if advice.get("contract_version") in {"security-remediation/13", "security-remediation/14", "security-remediation/15", "security-remediation/16", REMEDIATION_VERSION} else
                         "AI의 영역 선택과 메모 의미는 검사하지 않았습니다. 이 상태는 내용 품질 통과가 아닙니다."
                         if advice.get("contract_version") == "security-remediation/12" else
                         "이 대조는 자유문 전체의 의미 정확성을 검사하지 않으며 문자 대조는 오탐/누락될 수 있습니다.")]
    for row in advice.get("recommendations", []):
        rationale_label = "AI 설명(보류 · 관찰 행위자 범위 확인 필요): " if row.get("rationale_review", {}).get("disposition") == "WITHHELD_FOR_REVIEW" else "AI 설명(미검토): "
        if row.get("rationale_source") == "HARNESS_EVIDENCE":
            rationale_label = "저장 근거 설명(하네스 작성): "
        lines += ["", "### " + cell(row["finding_id"] + ": " + row["title"]), "", rationale_label + cell(row["rationale"]),
                  "", "근거 보고서: " + cell(row["evidence_report_id"])]
        if row.get("presentation_source") == "HARNESS_EVIDENCE":
            lines += ["", "확인된 영향(하네스): " + cell(row["confirmed_impact"]),
                      "심각도: " + cell(row["severity"]) + " · 악용 가능성: " + cell(row["exploitability"])]
        if row.get("dependency_review"):
            dependency = row["dependency_review"]
            lines += ["", "하네스의 공지 후보 대조(모델 호출 없음):",
                      "- 공지별 후보·출처: " + cell(dependency["candidate_provenance"]),
                      "- 버전 선택: 보류 · 브랜치/호환성 미확인 · 이상 버전의 안전 범위가 아님"]
        if row.get("ai_review"):
            selection = row["ai_review"]
            lines += ["", "AI 점검 우선순위(의미 미검토·원인 확정 아님): " + cell(selection["focus"]),
                      "인용 근거: " + cell(selection["evidence_ids"])]
            if "review_note" in selection:
                lines.append("AI 검토 메모(미검토): " + cell(selection["review_note"]))  # 과거 /12 결과 표시 전용
        if row.get("focus_explanation"):
            lines += ["", "점검 안내(하네스 작성·AI 선택에 따른 조건부 안내): " + cell(row["focus_explanation"]["text"])]
        if row.get("review_procedure"):
            lines += ["", "하네스 작성 검토·수정 절차(실제 구현 관찰이나 적용 승인이 아님):", ""]
            lines += ["- " + cell(step) for step in row["review_procedure"]["steps"]]
        for key, title in (("observed_facts", "AI가 요약한 관찰 사실(미검토)"), ("cause_hypotheses", "확인 필요한 원인 가설"),
                           ("recommended_changes", "권장 변경"), ("policy_questions", "추가 정책 확인 질문(적용 미승인)"), ("additional_checks", "AI의 추가 확인 제안(미검토)"),
                           ("verification_tests", "이전 계약의 AI 확인 테스트(미검토)"), ("cautions", "주의/미확인")):
            if key not in row:
                continue  # 이전 /1 결과도 바꾸지 않고 표시할 수 있다.
            if key == "observed_facts" and row.get("observed_facts_source") == "HARNESS_EVIDENCE":
                title = "하네스가 근거에서 표시한 관찰 사실(AI 작성 아님)"
            lines += ["", title + ":", ""]
            for value in row[key]:
                if not isinstance(value, dict):
                    lines.append("- " + cell(value))
                    continue
                lines.append("- " + cell(value["text"]) + " · 근거: " + cell(", ".join(value["evidence_ids"])))
                if key == "cause_hypotheses" and value.get("disposition") == "WITHHELD_FOR_REVIEW":
                    lines.append("  - 보류 가설 · 인용 근거와 재대조 필요: " + cell(value.get("withheld_reasons", [])))
                if key == "additional_checks" and value.get("disposition") == "WITHHELD_FOR_REVIEW":
                    lines.append("  - 보류 추가 점검 · 근거 없는 설계 제한인지 확인: " + cell(value.get("withheld_reasons", [])))
                if value.get("scope"):
                    label = "추가 정책 확인 대상 · 적용 미승인" if value["scope"] == "ADDITIONAL_POLICY_REVIEW" else "확인된 대상 범위에 한정 · 내용 미검토"
                    if value.get("disposition") == "WITHHELD_FOR_REVIEW":
                        label = "보류 권고 · 그대로 적용하지 마세요 · " + label
                    lines.append("  - 분류: " + label)
                    if value.get("withheld_reasons"):
                        lines.append("  - 보류 사유: " + cell(value["withheld_reasons"]))
                    lines.append("  - 근거 대상: " + cell(value.get("scope_binding", {}).get("targets", [])))
                if value.get("ownership_check"):
                    lines.append("  - 구현 시 확인할 소유권 설계(실제 코드 관찰 아님): " + cell(value["ownership_check"]))
                    if value.get("owner_source_verification"):
                        lines.append("  - 소유자 출처·조회 순서는 제안이며 실제 구현 검증 전입니다.")
                if "confirmation_needed" in value:
                    lines.append("  - 추가 확인: " + cell(value["confirmation_needed"]))
                for assumption in value.get("assumptions", []):
                    lines.append("  - 적용 가정: " + cell(assumption))
                if value.get("kind") == "HTTP_SCENARIO":
                    lines.append("  - 구조화 조건: " + cell({k: value.get(k) for k in ("request_method", "request_path", "request_actor", "expected_status_codes", "state_json_pointer", "expected_state")}))
                if value.get("kind") == "DEPENDENCY_REGRESSION":
                    lines.append("  - 버전 후보(호환성 미검토): " + cell(value.get("candidate_version")))
        if row.get("consistency_issues"):
            lines += ["", "**기대 조건 대조 경고 — 그대로 적용하지 마세요.**", ""]
            lines += ["- " + cell(issue["code"]) for issue in row["consistency_issues"]]
    lines += ["", "제한 사항:", ""] + ["- " + cell(value) for value in report["limitations"]]
    return "\n".join(lines) + "\n"


def acknowledge_scan(config: ProductConfig, scan_id: str, stopped_confirmed: bool):
    """로컬 운영자의 프로세스/데이터 확인 후 통합 잠금만 해제한다. AI/HTTP 잠금과 예산은 건드리지 않는다."""
    if not stopped_confirmed:
        raise ProductError("DISPOSABLE_PROCESSES_AND_CLEANUP_CONFIRMATION_REQUIRED")
    jobs = ProjectScans(config)
    state = jobs.status(scan_id)
    if state["state"] not in {"FAILED", "CANCELLED", "INTERRUPTED"}:
        raise ProductError("PROJECT_SCAN_NOT_STOPPED")
    lock = config.results / "control/project-scan.lock"
    if not lock.exists() or lock.read_text(encoding="utf-8") != scan_id:
        raise ProductError("PROJECT_SCAN_LOCK_MISMATCH")
    folder = jobs.store.folder(scan_id)
    for name in ("server-workspace", "server-temp"):
        target = folder / name
        if target.exists():
            if target.is_symlink() or (hasattr(target, "is_junction") and target.is_junction()) or target.resolve().parent != folder.resolve():
                raise ProductError("DISPOSABLE_CLEANUP_PATH_INVALID")
            shutil.rmtree(target.resolve())
    lock.unlink()
    state.update(local_stop_acknowledged_at=now())
    save_json(folder / "status.json", state, replace=True)
    return {"acknowledged": scan_id, "model_budget_changed": False, "review_http_locks_changed": False}


class ProjectScans:
    def __init__(self, config: ProductConfig):
        self.config, self.store = config, ProductStore(config.results)
        self.tasks = {}

    def status(self, scan_id: str):
        state = self.store.read(scan_id, "status.json")
        if state.get("kind") != "project-security-scan":
            raise ProductError("NOT_A_PROJECT_SCAN")
        if state["state"] not in TERMINAL and scan_id not in self.tasks and not process_alive(state.get("owner_pid")):
            state.update(state="INTERRUPTED", phase="PROCESS_EXITED_NO_AUTOMATIC_RESUME", updated_at=now())
            save_json(self.store.folder(scan_id) / "status.json", state, replace=True)
            report = self.store.read(scan_id)
            report.update(execution_state="INTERRUPTED", coverage_status="PARTIAL")
            for stage in report["checks"].values():
                if stage["status"] in {"PENDING", "RUNNING"}:
                    stage.update(status="NOT_RUN", reason="PROCESS_INTERRUPTED_NO_AUTOMATIC_RESUME")
            self._save(report)
        return state

    def report(self, scan_id: str):
        self.status(scan_id)
        report = self.store.read(scan_id)
        if report.get("kind") != "project-security-scan":
            raise ProductError("NOT_A_PROJECT_SCAN")
        return report

    async def start(self, project_path: str, max_endpoints: int = 100, max_ai_endpoints: int = 20, include_remediation: bool = True):
        if type(include_remediation) is not bool:
            raise ProductError("REMEDIATION_OPTION_MUST_BE_BOOLEAN")
        if type(max_endpoints) is not int or not 1 <= max_endpoints <= 500 or type(max_ai_endpoints) is not int or not 0 <= max_ai_endpoints <= 20:
            raise ProductError("PROJECT_SCAN_LIMIT_INVALID")
        config, project_id, root = folder_config(self.config, project_path)
        profile_id, profile = profile_for(config, root)
        control = config.results / "control"
        control.mkdir(parents=True, exist_ok=True)
        lock = control / "project-scan.lock"
        try:
            with lock.open("x", encoding="utf-8") as stream:
                stream.write("STARTING")
        except FileExistsError:
            raise ProductError("ACTIVE_OR_INTERRUPTED_PROJECT_SCAN_EXISTS") from None
        try:
            identifier = self.store.create("scan", {"kind": "project-security-scan", "project_id": project_id})
            lock.write_text(identifier, encoding="utf-8")
            state = {"job_id": identifier, "kind": "project-security-scan", "state": "QUEUED", "phase": "QUEUED",
                     "created_at": now(), "owner_pid": os.getpid(), "report_available": True}
            save_json(self.store.folder(identifier) / "status.json", state)
            report = {"report_id": identifier, "kind": "project-security-scan", "execution_state": "QUEUED", "coverage_status": "NOT_COMPLETE",
                      "project_id": project_id, "project_path": str(root), "profile_id": profile_id, "started_at": now(),
                      "checks": {name: {"status": "PENDING"} for name in ("source", "sast", "ai", "cve", "dynamic", "remediation", "fix")},
                      "endpoints": [], "findings": [], "errors": [], "model_calls_sent": 0,
                      "authors": config.projects[project_id].get("proposal_authors", []),
                      "audit_contract_version": "audit-ledger/2",
                      "review_policy_sha256": digest(config.audit_policy.get('trusted_reviewers', {})),
                      "discovery_model_digest": config.model.get('digest'),
                      "limits": {"max_endpoints": max_endpoints, "max_ai_endpoints": max_ai_endpoints,
                                 "include_remediation": include_remediation, "remediation_max_findings": 20},
                      "security_verdict": "NOT_ASSESSED", "limitations": [
                          "Java/Spring·Python http.server 지원 구간의 제한된 선언 연결이며 자동 수집의 완전성을 증명하지 않는다.",
                          "AI 응답은 형식 검증을 거친 관찰이며 의미 정확성을 자동 승인하지 않는다.",
                          "CVE는 제공/해석된 패키지의 버전 영향 대조이며 악용 검증이 아니다.",
                          "동적 검사는 등록된 일회용 서버·명시 시나리오에 한정된다.",
                          "기존 로컬 생성 예산과 OSV/실행 설정을 사용하며 자동 승인·증액하지 않는다.",
                          "AI 해결방안은 검사 근거에 대한 미검토 제안이며 자동 적용·수정 검증을 하지 않는다."]}
            self._save(report)
            task = asyncio.create_task(self._run(identifier, config, root, report, profile, max_endpoints, max_ai_endpoints))
            self.tasks[identifier] = task
            task.add_done_callback(lambda _: self.tasks.pop(identifier, None))
            return state
        except Exception:
            lock.unlink(missing_ok=True)
            raise

    def _save(self, report):
        report['audit'] = project_ledger(report)
        folder = self.store.folder(report["report_id"])
        save_json(folder / "report.json", report, replace=True)
        path = folder / "report.md"
        temporary = folder / "report.md.tmp"
        temporary.write_text(markdown(report), encoding="utf-8", newline="\n")
        replace_local_file(temporary, path)

    async def cancel(self, scan_id: str):
        task = self.tasks.get(scan_id)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            state = self.store.read(scan_id, "status.json")
            if state["state"] == "QUEUED":
                # 최초 코루틴 실행 전에 취소되면 _run의 finally가 실행되지 않는다.
                report = self.store.read(scan_id)
                report.update(execution_state="CANCELLED", coverage_status="PARTIAL", finished_at=now())
                for stage in report["checks"].values():
                    stage.update(status="NOT_RUN", reason="CANCELLED_BEFORE_START")
                self._save(report)
                state.update(state="CANCELLED", phase="FINISHED", updated_at=now())
                save_json(self.store.folder(scan_id) / "status.json", state, replace=True)
                lock = self.config.results / "control/project-scan.lock"
                if lock.exists() and lock.read_text(encoding="utf-8") == scan_id:
                    lock.unlink()
        return self.status(scan_id)

    async def _run(self, identifier, config, root, report, profile, maximum, ai_maximum):
        folder, state = self.store.folder(identifier), self.store.read(identifier, "status.json")
        snapshot, server, reviews, child_id = None, None, None, None
        unsafe_cleanup = False

        def phase(name):
            state.update(state="RUNNING", phase=name, updated_at=now())
            report["execution_state"] = "RUNNING"
            save_json(folder / "status.json", state, replace=True)
            self._save(report)

        def fail(stage, error):
            report["checks"][stage].update(status="INCOMPLETE", reason=safe_error(error))
            report["errors"].append({"stage": stage, "reason": safe_error(error)})
            self._save(report)

        def finding(row):
            if len(report["findings"]) < 500:
                row["finding_id"] = "F" + str(len(report["findings"]) + 1).zfill(3)
                report["findings"].append(row)
            else:
                report["findings_omitted_by_limit"] = report.get("findings_omitted_by_limit", 0) + 1

        try:
            phase("SOURCE")
            report["languages"] = await asyncio.to_thread(languages_at, root)
            try:
                prepared = await asyncio.to_thread(inventory, config, report["project_id"])
                snapshot, _, info = prepared
                report["source_snapshot_sha256"] = info["snapshot_sha256"]
                report["source_identity"] = info["snapshot"]["identity"]
                report['surface_inventory'] = surface_inventory(snapshot, info)
                stage = {"status": "PARTIAL" if info["support_reasons"] else "COMPLETED", "coverage": info["support"],
                         "reasons": info["support_reasons"], "excluded_sources": info["snapshot"]["excluded"],
                         "endpoint_count": len(info["endpoints"]), "endpoints_collected": 0,
                         "endpoints_omitted_by_limit": max(0, len(info["endpoints"]) - maximum)}
                if info.get('source_language') == 'Python':
                    report['languages']['supported_source'].append('Python/http.server literal dispatch subset')
                    report['languages']['unsupported_source'] = [n for n in report['languages']['unsupported_source'] if n != 'Python']
                    stage.update(source_language='Python',raw_source_allowed_for_ai=False)
                elif not any(p.endswith(".java") for p in snapshot.files):
                    stage.update(status="UNSUPPORTED", reason="NO_SUPPORTED_JAVA_SOURCES")
                elif not info["endpoints"]:
                    stage.update(status="PARTIAL", reason="NO_SUPPORTED_SPRING_ENDPOINTS")
                if stage["endpoints_omitted_by_limit"]:
                    stage["status"] = "PARTIAL"
                report["checks"]["source"] = stage
                try:
                    static = await asyncio.to_thread(scan_source_security, config, report["project_id"], prepared)
                    report["checks"]["sast"] = {"status":static["status"],"report_id":static["report_id"],
                        "candidate_count":len(static["findings"]),"coverage":static["coverage"],"errors":static["errors"]}
                    for candidate in static["findings"]:
                        finding({**candidate,"report_id":static["report_id"]})
                except Exception as error:
                    fail("sast", error)
                for endpoint in info["endpoints"][:maximum]:
                    row = {key: endpoint[key] for key in ("endpoint_id", "http_method", "http_path", "mapping_status")}
                    try:
                        collection = await asyncio.to_thread(collect, config, report["project_id"], endpoint["endpoint_id"], prepared=prepared)
                        row.update(collection_id=collection["collection_id"], evidence_count=len(collection["evidence"]),
                                   unresolved_calls=len(collection["unresolved_calls"]), collection_status="COMPLETED", ai_status="PENDING")
                        if collection.get('source_language') == 'Python':
                            row.update(ai_status='SKIPPED',ai_skip_reason='PYTHON_RAW_SOURCE_AI_NOT_SUPPORTED')
                        stage["endpoints_collected"] += 1
                    except Exception as error:
                        row.update(collection_status="INCOMPLETE", ai_status="SKIPPED", reason=safe_error(error))
                        stage["status"] = "PARTIAL"
                    report["endpoints"].append(row)
                    self._save(report)
            except Exception as error:
                fail("source", error)
                if report["checks"]["sast"]["status"] == "PENDING":
                    report["checks"]["sast"].update(status="SKIPPED",reason="SOURCE_UNAVAILABLE")

            phase("AI_OBSERVATIONS")
            reviews = ReviewJobs(config)
            completed, attempts, skip_reason = 0, 0, None
            for row in report["endpoints"]:
                if row.get("ai_status") != "PENDING":
                    continue
                reason = "AI_ENDPOINT_LIMIT" if attempts >= ai_maximum else ai_permission(config)
                if reason is None and report["limits"]["include_remediation"] and reserve_remediation_call(config):
                    reason = "MODEL_CALL_RESERVED_FOR_REMEDIATION"
                if row["mapping_status"] != "AST_LITERAL":
                    reason = "ENDPOINT_MAPPING_UNRESOLVED"
                if skip_reason:
                    reason = skip_reason
                if reason:
                    row.update(ai_status="SKIPPED", ai_skip_reason=reason)
                    continue
                try:
                    started = await reviews.start(report["project_id"], row["collection_id"], "NOT_PROVIDED")
                    attempts += 1
                    child_id = started["job_id"]
                    row.update(review_id=child_id, ai_status="RUNNING")
                    self._save(report)
                    await asyncio.shield(reviews.tasks[child_id])
                    status = reviews.status(child_id)
                    report["model_calls_sent"] += int(status.get("request_sent") is True)
                    row["ai_status"] = status["state"]
                    if status["state"] != "COMPLETED":
                        skip_reason = "PREVIOUS_AI_FAILURE_NO_AUTOMATIC_CONTINUATION"
                        row["ai_failure_reason"] = status.get("reason")
                    else:
                        child = reviews.store.read(child_id)
                        row.update(observation=child["observation"], verdict=child["pipeline"]["verdict"],
                                   semantic_review_status=child["semantic_review_status"], diagnostic_saved=child["diagnostic_saved"])
                        completed += 1
                    child_id = None
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    row.update(ai_status="INCOMPLETE", ai_failure_reason=safe_error(error))
                    skip_reason = "PREVIOUS_AI_FAILURE_NO_AUTOMATIC_CONTINUATION"
                self._save(report)
            report["checks"]["ai"] = {"status": "COMPLETED" if completed and all(r.get("ai_status") == "COMPLETED" for r in report["endpoints"]) else "PARTIAL" if attempts else "SKIPPED",
                                      "attempted": attempts, "completed": completed,
                                      "reason": skip_reason or next((r.get("ai_skip_reason") for r in report["endpoints"] if r.get("ai_skip_reason")), "NO_ELIGIBLE_ENDPOINTS" if not completed else "SEMANTIC_REVIEW_NOT_PERFORMED"),
                                      "semantic_review_status": "NOT_REVIEWED"}

            phase("DEPENDENCY_CVES")
            try:
                if snapshot is not None and info.get('source_language') == 'Python':
                    from .python_dependencies import scan as scan_python_cves
                    cves = await asyncio.to_thread(scan_python_cves, config, report['project_id'], snapshot)
                else:
                    cves = await scan_cves(config, report["project_id"], config.allow_osv_network)
                report["checks"]["cve"] = {"status": "COMPLETED" if cves["status"] == "COMPLETED_FOR_LISTED_PACKAGES" and cves["inventory"]["packages"] else "PARTIAL",
                    "report_id": cves["report_id"], "coverage": cves["inventory"]["coverage"],
                    "online_queries": cves["queries_sent"], "package_count": len(cves["inventory"]["packages"]),
                    "reason": "ONLINE_QUERY_APPROVED" if config.allow_osv_network else "CACHE_ONLY_OSV_NETWORK_NOT_APPROVED",
                    "unresolved": cves["inventory"]["unresolved"]}
                if not cves["inventory"]["packages"]:
                    report["checks"]["cve"].update(status="SKIPPED", reason="NO_SUPPORTED_EXACT_PYPI_PINS" if cves['inventory'].get('source_ecosystem')=='PyPI' else "NO_SUPPORTED_RESOLVED_MAVEN_PACKAGES")
                if cves['inventory'].get('source_ecosystem')=='PyPI':
                    report['checks']['cve'].update(reason='EXPLICIT_PYPI_ADAPTER' if cves['queries_sent'] else 'PYPI_NETWORK_OR_TOOL_NOT_APPROVED',
                        engine='PIP_AUDIT',raw_advisory_count=cves.get('raw_advisory_count',0),
                        unique_package_advisory_count=cves.get('unique_package_advisory_count',0))
                for package in cves["packages"]:
                    for group in package.get("vulnerability_groups", []):
                        finding({"kind": "DEPENDENCY_VERSION_MATCH", "identifiers": group["identifiers"],
                                 "package": {k: package["package"][k] for k in ("ecosystem", "name", "version")},
                                 "basis": "VERSION_MATCH_NOT_EXPLOITABILITY", "lookup_status": package["status"], "report_id": cves["report_id"]})
            except Exception as error:
                fail("cve", error)

            phase("DYNAMIC_HTTP")
            if profile and profile.get('python_validation') and snapshot is not None and info.get('source_language') == 'Python':
                try:
                    from .python_validation import run as run_python_validation
                    child = await run_python_validation(config, report['project_id'], snapshot, info, static, profile, folder)
                    report['checks']['dynamic'] = {'status':child['status'],'report_id':child['report_id'],
                        'case_count':len(child['cases']),'matched':sum(c['matches'] for c in child['cases']),
                        'requests_sent':child['requests_sent'],'browser':child['browser'],'server':child['server']}
                    report['python_evidence_links'] = [{'scenario_id':c['id'],'http_report_id':child['report_id'],
                        'source_link_status':c['source_link_status'],'static_evidence_ids':c.get('static_evidence_ids',[]),
                        'registered_behavior_matches':c['matches'],'intent':c['intent'],'binding':c['binding']}
                        for c in child['cases'] if c.get('binding')]
                    if child['status']!='COMPLETED':report['errors'].append({'stage':'dynamic','reason':child.get('reason','PYTHON_VALIDATION_MISMATCH')})
                except asyncio.CancelledError:raise
                except Exception as error:fail('dynamic',error)
            elif profile is None:
                report["checks"]["dynamic"] = {"status": "SKIPPED", "reason": "NO_OPERATOR_REGISTERED_SCAN_PROFILE"}
            else:
                try:
                    names = profile.get("http_target_ids", [])
                    if not isinstance(names, list) or not names or len(names) > 10 or len(set(names)) != len(names) or any(name not in config.http_targets for name in names):
                        raise ProductError("SCAN_PROFILE_HTTP_TARGETS_REQUIRED")
                    spec = profile.get("disposable_server")
                    if not isinstance(spec, dict):
                        raise ProductError("DISPOSABLE_SERVER_SETTINGS_REQUIRED")
                    if snapshot is not None:
                        await asyncio.to_thread(snapshot.verify)
                    backend = spec.get("isolation_backend", "local_process")
                    if backend not in {"local_process", "docker"}:
                        raise ProductError("ISOLATION_BACKEND_UNSUPPORTED_NO_FALLBACK")
                    server = (ContainerServer if backend == "docker" else DisposableServer)(spec, root, folder, [config.http_targets[name] for name in names])
                    report["checks"]["dynamic"] = {"status": "RUNNING", "targets": [], "server": server.metadata}
                    await server.start()
                    for target in names:
                        child = await run_http_checks(config, target)
                        report["checks"]["dynamic"]["targets"].append({"target_id": target, "report_id": child["report_id"], "status": child["status"]})
                        for scenario in child["scenarios"]:
                            if scenario["status"] == "BEHAVIOR_DISCREPANCY":
                                finding({"kind": "DYNAMIC_BEHAVIOR_DISCREPANCY", "identifiers": [scenario["id"]], "target_id": target,
                                         "basis": "CONFIGURED_HTTP_AND_STATE_EXPECTATIONS", "report_id": child["report_id"]})
                        if child["status"] != "COMPLETED":
                            raise ProductError("DYNAMIC_REQUEST_OR_CLEANUP_INCOMPLETE")
                    report["checks"]["dynamic"]["status"] = "COMPLETED"
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    fail("dynamic", error)
                finally:
                    if server is not None:
                        await server.stop()
                        report["disposable_server"] = server.metadata
            if snapshot is not None:
                await asyncio.to_thread(snapshot.verify)
                report["source_snapshot_unchanged"] = True
            if profile and profile.get('python_dependency_runtime'):
                phase('PYTHON_DEPENDENCY_RUNTIME')
                from .python_runtime import run as run_python_runtime
                task = asyncio.create_task(asyncio.to_thread(run_python_runtime,config,report['project_id'],profile['python_dependency_runtime']))
                try:
                    result = await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise
                report['checks']['dependency_runtime'] = {'status':'COMPLETED' if result['status']=='MATCHES_REGISTERED_CHECKS' else 'INCOMPLETE',
                    'report_id':result['report_id'],'verification':result['status'],
                    'registered_conditions_fixed':result.get('registered_conditions_fixed',False),
                    'ordinary_api_checks_passed':result.get('ordinary_api_checks_passed',False),
                    'application_runtime_use_proven':False,'deployment_compatibility_proven':False,'cleanup':result['cleanup']}
            phase("AI_REMEDIATION")
            advice = report["checks"]["remediation"]
            context_error = None
            items = []
            try:
                items = finding_context(report, self.store)
                report["verification_plan"] = verification_plan(items)
                report["verification_plan"]["findings_omitted_by_limit"] = sum(f["kind"] != "STATIC_SECURITY_CANDIDATE" for f in report["findings"]) - len(items)
            except Exception as error:
                context_error = safe_error(error)
                report["verification_plan"] = {"source": "HARNESS_NOT_MODEL", "status": "UNAVAILABLE", "reason": context_error, "cases": []}
            http_items = [item for item in items if item["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY"]
            if items:
                fixed_rows = cve_recommendations(items, report["findings"])
                if fixed_rows:
                    advice.update(recommendations=fixed_rows, contract_version=REMEDIATION_VERSION,
                                  semantic_review_status="NOT_REVIEWED", model_calls=0)
            reason = ("REMEDIATION_DISABLED" if not report["limits"]["include_remediation"] else
                      context_error if context_error else
                      "PREVIOUS_AI_FAILURE_NO_AUTOMATIC_CONTINUATION" if skip_reason and http_items else
                      "NO_CONFIRMED_FINDINGS" if not report["findings"] else
                      "STATIC_RULE_GUIDANCE_ONLY" if not items and context_error is None else
                      "SOURCE_SNAPSHOT_UNAVAILABLE" if snapshot is None else ai_permission(config) if http_items else None)
            if reason:
                advice.update(status="SKIPPED", reason=reason)
            else:
                def sent():
                    report["model_calls_sent"] += 1
                    self._save(report)
                await generate_remediation(config, report, advice, snapshot.verify, sent)
                if advice["status"] == "INCOMPLETE":
                    report["errors"].append({"stage": "remediation", "reason": advice["reason"]})
            phase("COPY_FIX_VERIFICATION")
            if profile and profile.get("run_fix_verification_after_scan") is True:
                from .fix_verification import FixVerifications
                try:
                    fixes = FixVerifications(config)
                    started_fix = await fixes.start(str(root), baseline_report=report)
                    await fixes.tasks[started_fix["job_id"]]
                    fixed = fixes.status(started_fix["job_id"])
                    report["checks"]["fix"] = {"status": "COMPLETED" if fixed.get("verification") == "MATCHES_FROZEN_CHECKS" else "INCOMPLETE",
                        "report_id": started_fix["job_id"], "verification": fixed.get("verification"),
                        "before": fixed.get("before"), "after": fixed.get("after"),
                        "original_snapshot_unchanged": fixed.get("original_snapshot_unchanged"),
                        "workspace_removed": fixed.get("workspace_removed"), "automatic_apply_to_original": False}
                except Exception as error:
                    fail("fix", error)
            else:
                report["checks"]["fix"] = {"status": "SKIPPED", "reason": "COPY_FIX_VERIFICATION_NOT_OPERATOR_ENABLED"}
            report["execution_state"] = "COMPLETED"
        except asyncio.CancelledError:
            if child_id and reviews is not None:
                child = await reviews.cancel(child_id)
                report["cancelled_review_id"] = child_id
                report["cancelled_review_remote_completion"] = child.get("remote_completion")
                report["model_calls_sent"] += int(child.get("request_sent") is True)
            report["execution_state"] = "CANCELLED"
        except Exception as error:
            report["errors"].append({"stage": state["phase"], "reason": safe_error(error)})
            report["execution_state"] = "FAILED"
        finally:
            if server is not None:
                try:
                    await server.stop()
                    report["disposable_server"] = server.metadata
                except Exception as error:
                    unsafe_cleanup = True
                    report["execution_state"] = "FAILED"
                    report["errors"].append({"stage": "SERVER_CLEANUP", "reason": safe_error(error)})
            for stage in report["checks"].values():
                if stage["status"] in {"PENDING", "RUNNING"}:
                    stage.update(status="NOT_RUN", reason="SCAN_STOPPED_BEFORE_COMPLETION")
            report["coverage_status"] = "SCOPED_CHECKS_EXECUTED" if all(s["status"] == "COMPLETED" for s in report["checks"].values()) else "PARTIAL"
            report["finished_at"] = now()
            report["artifact_paths"] = {"json": str(folder / "report.json"), "markdown": str(folder / "report.md")}
            self._save(report)
            state.update(state=report["execution_state"], phase="FINISHED", report_available=True,
                         coverage_status=report["coverage_status"], model_calls_sent=report["model_calls_sent"],
                         updated_at=now(), automatic_resume=False)
            save_json(folder / "status.json", state, replace=True)
            lock = config.results / "control/project-scan.lock"
            if not unsafe_cleanup and lock.exists() and lock.read_text(encoding="utf-8") == identifier:
                lock.unlink()

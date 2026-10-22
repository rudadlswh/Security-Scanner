"""한글 기능 설명: 운영자 승인 수정 묶음을 복사본에만 적용하고 동일한 검사로 전후를 비교한다.

MCP 입력으로 코드나 명령을 받지 않는다. 로컬 프로필의 해시 고정 묶음·빌드 명령만 사용한다.
원본 수정/자동 배포/AI 수정안 자동 채택은 하지 않는다.
"""
from __future__ import annotations
import asyncio
import copy
from dataclasses import replace
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from .disposable import copy_workspace, WindowsJob
from .workspace import ProductError, ProductStore, Snapshot, digest, inside, load_json, now, save_json


def apply_bundle(root: Path, bundle: dict) -> list[dict]:
    if bundle.get("version") != 1 or not isinstance(bundle.get("edits"), list) or not 1 <= len(bundle["edits"]) <= 50:
        raise ProductError("FIX_BUNDLE_FORMAT_INVALID")
    staged, seen = [], set()
    for edit in bundle["edits"]:
        path = inside(root, edit["path"])
        if path in seen or not path.is_file() or path.suffix not in {".java", ".xml", ".gradle", ".kts", ".properties", ".yml", ".yaml"}:
            raise ProductError("FIX_BUNDLE_PATH_INVALID")
        seen.add(path)
        before = path.read_bytes()
        if len(before) > 1_048_576 or digest(before) != edit.get("before_sha256"):
            raise ProductError("FIX_BUNDLE_PREIMAGE_MISMATCH")
        old, new = edit.get("old"), edit.get("new")
        if not isinstance(old, str) or not old or not isinstance(new, str) or len(new.encode()) > 1_048_576:
            raise ProductError("FIX_BUNDLE_REPLACEMENT_INVALID")
        old, new = old.encode("utf-8"), new.encode("utf-8")
        if before.count(old) != 1:
            raise ProductError("FIX_BUNDLE_UNIQUE_MATCH_REQUIRED")
        after = before.replace(old, new, 1)
        staged.append((path, before, after))
    # 모든 편집의 사전 검증 후 쓴다. 호출자가 만든 일회용 복사본에만 적용한다.
    for path, before, after in staged:
        path.write_bytes(after)
    return [{"path": p.relative_to(root).as_posix(), "before_sha256": digest(b), "after_sha256": digest(a)} for p, b, a in staged]


async def run_build(command: dict, workspace: Path, original: Path, folder: Path) -> dict:
    argv = command.get("argv")
    seconds = command.get("timeout_seconds", 120)
    if not isinstance(argv, list) or not argv or len(argv) > 100 or any(not isinstance(x, str) or not x or "\0" in x for x in argv):
        raise ProductError("FIX_BUILD_ARGV_INVALID")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.is_file() or executable.suffix.lower() in {".cmd", ".bat", ".ps1", ".sh"} or executable.resolve().is_relative_to(original):
        raise ProductError("FIX_BUILD_TRUSTED_EXECUTABLE_REQUIRED")
    if type(seconds) is not int or not 1 <= seconds <= 600:
        raise ProductError("FIX_BUILD_TIME_LIMIT_INVALID")
    if any(str(original).lower() in a.lower() or original.as_posix().lower() in a.lower() for a in argv[1:]):
        raise ProductError("FIX_BUILD_ORIGINAL_PATH_FORBIDDEN")
    argv = [a.replace("{project_copy}", str(workspace)) for a in argv]
    env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "JAVA_HOME"}}
    temp = folder / "build-temp"
    temp.mkdir(exist_ok=True)
    env.update(TEMP=str(temp), TMP=str(temp))
    import json
    process = subprocess.Popen([sys.executable, "-m", "localcode_review_mcp.disposable"],
        cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
    job = None
    try:
        if os.name == "nt":
            job = WindowsJob(process)
        process.stdin.write(json.dumps({"command": argv, "cwd": str(workspace), "environment": env}).encode())
        process.stdin.close()
        try:
            code = await asyncio.to_thread(process.wait, timeout=seconds)
        except subprocess.TimeoutExpired:
            raise ProductError("FIX_BUILD_TIMEOUT_NO_RETRY") from None
        if code:
            raise ProductError("FIX_BUILD_FAILED:" + str(code))
        return {"argv_sha256": digest(command["argv"]), "exit_code": code, "timeout_seconds": seconds,
                "execution_boundary": "PROCESS_TREE_GUARD_NOT_OS_SANDBOX"}
    finally:
        if job:
            job.close()
        elif os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        await asyncio.to_thread(process.wait, timeout=10)


class FixVerifications:
    def __init__(self, config):
        self.config, self.store, self.tasks = config, ProductStore(config.results), {}

    async def start(self, project_path, baseline_report=None):
        from .project_scan import folder_config, profile_for
        cfg, project, root = folder_config(self.config, project_path)
        _, profile = profile_for(cfg, root)
        spec = (profile or {}).get("fix_verification", {})
        if spec.get("authorized_copy_only_verification") is not True or spec.get("acknowledge_build_execution") is not True:
            raise ProductError("FIX_VERIFICATION_OPERATOR_PROFILE_REQUIRED")
        if profile.get("disposable_server", {}).get("require_os_isolation") or profile.get("disposable_server", {}).get("isolation_backend") == "docker":
            raise ProductError("FIX_BUILD_ISOLATION_NOT_SUPPORTED_NO_HOST_FALLBACK")
        patch = Path(spec.get("bundle_file", "")).expanduser().resolve(strict=True)
        if patch.is_relative_to(root) or digest(patch.read_bytes()) != spec.get("bundle_sha256"):
            raise ProductError("FIX_BUNDLE_OPERATOR_HASH_REQUIRED_OUTSIDE_PROJECT")
        bundle = load_json(patch)
        commands = spec.get("build_commands", [])
        if not isinstance(commands, list) or not 1 <= len(commands) <= 5:
            raise ProductError("FIX_BUILD_COMMANDS_REQUIRED")
        control = cfg.results / "control"
        control.mkdir(parents=True, exist_ok=True)
        lock = control / "fix-verification.lock"
        with lock.open("x", encoding="utf-8") as stream:
            identifier = self.store.create("fix", {"kind": "fix-verification", "project_id": project})
            stream.write(identifier)
        report = {"report_id": identifier, "kind": "fix-verification", "state": "QUEUED", "created_at": now(),
                  "owner_pid": os.getpid(), "source_modified": None, "automatic_apply_to_original": False,
                  "model_calls": 0, "external_cve_queries": 0, "bundle_sha256": spec["bundle_sha256"],
                  "semantic_status": "NOT_REVIEWED", "os_security_sandbox": False}
        save_json(self.store.folder(identifier) / "report.json", report)
        self.tasks[identifier] = asyncio.create_task(self._run(cfg, project, root, profile, spec, bundle, commands, report, lock, baseline_report))
        return {"job_id": identifier, "state": "QUEUED", "original_modified": False}

    def status(self, identifier):
        report = self.store.read(identifier)
        if report.get("kind") != "fix-verification":
            raise ProductError("NOT_A_FIX_VERIFICATION")
        from .reviews import process_alive
        if report["state"] in {"QUEUED", "RUNNING"} and identifier not in self.tasks and not process_alive(report.get("owner_pid")):
            report.update(state="INTERRUPTED", reason="PROCESS_EXITED_NO_AUTOMATIC_RESUME")
            save_json(self.store.folder(identifier) / "report.json", report, replace=True)
        return report

    async def cancel(self, identifier):
        report = self.status(identifier)
        task = self.tasks.get(identifier)
        if report["state"] not in {"QUEUED", "RUNNING"}:
            return report
        if task is None:
            raise ProductError("FIX_VERIFICATION_NOT_OWNED_BY_THIS_SERVER")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # 시작 전 취소는 _run의 finally에 도달하지 않으므로 상태와 자기 잠금만 정리한다.
        current = self.store.read(identifier)
        if current["state"] == "QUEUED":
            current.update(state="CANCELLED", verification="NOT_RUN", source_modified=False, workspace_removed=True, finished_at=now())
            save_json(self.store.folder(identifier) / "report.json", current, replace=True)
            lock = self.config.results / "control/fix-verification.lock"
            if lock.exists() and lock.read_text(encoding="utf-8") == identifier:
                lock.unlink()
        return self.status(identifier)

    async def _run(self, cfg, project, root, profile, spec, bundle, commands, report, lock, baseline_report):
        from .project_scan import ProjectScans
        folder = self.store.folder(report["report_id"]).resolve()
        workspace = folder / "fix-workspace"
        snapshot = None
        async def scan(current, current_root):
            jobs = ProjectScans(current)
            started = await jobs.start(str(current_root), max_ai_endpoints=0, include_remediation=False)
            await jobs.tasks[started["job_id"]]
            child = jobs.report(started["job_id"])
            if child["execution_state"] != "COMPLETED" or child["checks"]["dynamic"]["status"] != "COMPLETED" or child["checks"]["sast"]["status"] != "COMPLETED_FOR_RULESET":
                raise ProductError("FIX_COMPARISON_SCAN_INCOMPLETE")
            return child
        safe_cleanup = True
        try:
            snapshot = Snapshot.read(root, cfg.projects[project].get("commit"))
            report["state"] = "RUNNING"
            save_json(folder / "report.json", report, replace=True)
            # 네트워크/생성 예산을 사용하지 않는다. 원본은 읽기·복사만 한다.
            if baseline_report is None:
                baseline_profile = copy.deepcopy(profile)
                baseline_profile.pop("fix_verification", None)
                baseline_profile.pop("run_fix_verification_after_scan", None)
                baseline_cfg = replace(cfg, results=folder / "before", allow_osv_network=False, model={}, scan_profiles={"baseline": baseline_profile})
                baseline = await scan(baseline_cfg, root)
                report["before_report"] = str(baseline_cfg.results / baseline["report_id"] / "report.json")
            else:
                baseline = copy.deepcopy(baseline_report)
                if (baseline.get("project_id") != project or baseline.get("project_path") != str(root)
                        or baseline.get("source_snapshot_unchanged") is not True
                        or baseline.get("checks", {}).get("dynamic", {}).get("status") != "COMPLETED"
                        or baseline.get("checks", {}).get("sast", {}).get("status") != "COMPLETED_FOR_RULESET"):
                    raise ProductError("FIX_PARENT_BASELINE_NOT_COMPLETE")
                save_json(folder / "parent-baseline.json", baseline)
                report["before_report"] = str(folder / "parent-baseline.json")
                report["baseline_reused_from_parent_scan"] = True
            def counts(child):
                return {"static_rules": sorted(f["rule_id"] for f in child["findings"] if f["kind"] == "STATIC_SECURITY_CANDIDATE"),
                        "dynamic_discrepancies": sum(f["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY" for f in child["findings"])}
            report["before"] = counts(baseline)
            if report["before"] != spec.get("expected_before"):
                raise ProductError("FIX_BASELINE_EXPECTATION_MISMATCH_NO_PATCH_APPLIED")
            copying = asyncio.create_task(asyncio.to_thread(copy_workspace, root, workspace))
            try:
                report["copy"] = await asyncio.shield(copying)
            except asyncio.CancelledError:
                await copying
                raise
            report["edits"] = apply_bundle(workspace, bundle)
            report["builds"] = []
            for command in commands:
                report["builds"].append(await run_build(command, workspace, root, folder))
            child_profile = copy.deepcopy(profile)
            child_profile.pop("fix_verification", None)
            child_profile.pop("run_fix_verification_after_scan", None)
            child_profile["project_root"] = str(workspace)
            child_profile["disposable_server"]["project_root"] = str(workspace)
            project_settings = dict(cfg.projects[project])
            project_settings.update(root=str(workspace))
            project_settings.pop("commit", None)
            external = project_settings.get("dependency_inventory")
            if external:
                external_path = Path(external).resolve()
                if not external_path.is_relative_to(root):
                    raise ProductError("FIX_INVENTORY_MUST_BE_REBUILT_IN_COPY")
                project_settings["dependency_inventory"] = str(workspace / external_path.relative_to(root))
            fixed_cfg = replace(cfg, projects={project: project_settings}, scan_profiles={"fix": child_profile},
                                results=folder / "after", allow_osv_network=False, model={})
            after = await scan(fixed_cfg, workspace)
            report["after_report"] = str(fixed_cfg.results / after["report_id"] / "report.json")
            report["after"] = counts(after)
            report["verification"] = "MATCHES_FROZEN_CHECKS" if report["after"] == spec.get("expected_after") else "NEEDS_REVISION"
            report.update(state="COMPLETED", safety_guarantee=False,
                          limits=["Only the frozen static rules and configured HTTP cases were compared.",
                                  "Build commands have operator process privileges; this workflow is not an OS sandbox.",
                                  "A passing copy is not approval to apply to the original or deploy."])
        except asyncio.CancelledError:
            report.update(state="CANCELLED", verification="INCOMPLETE")
            raise
        except Exception as error:
            report.update(state="FAILED", verification="INCOMPLETE", reason=str(error) if isinstance(error, ProductError) else type(error).__name__)
        finally:
            try:
                if snapshot is not None:
                    snapshot.verify()
                    report["original_snapshot_unchanged"] = True
                    report["source_modified"] = False
                for target in (workspace, folder / "build-temp"):
                    if target.exists():
                        if target.is_symlink() or (hasattr(target, "is_junction") and target.is_junction()) or target.resolve().parent != folder:
                            raise ProductError("FIX_CLEANUP_PATH_INVALID")
                        shutil.rmtree(target.resolve())
                report["workspace_removed"] = True
            except Exception as error:
                safe_cleanup = False
                report.update(state="FAILED", cleanup_error=str(error) if isinstance(error, ProductError) else type(error).__name__)
                if report.get("original_snapshot_unchanged") is not True:
                    report["source_modified"] = "UNKNOWN_OR_CHANGED"
            report["finished_at"] = now()
            save_json(folder / "report.json", report, replace=True)
            if safe_cleanup and lock.exists() and lock.read_text(encoding="utf-8") == report["report_id"]:
                lock.unlink()

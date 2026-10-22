"""한글 기능 설명: 실제 프로젝트 조사·근거 수집·로컬 관찰·CVE·HTTP 검사를 MCP에 등록한다."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field, StrictBool

from .collector import collect, inventory
from .dependencies import dependency_inventory, scan_cves
from .http_checks import run_http_checks
from .reviews import ReviewJobs
from .project_scan import ProjectScans
from .fix_verification import FixVerifications
from .remediation_compact import VERSION as REMEDIATION_VERSION
from .workspace import ProductConfig, ProductError, ProductStore, REPO, load_json


def register_product_tools(server: FastMCP, config_path: Path, jdk: Path | None):
    jobs: ReviewJobs | None = None
    scans: ProjectScans | None = None
    fixes: FixVerifications | None = None
    http_running = False
    readonly = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    local_write = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)

    def config():
        return ProductConfig.read(config_path, jdk)

    def review_jobs():
        nonlocal jobs
        current = config()
        if jobs is None:
            jobs = ReviewJobs(current)
        elif all(task.done() for task in jobs.tasks.values()):
            jobs.config = current
            jobs.store = ProductStore(current.results)
        return jobs

    def project_scans():
        nonlocal scans
        current = config()
        if scans is None:
            scans = ProjectScans(current)
        elif all(task.done() for task in scans.tasks.values()):
            scans.config = current
            scans.store = ProductStore(current.results)
        return scans

    def fix_jobs():
        nonlocal fixes
        current = config()
        if fixes is None:
            fixes = FixVerifications(current)
        elif all(task.done() for task in fixes.tasks.values()):
            fixes.config = current
            fixes.store = ProductStore(current.results)
        return fixes

    async def guarded(function, *args):
        try:
            if asyncio.iscoroutinefunction(function):
                return await function(*args)
            return await asyncio.to_thread(function, *args)
        except ProductError as error:
            raise ToolError(str(error)) from None
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ToolError("PRODUCT_OPERATION_INCOMPLETE:" + type(error).__name__) from None

    @server.tool(annotations=readonly)
    def get_product_capabilities() -> dict:
        """제품 확장 설정·준비 상태 조회. 모델/HTTP/CVE 요청을 보내지 않습니다."""
        cfg = config()
        return {"implementation": "product-workflow/3", "validation_status": "READ_LOCAL_VERIFICATION_RECEIPTS; THIS_CALL_RUNS_NO_TESTS",
                "projects": list(cfg.projects), "http_targets": list(cfg.http_targets), "jdk_configured": cfg.jdk is not None,
                "java_bridge_built": (REPO / "build/product/classes/dev/localcodereview/ProductBridge.class").is_file(),
                "configuration_file_present": config_path.is_file(), "osv_network_enabled": cfg.allow_osv_network,
                "model_authorization_present": (cfg.results / "control/model-authorization.json").is_file(),
                "scope_confirmation": "LOCAL_OPERATOR_NOT_MODEL", "default_raw_logs": "OFF", "checks_executed_by_this_call": 0,
                "folder_scan_tool": "scan_project", "supported_source_languages": ["Java/Spring supported subset"],
                "disposable_server_execution": "EXPLICIT_LOCAL_SCAN_PROFILE_ONLY",
                "ai_remediation": "HTTP_FOCUS_SELECTION_ONLY; NO_GENERATED_FREE_TEXT; ONE_EXISTING_AUTHORIZED_CALL_RESERVED; UNREVIEWED_NO_AUTO_APPLY",
                "cve_remediation": "HARNESS_EXACT_ADVISORY_CANDIDATES_AND_CHECKLIST; ZERO_MODEL_CALLS; COMPATIBILITY_UNVERIFIED",
                "remediation_contract": REMEDIATION_VERSION, "http_evidence_contract": "http-expectations/2",
                "verification_conditions": "HARNESS_NOT_MODEL",
                "source_security_rules": ["SQL_HTTP_INPUT", "HTML_HTTP_OUTPUT", "RESTTEMPLATE_HTTP_DESTINATION"],
                "source_security_limits": "INTRAPROCEDURAL_AST_CANDIDATES_NOT_COMPLETE_SECURITY_PROOF",
                "resolved_inventory_binding": "SOURCE_AND_APPLICATION_AND_RUNTIME_JAR_HASHES",
                "strong_isolation": "OPT_IN_LOCAL_LINUX_DOCKER_DIGEST_PINNED; ENGINE_UNAVAILABLE_FAILS_CLOSED; LIVE_VERIFICATION_REQUIRED",
                "copy_fix_verification": "OPERATOR_HASH_PINNED_BUNDLE_AND_BUILD_PROFILE; ORIGINAL_NEVER_MODIFIED"}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False))
    async def verify_project_fix(project_path: str) -> dict:
        """운영자 fix_verification 프로필의 수정 묶음을 복사본에 적용하고 빌드·동일 SAST/HTTP 전후 대조를 시작합니다.
        코드/명령/수정 승인을 MCP 입력에서 받지 않습니다. 원본 수정·배포 없음. 실제 빌드 권한은 로컬 프로필에서 사전 승인해야 합니다.
        get_fix_verification_status로 완료·정리 상태를 조회합니다. 모델/외부 CVE 호출 없음.
        """
        return await guarded(fix_jobs().start, project_path)

    @server.tool(annotations=readonly)
    def get_fix_verification_status(job_id: str) -> dict:
        """복사본 수정 전후 검증 결과·빌드·원본 불변·정리 상태를 조회합니다. 자동 재시작 없음."""
        try:
            return fix_jobs().status(job_id)
        except (OSError, ValueError, KeyError):
            raise ToolError("FIX_VERIFICATION_UNAVAILABLE") from None

    @server.tool(annotations=local_write)
    async def cancel_fix_verification(job_id: str) -> dict:
        """이 서버가 시작한 복사본 검증을 취소하고 빌드 프로세스·서버·복사본 정리를 기다립니다. 자동 재개 없음."""
        return await guarded(fix_jobs().cancel, job_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    async def scan_project(project_path: str,
                           max_endpoints: Annotated[int, Field(strict=True, ge=1, le=500)] = 100,
                           max_ai_endpoints: Annotated[int, Field(strict=True, ge=0, le=20)] = 20,
                           include_remediation: StrictBool = True) -> dict:
        """절대 폴더 경로 하나로 조사→승인된 AI/CVE→등록된 일회용 서버/HTTP→통합 보고서를 시작합니다.
        기존 로컬 예산·OSV 허용·운영자 scan_profiles만 사용합니다. 미지원/미실행은 보고하며 자동 승인/원본 빌드는 하지 않습니다.
        반환한 job_id를 get_project_scan_status/read_project_scan_report에 전달합니다. 반복 호출은 새 검사입니다.
        include_remediation=true면 HTTP 점검 우선순위에 기존 승인1회를 사용합니다. CVE 절차는 모델 호출 없이 표시합니다.
        max_ai_endpoints는 소스 관찰 상한입니다. HTTP AI 예산 없음은 미실행이며 하네스 검증 목록은 남습니다. 자동 수정 없음.
        """
        return await guarded(project_scans().start, project_path, max_endpoints, max_ai_endpoints, include_remediation)

    @server.tool(annotations=readonly)
    def get_project_scan_status(job_id: str) -> dict:
        """통합 작업 진행 단계와 완료 상태를 조회합니다. 중단된 작업을 자동 재개하지 않습니다."""
        try:
            return project_scans().status(job_id)
        except (ValueError, OSError, KeyError):
            raise ToolError("PROJECT_SCAN_STATUS_UNAVAILABLE") from None

    @server.tool(annotations=readonly)
    def read_project_scan_report(job_id: str) -> dict:
        """통합 JSON 보고서와 로컬 Markdown 경로를 조회합니다. 소스/진단 원문/실행 환경변수는 반환하지 않습니다."""
        try:
            return project_scans().report(job_id)
        except (ValueError, OSError, KeyError):
            raise ToolError("PROJECT_SCAN_REPORT_UNAVAILABLE") from None

    @server.tool(annotations=local_write)
    async def cancel_project_scan(job_id: str) -> dict:
        """통합 검사를 중단하고 이번 작업이 시작한 일회용 서버 트리를 종료합니다. 전송된 생성 예산은 환불하지 않습니다."""
        return await guarded(project_scans().cancel, job_id)

    @server.tool(annotations=readonly)
    def list_projects() -> dict:
        """운영자가 로컬 설정에 등록한 프로젝트 ID와 커밋 고정 여부를 조회합니다."""
        cfg = config()
        return {"projects": [{"project_id": key, "commit_pinned": bool(value.get("commit"))} for key, value in cfg.projects.items()], "configuration": str(config_path)}

    @server.tool(annotations=readonly)
    async def inspect_project(project_id: str, offset: Annotated[int, Field(strict=True, ge=0)] = 0,
                              limit: Annotated[int, Field(strict=True, ge=1, le=100)] = 50) -> dict:
        """등록된 프로젝트를 읽기 전용으로 조사합니다. 소스 본문·빌드 실행·모델 호출 없음."""
        def inspect():
            _, _, data = inventory(config(), project_id)
            return {k: v for k, v in data.items() if k not in {"snapshot", "endpoints"}} | {
                "identity": data["snapshot"]["identity"], "file_count": len(data["snapshot"]["files"]),
                "excluded_count": len(data["snapshot"]["excluded"]), "endpoint_count": len(data["endpoints"]),
                "endpoints": data["endpoints"][offset:offset + limit], "offset": offset,
                "next_offset": offset + limit if offset + limit < len(data["endpoints"]) else None}
        return await guarded(inspect)

    @server.tool(annotations=local_write)
    async def collect_endpoint_evidence(project_id: str, endpoint_id: str) -> dict:
        """AST로 근거 메타데이터를 수집·저장합니다. 제한된 선언 연결이며 소스 본문은 반환하지 않습니다."""
        result = await guarded(collect, config(), project_id, endpoint_id)
        return {k: v for k, v in result.items() if k not in {"snapshot", "ledger"}}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    async def review_endpoint(project_id: str, collection_id: str, policy: str = "NOT_PROVIDED") -> dict:
        """로컬에서 승인한 예산으로 Ollama 관찰 1회를 시작합니다. 작업 ID로 상태 조회. 정책은 모델 입력에서 제외."""
        return await guarded(review_jobs().start, project_id, collection_id, policy)

    @server.tool(annotations=readonly)
    def get_review_status(job_id: str) -> dict:
        """관찰 작업 상태와 원격 완료 여부를 조회합니다. 재시작 후 자동 재전송하지 않습니다."""
        try:
            return review_jobs().status(job_id)
        except (ValueError, OSError, KeyError):
            raise ToolError("REVIEW_STATUS_UNAVAILABLE") from None

    @server.tool(annotations=local_write)
    async def cancel_review(job_id: str) -> dict:
        """관찰을 취소합니다. 전송 후에는 원격 완료 불명일 수 있어 로컬 상태 확인 전 후속 호출을 차단합니다."""
        return await guarded(review_jobs().cancel, job_id)

    @server.tool(annotations=readonly)
    def read_review_report(report_id: str) -> dict:
        """제품 조사/관찰/CVE/HTTP 결과 ID를 조회합니다. 진단 원문·토큰·임의 파일은 반환하지 않습니다."""
        try:
            result = ProductStore(config().results).read(report_id)
            if result.get("kind") not in {"endpoint-review", "dependency-cve", "http-security", "project-security-scan", "security-remediation", "source-security", "fix-verification"}:
                raise ToolError("UNSUPPORTED_PRODUCT_REPORT_KIND")
            return result
        except (ValueError, OSError, KeyError):
            raise ToolError("PRODUCT_REPORT_UNAVAILABLE") from None

    @server.tool(annotations=readonly)
    def list_product_reports(limit: Annotated[int, Field(strict=True, ge=1, le=100)] = 20) -> dict:
        cfg = config()
        rows = []
        if cfg.results.exists():
            directories = sorted(cfg.results.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            for folder in directories:
                if not folder.is_dir() or folder.is_symlink() or folder.name in {"control", "osv-cache"}:
                    continue
                try:
                    metadata = ProductStore(cfg.results).read(folder.name, "metadata.json")
                    rows.append({key: metadata.get(key) for key in ("id", "kind", "project_id", "target_id", "created_at")})
                except (ValueError, OSError):
                    continue
                if len(rows) >= limit:
                    break
        return {"reports": rows}

    @server.tool(annotations=readonly)
    async def inspect_dependencies(project_id: str) -> dict:
        """Maven/Gradle/잠금/CycloneDX·해석된 목록을 읽습니다. 대상 빌드나 네트워크 조회는 하지 않습니다."""
        return await guarded(dependency_inventory, config(), project_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    async def scan_dependency_cves(project_id: str, online: StrictBool = False) -> dict:
        """기본은 OSV 캐시 조회. online=true와 로컬 허용 설정일 때만 패키지 이름·버전을 OSV에 전송합니다."""
        return await guarded(scan_cves, config(), project_id, online)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
    async def run_http_security_check(target_id: str) -> dict:
        """명시 등록·허용된 폐기 가능 루프백 테스트 환경의 HTTP 변경 요청을 실행합니다. 자동 재시도 없음."""
        nonlocal http_running
        if http_running:
            raise ToolError("HTTP_CHECK_ALREADY_RUNNING")
        http_running = True
        try:
            return await guarded(run_http_checks, config(), target_id)
        finally:
            http_running = False

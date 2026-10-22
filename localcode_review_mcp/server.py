# [한글 기능 설명]
# 기능: 기존 예제 검사와 보고서/완료 실험 요약을 MCP 도구로 제공한다.
# 시작점/입력: 운영자가 서버 시작 때 고정한 예제/JDK 경로와 도구별 제한된 인자.
# 이어지는 기능: FastMCP → ReviewService → 기존 검사 스크립트 → 구조화 결과.
# 주의: 예제 도구와 폴더 통합 검사를 구분한다. MCP에서 명령을 받거나 실행 예산을 만들지 않는다.
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Annotated, Any
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field, StrictBool

from .prompts import REPORT_ID, register_prompts
from .product_tools import register_product_tools

REPO = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 1_048_576


def read_json(path: Path) -> dict[str, Any]:
    """파일 크기와 JSON 루트 형식을 검사하며 소스/임의 텍스트는 반환하지 않는다."""
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ToolError("JSON result exceeds the size limit")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ToolError("Result must be a JSON object")
    return result


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


@dataclass(frozen=True)
class Settings:
    sample_target: Path
    jdk: Path | None
    reports_dir: Path = REPO / "results/mcp-security"
    check_timeout_seconds: float = 180
    product_config: Path = REPO / "localcode-review.json"


class ReviewService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._running = False

    def capabilities(self) -> dict[str, Any]:
        """클라이언트가 도구의 실제 범위를 먼저 확인하게 한다."""
        return {
            "server": "LocalCode Review", "version": "0.1.0", "transport": "stdio",
            "capabilities_scope": "PINNED_SAMPLE_TOOLS; use get_product_capabilities for registered-project workflows",
            "mcp_sdk_version": importlib.metadata.version("mcp"),
            "sample_target": str(self.settings.sample_target),
            "jdk_configured": self.settings.jdk is not None,
            "available": ["pinned Java sample execution", "optional April 2026 Oracle JDK advisory match",
                          "MCP-created report listing/reading", "completed synthetic C summary"],
            "unavailable": ["generic project scan", "HTTP DAST", "comprehensive dependency CVE scan",
                            "arbitrary file/command execution", "new Ollama evaluation calls"],
            "model_calls": 0, "runtime_CVE_network_default": False,
            "project_workflow_tool": "scan_project",
            "warning": "A tool call or passing tests does not establish code safety.",
        }

    def _report_path(self, report_id: str) -> Path:
        """보고서 ID만 받고 경로 지정이나 링크를 통한 범위 밖 참조를 거부한다."""
        if not REPORT_ID.fullmatch(report_id):
            raise ToolError("Invalid report_id; use list_security_reports")
        base = self.settings.reports_dir.resolve()
        directory = base / report_id
        path = directory / "artifacts/report.json"
        # 다른 실행으로의 링크도 거부한다. 해당 실행이 저장한 JSON만 공개한다.
        if directory.is_symlink() or path.parent.is_symlink() or path.is_symlink():
            raise ToolError("Linked report paths are not allowed")
        if not path.resolve().is_relative_to(base):
            raise ToolError("Report path is outside the configured report directory")
        return path

    def read_report(self, report_id: str) -> dict[str, Any]:
        path = self._report_path(report_id)
        try:
            report = read_json(path)
        except (OSError, ValueError):
            raise ToolError("Report is missing or invalid") from None
        if report.get("tool") != "LocalCode Review fixture security adapter/1":
            raise ToolError("Unsupported report type")
        if report.get("target") != str(self.settings.sample_target.resolve()):
            raise ToolError("Report target differs from the configured sample")
        return {"report_id": report_id, "report": report}

    def list_reports(self, limit: int = 20) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        base = self.settings.reports_dir
        if not base.exists():
            return {"reports": [], "invalid_or_incomplete": [], "limit": limit}
        rows, invalid = [], []
        for directory in sorted(base.iterdir(), key=lambda p: p.name, reverse=True):
            if not REPORT_ID.fullmatch(directory.name):
                continue
            try:
                report = self.read_report(directory.name)["report"]
                rows.append({"report_id": directory.name, "recorded_at": report.get("recorded_at"),
                             "finding_count": report.get("dynamic", {}).get("finding_count"),
                             "runtime_CVE_status": report.get("runtime_CVE", {}).get("status")})
            except ToolError:
                invalid.append(directory.name)
            if len(rows) + len(invalid) >= limit:
                break
        return {"reports": rows, "invalid_or_incomplete": invalid, "limit": limit}

    def synthetic_summary(self) -> dict[str, Any]:
        """완료된 합성 C 집계만 읽는다. 실제 소스/진단/미채점 메모리는 노출하지 않는다."""
        path = REPO / "results/20261019-new-synthetic-c-001/summary.json"
        try:
            summary = read_json(path)
        except (OSError, ValueError):
            raise ToolError("Completed synthetic summary is unavailable") from None
        keys = ("status", "normal_completions", "not_executed", "reviewed_label_counts",
                "unreviewed_normal_completions", "independent_human_reviews", "C_requests_sent")
        return {"study": "new-synthetic-c/execution-1", "historical_result_not_reexecuted": True,
                "summary": {key: summary.get(key) for key in keys},
                "cases": [{"observation_id": row.get("observation_id"), "case": row.get("case"),
                           "classification": row.get("primary_classification"),
                           "explanation_status": row.get("explanation_status"),
                           "citation_status": row.get("citation_status")}
                          for row in summary.get("case_details", [])],
                "summary_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "model_calls": 0, "limits": "Four synthetic cases, once each, AI-only labels; no generalization claim."}

    async def _stop_child(self, process: asyncio.subprocess.Process) -> None:
        """중단/시간 초과 시 이번 도구가 띄운 자식 프로세스 트리만 종료한다."""
        if process.returncode is not None:
            return
        if os.name == "nt":
            killer = await asyncio.create_subprocess_exec(
                "taskkill", "/PID", str(process.pid), "/T", "/F",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            await killer.wait()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await process.wait()

    async def run_check(self, check_runtime_cves: bool = False) -> dict[str, Any]:
        """한 번에 한 검사만 실행하고 결과 폴더를 새 ID로 분리한다."""
        if not isinstance(check_runtime_cves, bool):
            raise ToolError("check_runtime_cves must be boolean")
        if self._running:
            raise ToolError("A sample check is already running; automatic queuing/retry is disabled")
        if self.settings.jdk is None:
            raise ToolError("Configure --jdk before running a check")
        self._running = True
        process = None
        folder = None
        try:
            report_id = "run-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
            folder = self.settings.reports_dir / report_id
            folder.mkdir(parents=True, exist_ok=False)
            write_new_json(folder / "request.json", {"report_id": report_id,
                           "check_runtime_cves": check_runtime_cves, "model_calls": 0})
            command = [sys.executable, "-u", str(REPO / "scripts/check_review_sample_security.py"),
                       "--target", str(self.settings.sample_target), "--jdk", str(self.settings.jdk),
                       "--output", str(folder / "artifacts")]
            if not check_runtime_cves:
                command.append("--skip-runtime-cves")
            options = ({"creationflags": subprocess.CREATE_NO_WINDOW}
                       if os.name == "nt" else {"start_new_session": True})
            # 검사 자식은 MCP 프로토콜 stdin을 상속하면 안 된다. 로그도 프로토콜 stdout과 분리한다.
            with (folder / "child.stdout.txt").open("xb") as stdout, (folder / "child.stderr.txt").open("xb") as stderr:
                async with asyncio.timeout(self.settings.check_timeout_seconds):
                    process = await asyncio.create_subprocess_exec(
                        *command, cwd=REPO, stdin=asyncio.subprocess.DEVNULL,
                        stdout=stdout, stderr=stderr, **options)
                    await process.wait()
            write_new_json(folder / "completion.json", {"status": "completed" if process.returncode == 0 else "incomplete",
                           "exit_code": process.returncode, "report_id": report_id})
            result = self.read_report(report_id)
            result["check_completed"] = process.returncode == 0
            if process.returncode != 0:
                raise ToolError(f"Sample check incomplete; report_id={report_id}. Inspect the saved report locally.")
            return result
        except (asyncio.CancelledError, TimeoutError) as interrupted:
            if process is not None:
                await self._stop_child(process)
            if folder is not None:
                write_new_json(folder / "completion.json", {"status": "interrupted_or_timed_out", "automatic_retry": False})
            if isinstance(interrupted, TimeoutError):
                raise ToolError("Sample check timed out; inspect the saved run locally. No automatic retry.") from None
            raise
        except (OSError, ValueError):
            raise ToolError("Local check could not run; check the configured sample/JDK and saved run logs") from None
        finally:
            self._running = False


def create_server(settings: Settings) -> FastMCP:
    """도구 정의·인자 스키마·프로토콜 처리는 공식 SDK에 맡긴다."""
    service = ReviewService(settings)
    server = FastMCP("LocalCode Review", instructions=(
        "Java/Spring 폴더의 scan_project 통합 검사와 개별 조사·관찰·의존성 CVE·루프백 HTTP 도구입니다. "
        "scan_project는 폴더 경로 하나를 받고 기존 로컬 승인 범위에서 실행하며 미지원/미실행을 통합 보고서에 기록합니다. "
        "HTTP 근거의 점검 영역 선택에 기존 승인1회를 사용하고 설명·수정 절차·CVE 후보는 하네스가 표시합니다. AI 자유문 생성·자동 수정은 없습니다. include_remediation=false로 AI 선택을 생략합니다. "
        "프로젝트 명령은 MCP 인자로 받지 않으며 명시된 scan_profiles의 일회용 복사본 실행만 허용합니다. "
        "예제 도구는 Ollama를 호출하지 않습니다. review_endpoint와 scan_project의 AI 단계는 별도 로컬 생성 예산을 사용합니다. "
        "실제 소스 본문과 진단 원문은 MCP로 반환하지 마세요. 관찰/규칙/설명 검증을 구분하세요. "
        "실행 완료와 코드 안전성은 다릅니다. 검증 범위는 로컬 영수증과 보고서를 확인하세요."), log_level="WARNING")
    readonly = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=readonly)
    def get_capabilities() -> dict[str, Any]:
        """구현된 기능·예제 경로·미지원 기능과 모델 호출0회 계약을 조회합니다."""
        return service.capabilities()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    async def run_sample_security_check(check_runtime_cves: StrictBool = False) -> dict[str, Any]:
        """고정 Java 예제를 새 폴더에서 실행합니다. true일 때만 공개 Oracle 공지를 조회합니다. 원본 불변·Ollama 호출 없음."""
        return await service.run_check(check_runtime_cves)

    @server.tool(annotations=readonly)
    def list_security_reports(limit: Annotated[int, Field(strict=True, ge=1, le=100)] = 20) -> dict[str, Any]:
        """이 MCP가 생성한 검사 보고서 목록을 조회합니다. 실제 소스 진단 폴더는 열지 않습니다."""
        return service.list_reports(limit)

    @server.tool(annotations=readonly)
    def read_security_report(report_id: str) -> dict[str, Any]:
        """목록에서 받은 report_id의 구조화 보고서를 읽습니다. 파일 경로나 원문 로그는 인자로 받지 않습니다."""
        return service.read_report(report_id)

    @server.tool(annotations=readonly)
    def get_synthetic_evaluation_summary() -> dict[str, Any]:
        """이미 끝난 합성 C4건의 집계와 설명/인용 축을 조회합니다. 실험을 재실행하지 않습니다."""
        return service.synthetic_summary()

    register_prompts(server)
    register_product_tools(server, settings.product_config, settings.jdk)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="LocalCode Review MCP server (local STDIO only)")
    parser.add_argument("--sample-target", type=Path, default=REPO.parent / "code review test")
    parser.add_argument("--jdk", type=Path, default=Path(os.environ["JAVA_HOME"]) if os.environ.get("JAVA_HOME") else None)
    parser.add_argument("--config", type=Path, default=REPO / "localcode-review.json")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    settings = Settings(sample_target=args.sample_target.resolve(), jdk=args.jdk.resolve() if args.jdk else None,
                        product_config=args.config.resolve())
    create_server(settings).run(transport="stdio")

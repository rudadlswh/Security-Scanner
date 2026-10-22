# [한글 기능 설명]
# 기능: 실제 STDIO 서버와 공식 SDK 클라이언트로 연결·도구 호출을 검증한다.
# 시작점/입력: Python 실행, 예제/JDK 경로, 새 영수증 경로.
# 이어지는 기능: initialize → tools/list → 검사/조회 → JSON 검증 영수증.
# 주의: 실제 예제 실행은 하지만 Ollama 생성이나 과거 실험 재실행은 하지 않는다.
import argparse
import asyncio
import datetime as dt
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO = Path(__file__).resolve().parents[1]
TOOLS = {"get_capabilities", "run_sample_security_check", "list_security_reports",
         "read_security_report", "get_synthetic_evaluation_summary",
         "get_product_capabilities", "list_projects", "inspect_project", "collect_endpoint_evidence", "review_endpoint",
         "get_review_status", "cancel_review", "read_review_report", "list_product_reports", "inspect_dependencies",
         "scan_dependency_cves", "run_http_security_check", "scan_project", "get_project_scan_status",
         "read_project_scan_report", "cancel_project_scan", "verify_project_fix", "get_fix_verification_status", "cancel_fix_verification"}


async def smoke(target: Path, jdk: Path, runtime_cves: bool) -> dict:
    params = StdioServerParameters(command=sys.executable,
        args=["-u", str(REPO / "mcp_server.py"), "--sample-target", str(target), "--jdk", str(jdk)],
        cwd=str(REPO.parent), encoding="utf-8")
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=180)) as session:
            initialized = await session.initialize()
            print("MCP initialized", file=sys.stderr, flush=True)
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == TOOLS
            capabilities = await session.call_tool("get_capabilities", {})
            assert not capabilities.isError and capabilities.structuredContent["model_calls"] == 0
            rejected = await session.call_tool("read_security_report", {"report_id": "../kbo-observation-v3/run-001"})
            assert rejected.isError
            wrong_type = await session.call_tool("run_sample_security_check", {"check_runtime_cves": "false"})
            assert wrong_type.isError
            historical = await session.call_tool("get_synthetic_evaluation_summary", {})
            assert not historical.isError and historical.structuredContent["historical_result_not_reexecuted"]
            print("Tool discovery, read-only calls and rejection checks passed; running pinned sample", file=sys.stderr, flush=True)
            result = await session.call_tool("run_sample_security_check", {"check_runtime_cves": runtime_cves})
            assert not result.isError, result.content
            data = result.structuredContent
            assert data["check_completed"] and data["report"]["target_unchanged"]
            assert data["report"]["model_calls"] == 0
            assert data["report"]["dynamic"]["finding_count"] == 1
            expected = "VENDOR_ADVISORY_CHECKED" if runtime_cves else "SKIPPED_BY_REQUEST"
            assert data["report"]["runtime_CVE"]["status"] == expected
            report_id = data["report_id"]
            listing = await session.call_tool("list_security_reports", {"limit": 100})
            assert not listing.isError and report_id in {row["report_id"] for row in listing.structuredContent["reports"]}
            fetched = await session.call_tool("read_security_report", {"report_id": report_id})
            assert not fetched.isError and fetched.structuredContent["report"] == data["report"]
            return {"status": "passed", "transport": "stdio", "protocol_version": initialized.protocolVersion,
                    "server_info": initialized.serverInfo.model_dump(), "tools": sorted(TOOLS),
                    "real_sample_executed": True, "target_unchanged": True,
                    "dynamic_findings": 1, "report_id": report_id, "runtime_CVE_status": expected,
                    "runtime_version_matches": len(data["report"]["runtime_CVE"].get("matches", [])),
                    "traversal_rejected": True, "wrong_boolean_rejected": True,
                    "all_five_tools_called": True, "model_calls": 0,
                    "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--runtime-cves", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(smoke(args.target.resolve(), args.jdk.resolve(), args.runtime_cves))
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)
        file.write("\n")
    print(json.dumps(result))

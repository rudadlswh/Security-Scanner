"""사용자 실행용 STDIO 제품 계약 점검. 실제 소스·Ollama·OSV·HTTP 대상으로 요청하지 않는다."""
import asyncio
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from smoke_mcp import TOOLS

REPO = Path(__file__).resolve().parents[1]


async def smoke():
    with tempfile.TemporaryDirectory() as temporary:
        config = Path(temporary) / "config.json"
        config.write_text(json.dumps({"version": 1, "projects": {}, "http_targets": {}, "results_dir": str(Path(temporary) / "results")}), encoding="utf-8")
        parameters = StdioServerParameters(command=sys.executable,
            args=["-u", str(REPO / "mcp_server.py"), "--config", str(config)], cwd=str(REPO.parent), encoding="utf-8")
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=30)) as session:
                await session.initialize()
                listing = await session.list_tools()
                assert {tool.name for tool in listing.tools} == TOOLS
                scan_schema = next(tool.inputSchema for tool in listing.tools if tool.name == "scan_project")
                assert scan_schema["properties"]["include_remediation"]["type"] == "boolean"
                assert scan_schema["properties"]["include_remediation"]["default"] is True
                for name in ("get_product_capabilities", "list_projects", "list_product_reports"):
                    result = await session.call_tool(name, {})
                    assert not result.isError, result.content
                    if name == "get_product_capabilities":
                        value = result.structuredContent or json.loads("".join(item.text for item in result.content if item.type == "text"))
                        assert value["remediation_contract"] == "security-remediation/17"
                        assert value["http_evidence_contract"] == "http-expectations/2"
                        assert value["verification_conditions"] == "HARNESS_NOT_MODEL"
                for name, arguments in (
                    ("inspect_project", {"project_id": "unregistered"}),
                    ("collect_endpoint_evidence", {"project_id": "unregistered", "endpoint_id": "ep-no"}),
                    ("review_endpoint", {"project_id": "unregistered", "collection_id": "../secret"}),
                    ("read_review_report", {"report_id": "../secret"}),
                    ("scan_dependency_cves", {"project_id": "unregistered", "online": "true"}),
                    ("run_http_security_check", {"target_id": "unregistered"}),
                    ("scan_project", {"project_path": "relative/path"}),
                    ("scan_project", {"project_path": "relative/path", "max_ai_endpoints": True}),
                    ("scan_project", {"project_path": "relative/path", "include_remediation": "true"}),
                    ("get_project_scan_status", {"job_id": "../secret"}),
                    ("read_project_scan_report", {"job_id": "../secret"}),
                    ("cancel_project_scan", {"job_id": "../secret"}),
                    ("verify_project_fix", {"project_path": "relative/path"}),
                    ("get_fix_verification_status", {"job_id": "../secret"}),
                    ("cancel_fix_verification", {"job_id": "../secret"}),
                ):
                    result = await session.call_tool(name, arguments)
                    assert result.isError, (name, result.content)
        assert not (Path(temporary) / "results").exists()
        print(json.dumps({"status": "passed", "tools": len(TOOLS), "invalid_requests_rejected": 15,
                          "read_only_calls": 3, "model_calls": 0, "external_requests": 0}))


if __name__ == "__main__":
    asyncio.run(smoke())

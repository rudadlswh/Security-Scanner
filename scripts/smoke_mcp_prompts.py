# [한글 기능 설명]
# 기능: 공식 SDK의 실제 STDIO로 사용자 프롬프트 4개를 조회하고 영수증을 저장한다.
# 주의: 도구 실행·Java 검사·네트워크·Ollama 호출 없이 프롬프트 프로토콜만 검증한다.
import argparse
import asyncio
import datetime as dt
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from localcode_review_mcp.prompts import PROMPT_NAMES
from smoke_mcp import TOOLS


async def smoke():
    reports = REPO / "results/mcp-security"
    before = sorted(str(p.relative_to(reports)) for p in reports.rglob("*") if p.is_file())
    params = StdioServerParameters(command=sys.executable,
        args=["-u", str(REPO / "mcp_server.py")], cwd=str(REPO.parent), encoding="utf-8")
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=30)) as session:
            initialized = await session.initialize()
            assert initialized.capabilities.prompts is not None
            listing = await session.list_prompts()
            assert {p.name for p in listing.prompts} == set(PROMPT_NAMES)
            workflows = {}
            for name in PROMPT_NAMES:
                result = await session.get_prompt(name, {})
                workflows[name] = json.loads(result.messages[0].content.text)
            assert workflows["localcode-check"]["steps"][0]["arguments"]["check_runtime_cves"] is False
            assert workflows["localcode-cve"]["steps"][0]["arguments"]["check_runtime_cves"] is True
            report_id = "run-20261019T120000Z-123456789abc"
            fetched = await session.get_prompt("localcode-reports", {"report_id": report_id})
            assert json.loads(fetched.messages[0].content.text)["steps"][0]["arguments"]["report_id"] == report_id
            for name, arguments in (("unknown-command", {}), ("localcode-reports", {"report_id": "../secret"})):
                try:
                    await session.get_prompt(name, arguments)
                except McpError:
                    pass
                else:
                    raise AssertionError("Invalid prompt request was accepted")
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == TOOLS
    after = sorted(str(p.relative_to(reports)) for p in reports.rglob("*") if p.is_file())
    assert before == after
    return {"status": "passed", "transport": "stdio", "protocol_version": initialized.protocolVersion,
            "prompts": sorted(workflows), "prompt_fetches": 5, "invalid_requests_rejected": 2,
            "existing_tool_count": 5, "total_tool_count": len(TOOLS), "tool_calls": 0, "model_calls": 0,
            "sample_checks": 0, "report_files_added": 0,
            "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(smoke())
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    with args.receipt.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(result, file, ensure_ascii=False, indent=2)
        file.write("\n")
    print(json.dumps(result))

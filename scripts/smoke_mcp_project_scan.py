"""단일 scan_project 요청의 실제 STDIO→AST→캐시 CVE→일회용 HTTP→통합 보고서 검증.

새 임시 Java/Spring 소스와 프레임워크 대역 HTTP 서버를 사용한다. Ollama/외부 API는 호출하지 않는다.
실제 Spring/JPA 구동 정확성의 증거가 아니라 통합 흐름·권한/상태 프로브·프로세스 종료 검사다.
"""
import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from localcode_review_mcp.workspace import digest, now, save_json


def data(result):
    assert not result.isError, result.content
    return result.structuredContent if result.structuredContent is not None else json.loads("".join(x.text for x in result.content if x.type == "text"))


async def smoke(receipt):
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        project = base / "new-java-project"
        project.mkdir()
        (project / "Api.java").write_text('''import org.springframework.web.bind.annotation.*;
@RestController class Api {
 @DeleteMapping("/items/{id}") void remove(long id) { }
 @PostMapping("/items") void create() { }
}
''', encoding="utf-8")
        (project / "pom.xml").write_text('''<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId>
<artifactId>disposable</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId>
<artifactId>fixture-only</artifactId><version>1.0</version></dependency></dependencies></project>''', encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        fixture = (ROOT / "tools/http-fixture/server.py").read_text(encoding="utf-8")
        (project / "fixture.py").write_text(fixture.replace("18080", str(port)), encoding="utf-8")
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in project.iterdir()}
        results = base / "results"
        config = base / "config.json"
        targets = {}
        for name, unsafe in (("safe", False), ("unsafe", True)):
            plan = json.loads((ROOT / "mcp/http-plan.example.json").read_text())
            if unsafe:
                plan["scenarios"][0]["request"]["path"] = "/api/unsafe/items/lcr-disposable-001"
            path = base / (name + ".json")
            save_json(path, plan)
            target = json.loads((ROOT / "mcp/http-target.example.json").read_text())
            target.update(base_url="http://127.0.0.1:" + str(port), plan_file=str(path))
            targets[name] = target
        settings = {"version": 1, "projects": {}, "results_dir": str(results), "jdk": os.environ.get("JAVA_HOME"),
                    "http_targets": targets, "allow_osv_network": False, "scan_profiles": {"test-profile": {
                        "project_root": str(project), "http_target_ids": ["safe", "unsafe"],
                        "disposable_server": {"project_root": str(project), "authorized_disposable_environment": True,
                            "acknowledge_command_execution": True, "command": [sys.executable, "{project_copy}/fixture.py"],
                            "base_url": "http://127.0.0.1:" + str(port), "health_path": "/test/fixtures/item/state",
                            "health_statuses": [403], "startup_timeout_seconds": 20}}}}
        save_json(config, settings)
        config_hash = digest(config.read_bytes())
        package = {"ecosystem": "Maven", "name": "example:fixture-only", "version": "1.0"}
        save_json(results / "osv-cache" / (digest(package) + ".json"), {"query": package, "fetched_at": now(),
            "vulnerabilities": [{"id": "SYNTHETIC-TEST-ADVISORY", "aliases": [], "affected": [{"package": package,
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}]})
        params = StdioServerParameters(command=sys.executable,
            args=["-u", str(ROOT / "mcp_server.py"), "--config", str(config)], cwd=str(ROOT), encoding="utf-8",
            env={**os.environ, "LCR_FIXTURE_OWNER": "Bearer fixture-owner", "LCR_FIXTURE_NON_OWNER": "Bearer fixture-non-owner",
                 "LCR_FIXTURE_OBSERVER": "Bearer fixture-observer"})
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=60)) as session:
                await session.initialize()
                started = data(await session.call_tool("scan_project", {"project_path": str(project), "max_ai_endpoints": 0}))
                job = started["job_id"]
                for _ in range(150):
                    status = data(await session.call_tool("get_project_scan_status", {"job_id": job}))
                    if status["state"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                        break
                    await asyncio.sleep(0.2)
                report = data(await session.call_tool("read_project_scan_report", {"job_id": job}))
                save_json(receipt.with_name(receipt.stem + "-report.json"), report)
                assert status["state"] == "COMPLETED", report
                assert report["checks"]["source"]["endpoints_collected"] == 2, report
                assert report["checks"]["ai"]["status"] == "SKIPPED", report
                assert report["checks"]["cve"]["status"] == "COMPLETED", report
                assert report["checks"]["dynamic"]["status"] == "COMPLETED", report
                assert len(report["checks"]["dynamic"]["targets"]) == 2
                assert {f["kind"] for f in report["findings"]} == {"DEPENDENCY_VERSION_MATCH", "DYNAMIC_BEHAVIOR_DISCREPANCY"}
                assert report["model_calls_sent"] == 0 and report["disposable_server"]["stopped"] and report["disposable_server"]["workspace_removed"]
                assert report["coverage_status"] == "PARTIAL"  # AI 미실행을 성공으로 숨기지 않는다.
                assert report["source_snapshot_unchanged"]
                markdown = Path(report["artifact_paths"]["markdown"]).read_text(encoding="utf-8")
                receipt.with_suffix(".md").write_text(markdown, encoding="utf-8")
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in project.iterdir()}
        assert before == after and config_hash == digest(config.read_bytes())
        assert not (results / "control/project-scan.lock").exists()
        summary = {"status": "passed", "transport": "stdio", "single_scan_start": True, "endpoint_count": 2,
                   "source_unchanged": True, "config_unchanged": True, "disposable_server_stopped": True,
                   "temporary_copy_removed": True, "normal_http_block_and_unsafe_mutation_detected": True,
                   "synthetic_cve_cache_matched": True, "coverage_status": "PARTIAL", "ai_skipped": True,
                   "model_calls": 0, "external_requests": 0, "not_an_actual_spring_runtime": True}
        save_json(receipt, summary)
        print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    asyncio.run(smoke(args.receipt.resolve()))

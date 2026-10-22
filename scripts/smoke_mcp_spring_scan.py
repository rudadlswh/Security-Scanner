"""실제 Spring/Tomcat/H2 샘플을 한 MCP 요청으로 검사한다. AI/OSV 온라인 호출 없음.

prepareFixture로 사전 빌드한 자체 샘플만 실행한다. 기대 동작과 설정을 전송 전에 저장한다.
진단 결과를 보존하며 서버/복사본 정리는 검사기 자체 계약으로 검증한다.
"""
import argparse
import asyncio
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from localcode_review_mcp.workspace import digest, load_json, now, save_json

PROJECT = ROOT / "tools/spring-security-fixture"


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and ".gradle" not in p.relative_to(root).parts}


def data(result):
    assert not result.isError, result.content
    return result.structuredContent if result.structuredContent is not None else json.loads(
        "".join(x.text for x in result.content if x.type == "text"))


def plan(unsafe):
    template = load_json(ROOT / "mcp/http-plan.example.json")["scenarios"][0]
    scenarios = []
    for actor, status, remains in (("anonymous", 401, True), ("non_owner", 403, True), ("owner", 204, False)):
        row = copy.deepcopy(template)
        row["id"] = ("unsafe-" if unsafe else "safe-") + actor.replace("_", "-")
        row["request"].update(actor=actor, expect_status=[status],
            path=("/api/unsafe/items/" if unsafe else "/api/items/") + "lcr-disposable-001")
        row["after"]["expected"] = remains
        scenarios.append(row)
    return {"version": 1, "scenarios": scenarios}


async def smoke(output):
    output.mkdir(parents=True, exist_ok=False)
    java_home = Path(os.environ["JAVA_HOME"])
    java = java_home / "bin/java.exe"
    assert java.is_file()
    assert (PROJECT / "build/libs/fixture.jar").is_file(), "prepareFixture must run first"
    inventory = load_json(PROJECT / "build/dependency-inventory.json")
    before = tree_hashes(PROJECT)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    results = output / "product"
    targets = {}
    for name, unsafe in (("safe", False), ("unsafe", True)):
        path = output / (name + "-plan.json")
        save_json(path, plan(unsafe))
        target = load_json(ROOT / "mcp/http-target.example.json")
        target.update(base_url=f"http://127.0.0.1:{port}", plan_file=str(path))
        targets[name] = target
    project_id = "spring-fixture"
    config = output / "config.json"
    settings = {"version": 1, "projects": {project_id: {"root": str(PROJECT),
                    "dependency_inventory": str(PROJECT / "build/dependency-inventory.json")}},
        "results_dir": str(results), "jdk": str(java_home), "http_targets": targets,
        "allow_osv_network": False, "scan_profiles": {"spring-fixture": {
            "project_root": str(PROJECT), "http_target_ids": ["safe", "unsafe"],
            "disposable_server": {"project_root": str(PROJECT), "authorized_disposable_environment": True,
                "acknowledge_command_execution": True, "command": [str(java), "-Xmx256m", "-cp",
                    "{project_copy}/build/libs/fixture.jar;{project_copy}/build/runtime/*", "fixture.FixtureApplication",
                    "--server.address=127.0.0.1", "--server.port={port}", "--spring.main.banner-mode=off"],
                "base_url": f"http://127.0.0.1:{port}", "health_path": "/health", "health_statuses": [200],
                "startup_timeout_seconds": 60}}}}
    save_json(config, settings)
    expected = {"created_at": now(), "project_sha256": before, "config_sha256": digest(config.read_bytes()),
        "expected_endpoints": 6, "expected_dynamic_scenarios": 6,
        "expected_safe_statuses": [401, 403, 204], "expected_unsafe_statuses": [401, 204, 204],
        "expected_discrepancy_count": 1, "expected_non_owner_safe_row_retained": True,
        "expected_non_owner_unsafe_row_retained": False,
        "cve_expectation": "REAL_RESOLVED_INVENTORY_CACHE_MISSES_UNKNOWN_NOT_CLEAN",
        "ai_expectation": "SKIPPED_NO_AUTHORIZATION", "model_calls": 0, "external_api_requests": 0}
    save_json(output / "expectations.json", expected)
    save_json(output / "expectations-hash.json", {"sha256": digest((output / "expectations.json").read_bytes())})
    env = {**os.environ, "LCR_FIXTURE_OWNER": "Bearer fixture-owner", "LCR_FIXTURE_NON_OWNER": "Bearer fixture-non-owner",
           "LCR_FIXTURE_OBSERVER": "Bearer fixture-observer"}
    params = StdioServerParameters(command=sys.executable,
        args=["-u", str(ROOT / "mcp_server.py"), "--config", str(config)], cwd=str(ROOT), env=env)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=90)) as session:
            await session.initialize()
            started = data(await session.call_tool("scan_project", {"project_path": str(PROJECT)}))
            job = started["job_id"]
            for _ in range(300):
                status = data(await session.call_tool("get_project_scan_status", {"job_id": job}))
                if status["state"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                    break
                await asyncio.sleep(0.5)
            report = data(await session.call_tool("read_project_scan_report", {"job_id": job}))
            save_json(output / "report.json", report)
    assert status["state"] == "COMPLETED", report
    assert report["checks"]["source"]["endpoints_collected"] == expected["expected_endpoints"], report
    assert report["checks"]["ai"]["status"] == "SKIPPED", report
    assert report["checks"]["ai"]["reason"] == "MODEL_AUTHORIZATION_REQUIRED", report
    assert report["checks"]["cve"]["status"] == "PARTIAL", report
    assert report["checks"]["cve"]["online_queries"] == 0
    assert report["checks"]["dynamic"]["status"] == "COMPLETED", report
    children = {t["target_id"]: load_json(results / t["report_id"] / "report.json")
                for t in report["checks"]["dynamic"]["targets"]}
    safe, unsafe = children["safe"]["scenarios"], children["unsafe"]["scenarios"]
    assert [s["request"]["status_code"] for s in safe] == expected["expected_safe_statuses"], safe
    assert [s["request"]["status_code"] for s in unsafe] == expected["expected_unsafe_statuses"], unsafe
    assert safe[1]["after"]["state_matches"] is True
    assert unsafe[1]["after"]["state_matches"] is False
    assert all(s["cleanup_status"] == "COMPLETED" and s["cleanup_verify"]["state_matches"] for s in safe + unsafe), children
    discrepancies = [f for f in report["findings"] if f["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY"]
    assert len(discrepancies) == 1, report["findings"]
    assert not [f for f in report["findings"] if f["kind"] == "DEPENDENCY_VERSION_MATCH"]
    server = report["disposable_server"]
    assert server["stopped"] and server["workspace_removed"] and server["listener_verification"]["owned_by_server_job"]
    assert report["source_snapshot_unchanged"] and before == tree_hashes(PROJECT)
    assert digest(config.read_bytes()) == expected["config_sha256"]
    assert report["model_calls_sent"] == 0 and report["coverage_status"] == "PARTIAL"
    assert not (results / "control/project-scan.lock").exists()
    assert not (results / "control/http-check.lock").exists()
    assert not (results / "control/model-authorization.json").exists()
    with socket.socket() as sock:
        sock.settimeout(2)
        assert sock.connect_ex(("127.0.0.1", port)) != 0, "server listener remains"
    receipt = {"status": "passed", "completed_at": now(), "transport": "MCP_STDIO", "single_scan_start": True,
        "actual_runtime": "Spring Boot 3.4.0 / embedded Tomcat / H2 2.3.232 in-memory / plain JDBC",
        "spring_security_or_jpa_tested": False, "endpoints_collected": 6, "http_scenarios": 6,
        "safe_statuses": expected["expected_safe_statuses"], "unsafe_statuses": expected["expected_unsafe_statuses"],
        "intentional_non_owner_deletion_reproduced": True, "discrepancies": len(discrepancies),
        "all_test_rows_cleaned": True, "server_stopped": True, "loopback_port_closed": True,
        "copy_removed": True, "source_and_config_unchanged": True,
        "resolved_runtime_packages": len(inventory["packages"]), "cve_status": report["checks"]["cve"]["status"],
        "cve_conclusion": "UNKNOWN_NO_CACHE", "ai_status": "SKIPPED_NO_AUTHORIZATION",
        "model_calls": 0, "external_api_requests": 0, "report_id": job,
        "report_path": str(results / job / "report.json"), "coverage_status": "PARTIAL"}
    save_json(output / "summary.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(smoke(args.output.resolve()))

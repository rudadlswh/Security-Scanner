"""실제 Spring Security/JPA/H2의 SAST·권한·SQL·HTML·SSRF 및 복사본 수정 전후 검증.

자체 고정 샘플만 사용한다. 원본/기본 설정/이전 예산을 수정하지 않으며 AI·외부 CVE 호출은 없다.
"""
import argparse
import asyncio
import base64
import copy
import datetime as dt
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import quote
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from localcode_review_mcp.workspace import digest, load_json, now, save_json
PROJECT = ROOT / "tools/spring-assurance-fixture"


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in sorted(root.rglob("*"))
            if p.is_file() and ".gradle" not in p.relative_to(root).parts}


def action(path, method="GET", actor="observer", status=200, **extra):
    return dict(path=path, method=method, actor=actor, expect_status=[status], **extra)


def plans(base):
    deletion = []
    record = "/fixture/records/sample-one"
    probe = action(record, json_pointer="/exists", expected=True)
    for unsafe in (False, True):
        for actor, status, remains in (("anonymous", 401, True), ("non_owner", 403, True), ("owner", 204, False)):
            deletion.append({"id": ("unsafe-" if unsafe else "safe-") + actor.replace("_", "-"),
                "setup": [action(record, "POST", json={"owner": "owner", "label": "owned"})], "before": probe,
                "request": action(("/api/unsafe/records/" if unsafe else "/api/records/") + "sample-one", "DELETE", actor, status),
                "after": {**probe, "expected": remains}, "cleanup": [action(record, "DELETE")],
                "cleanup_verify": {**probe, "expected": False}})
    def check(identifier, request, group, setup=None, cleanup=None):
        path = "/fixture/probes/" + group
        probe = action(path, json_pointer="/value", expected=False)
        return {"id": identifier, "setup": [*(setup or []), action(path, "POST")], "before": probe,
                "request": request, "after": probe, "cleanup": [*(cleanup or []), action(path, "POST")], "cleanup_verify": probe}
    sql = []
    payload = quote("' OR '1'='1", safe="")
    rows = ["/fixture/records/sql-owner", "/fixture/records/sql-other"]
    setup = [action(rows[0], "POST", json={"owner": "owner", "label": "owned"}),
             action(rows[1], "POST", json={"owner": "other", "label": "private"})]
    for prefix in ("/api/unsafe", "/api"):
        sql.append(check(("unsafe" if "unsafe" in prefix else "safe") + "-sql",
                         action(prefix + "/search?label=" + payload, actor="owner"), "sql", setup,
                         [action(path, "DELETE") for path in rows]))
    html = []
    payload = quote("<script>alert(1)</script>", safe="")
    for prefix in ("/api/unsafe", "/api"):
        html.append(check(("unsafe" if "unsafe" in prefix else "safe") + "-html",
                         action(prefix + "/html?message=" + payload, actor="owner",
                                body_must_not_contain=["<script>"], body_must_contain=["&lt;script&gt;"]), "html"))
    destination = quote(base + "/fixture/private", safe="")
    ssrf = [check("unsafe-ssrf", action("/api/unsafe/fetch?url=" + destination, actor="owner", status=400), "ssrf"),
            check("safe-ssrf", action("/api/fetch?target=" + destination, actor="owner", status=400), "ssrf"),
            check("safe-allowed-target", action("/api/fetch?target=public", actor="owner", body_must_contain=["fixed-public-response"]), "ssrf")]
    return {key: {"version": 1, "scenarios": value} for key, value in (("deletion", deletion), ("sql", sql), ("html", html), ("ssrf", ssrf))}


def bundle():
    boundary = PROJECT / "src/main/java/assurance/BoundaryController.java"
    record = PROJECT / "src/main/java/assurance/RecordController.java"
    before = boundary.read_text(encoding="utf-8")
    after = before.replace('database.createQuery("select r from AuditRecord r where r.label = \'"+label+"\'",AuditRecord.class).getResultList()',
                           'database.createQuery("select r from AuditRecord r where r.label = :label",AuditRecord.class).setParameter("label",label).getResultList()')
    after = after.replace('public String unsafeHtml(@RequestParam String message){return message;}',
                          'public String unsafeHtml(@RequestParam String message){return HtmlUtils.htmlEscape(message);}')
    after = after.replace('public String unsafeFetch(@RequestParam String url){return http.getForObject(url,String.class);}',
                          'public String unsafeFetch(@RequestParam String url){throw new ResponseStatusException(HttpStatus.BAD_REQUEST);}')
    record_before = record.read_text(encoding="utf-8")
    record_after = record_before.replace('        records.deleteById(id);',
        '        AuditRecord r=records.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));\n'
        '        if(!r.ownerName.equals(principal.getName()))throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n'
        '        records.delete(r);')
    assert before != after and record_before != record_after
    # 원본 바이트 개행도 보존한다. 새 자체 샘플은 UTF-8 LF로 작성됐다.
    return {"version": 1, "source": "REVIEWED_SELF_OWNED_FIXTURE_PATCH_NOT_AI_AUTO_APPLY", "edits": [
        {"path": boundary.relative_to(PROJECT).as_posix(), "before_sha256": digest(boundary.read_bytes()), "old": before, "new": after},
        {"path": record.relative_to(PROJECT).as_posix(), "before_sha256": digest(record.read_bytes()), "old": record_before, "new": record_after}]}


def data(result):
    assert not result.isError, result.content
    return result.structuredContent or json.loads("".join(x.text for x in result.content if x.type == "text"))


async def smoke(output, verify_fix=True, integrated_fix=False):
    output.mkdir(parents=True, exist_ok=False)
    before = tree_hashes(PROJECT)
    java_home = Path(os.environ["JAVA_HOME"])
    java = java_home / "bin/java.exe"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    plan_map, targets = plans(base), {}
    for key, plan in plan_map.items():
        path = output / (key + "-plan.json")
        save_json(path, plan)
        actions = [a for s in plan["scenarios"] for a in [*s["setup"], s["before"], s["request"], s["after"], *s["cleanup"], s["cleanup_verify"]]]
        targets[key] = {"base_url": base, "authorized_disposable_environment": True, "plan_file": str(path),
            "allowed_paths": sorted({a["path"] for a in actions}), "max_requests": 100, "timeout_seconds": 120,
            "actors": {"owner": {"headers_env": {"Authorization": "LCR_ASSURANCE_OWNER"}},
                       "non_owner": {"headers_env": {"Authorization": "LCR_ASSURANCE_OTHER"}}, "observer": {}, "anonymous": {}}}
    patch_file = output / "fix-bundle.json"
    save_json(patch_file, bundle())
    before_expect = {"static_rules": ["LCR-SQL-001", "LCR-SSRF-001", "LCR-XSS-001"], "dynamic_discrepancies": 4}
    after_expect = {"static_rules": [], "dynamic_discrepancies": 0}
    config = output / "config.json"
    settings = {"version": 1, "projects": {"assurance": {"root": str(PROJECT), "dependency_inventory": str(PROJECT / "build/dependency-inventory.json")}},
        "results_dir": str(output / "product"), "jdk": str(java_home), "http_targets": targets, "allow_osv_network": False,
        "scan_profiles": {"assurance": {"project_root": str(PROJECT), "http_target_ids": list(targets), "disposable_server": {
            "project_root": str(PROJECT), "authorized_disposable_environment": True, "acknowledge_command_execution": True,
            "command": [str(java), "-Xmx384m", "-cp", "{project_copy}/build/libs/fixture.jar;{project_copy}/build/runtime/*",
                        "assurance.FixtureApplication", "--server.address=127.0.0.1", "--server.port={port}"],
            "base_url": base, "health_path": "/health", "startup_timeout_seconds": 90}, "fix_verification": {
            "authorized_copy_only_verification": True, "acknowledge_build_execution": True,
            "bundle_file": str(patch_file), "bundle_sha256": digest(patch_file.read_bytes()),
            "build_commands": [{"argv": [str(java), "-classpath", str(ROOT / "gradle/wrapper/gradle-wrapper.jar"),
                               "org.gradle.wrapper.GradleWrapperMain", "--offline", "--no-daemon", "-p", "{project_copy}", "prepareFixture"], "timeout_seconds": 180}],
            "expected_before": before_expect, "expected_after": after_expect}}}}
    save_json(config, settings)
    if integrated_fix:
        settings["scan_profiles"]["assurance"]["run_fix_verification_after_scan"] = True
        save_json(config, settings, replace=True)
    save_json(output / "expectations.json", {"frozen_at": now(), "project_files": before, "before": before_expect, "after": after_expect,
        "scenarios": {k: len(v["scenarios"]) for k, v in plan_map.items()}, "spring_security_actual": True, "jpa_actual": True,
        "isolation": "WINDOWS_JOB_PROCESS_GUARD_NOT_OS_SANDBOX", "model_calls": 0, "external_cve_queries": 0})
    params = StdioServerParameters(command=sys.executable, args=["-u", str(ROOT / "mcp_server.py"), "--config", str(config)],
        cwd=str(ROOT), env={**os.environ, "LCR_ASSURANCE_OWNER": "Basic " + base64.b64encode(b"owner:fixture-only").decode(),
                           "LCR_ASSURANCE_OTHER": "Basic " + base64.b64encode(b"other:fixture-only").decode()})
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=dt.timedelta(seconds=120)) as session:
            await session.initialize()
            listing = await session.list_tools()
            capabilities = data(await session.call_tool("get_product_capabilities", {}))
            save_json(output / "capabilities.json", capabilities)
            started = data(await session.call_tool("scan_project", {"project_path": str(PROJECT), "max_ai_endpoints": 0, "include_remediation": False}))
            for _ in range(600):
                status = data(await session.call_tool("get_project_scan_status", {"job_id": started["job_id"]}))
                if status["state"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                    break
                await asyncio.sleep(.5)
            report = data(await session.call_tool("read_project_scan_report", {"job_id": started["job_id"]}))
            save_json(output / "scan-report.json", report)
            assert status["state"] == "COMPLETED", report["errors"]
            assert report["checks"]["sast"]["status"] == "COMPLETED_FOR_RULESET", report["checks"]
            assert sorted(f["rule_id"] for f in report["findings"] if f["kind"] == "STATIC_SECURITY_CANDIDATE") == before_expect["static_rules"]
            assert report["checks"]["dynamic"]["status"] == "COMPLETED", report["checks"]["dynamic"]
            assert sum(f["kind"] == "DYNAMIC_BEHAVIOR_DISCREPANCY" for f in report["findings"]) == 4, report["findings"]
            assert report["checks"]["cve"]["coverage"] == "RESOLVED_RUNTIME_WITH_HASH_BINDING", report["checks"]["cve"]
            assert report["disposable_server"]["stopped"] and report["disposable_server"]["workspace_removed"]
            assert before == tree_hashes(PROJECT)
            fixed = None
            if integrated_fix:
                assert report["checks"]["fix"]["status"] == "COMPLETED", report["checks"]["fix"]
                fixed = data(await session.call_tool("get_fix_verification_status", {"job_id": report["checks"]["fix"]["report_id"]}))
                save_json(output / "fix-report.json", fixed)
                assert fixed["verification"] == "MATCHES_FROZEN_CHECKS", fixed
                assert fixed["baseline_reused_from_parent_scan"] is True
            elif verify_fix:
                start = data(await session.call_tool("verify_project_fix", {"project_path": str(PROJECT)}))
                for _ in range(900):
                    fixed = data(await session.call_tool("get_fix_verification_status", {"job_id": start["job_id"]}))
                    if fixed["state"] in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                        break
                    await asyncio.sleep(.5)
                save_json(output / "fix-report.json", fixed)
                assert fixed["state"] == "COMPLETED", fixed
                assert fixed["verification"] == "MATCHES_FROZEN_CHECKS", fixed
                assert fixed["original_snapshot_unchanged"] and fixed["workspace_removed"]
    assert before == tree_hashes(PROJECT), "original fixture modified"
    with socket.socket() as sock:
        assert sock.connect_ex(("127.0.0.1", port)) != 0, "listener remains"
    receipt = {"status": "PASSED", "finished_at": now(), "transport": "MCP_STDIO", "tools": len(listing.tools),
        "runtime": "Spring Boot 3.4.0 / actual Spring Security / actual Hibernate JPA / H2 memory",
        "static_candidates": 3, "dynamic_scenarios": sum(len(p["scenarios"]) for p in plan_map.values()),
        "intentional_discrepancies": 4, "fixed_copy": fixed and fixed["verification"],
        "source_and_config_unchanged": True, "server_stopped_and_workspace_removed": True,
        "model_calls": 0, "external_cve_queries": 0, "os_security_sandbox": False,
        "strong_container_backend_live_tested": False, "report_id": started["job_id"]}
    save_json(output / "summary.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--skip-fix", action="store_true")
    parser.add_argument("--integrated-fix", action="store_true")
    args = parser.parse_args()
    asyncio.run(smoke(args.output.resolve(), not args.skip_fix, args.integrated_fix))

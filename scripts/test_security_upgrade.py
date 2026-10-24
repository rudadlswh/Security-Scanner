"""추가 보안 흐름의 실패 차단·빌드 연결·원문 비저장·복사본 경계를 검증한다. 외부 요청 없음."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, AsyncMock
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.container_server import ContainerServer
from localcode_review_mcp.dependencies import dependency_inventory
from localcode_review_mcp.disposable import validate_server
from localcode_review_mcp.fix_verification import FixVerifications, apply_bundle, run_build
from localcode_review_mcp.http_checks import run_http_checks, validate_plan
from localcode_review_mcp.workspace import ProductConfig, ProductError, Snapshot, digest, save_json


class UpgradeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "Api.java").write_text("class Api {}", encoding="utf-8")
        self.cfg = ProductConfig(self.root / "config.json", {"demo": {"root": str(self.source)}}, None, self.root / "results", {})

    def resolved(self):
        artifact = self.source / "build/libs/app.jar"
        runtime = self.source / "build/runtime/lib.jar"
        artifact.parent.mkdir(parents=True)
        runtime.parent.mkdir(parents=True)
        artifact.write_bytes(b"application")
        runtime.write_bytes(b"library")
        data = {"format": "lcr-resolved-inventory/1", "packages": [{"name": "example:lib", "version": "1.0", "runtime_path": "build/runtime/lib.jar", "sha256": digest(runtime.read_bytes())}],
                "build": {"artifact": "build/libs/app.jar", "sha256": digest(artifact.read_bytes()), "resolved": True,
                          "configuration": "runtimeClasspath", "runtime_directory": "build/runtime",
                          "inputs": {p: digest(raw) for p, raw in Snapshot.read(self.source).files.items()}}}
        inventory = self.root / "inventory.json"
        save_json(inventory, data)
        self.cfg.projects["demo"]["dependency_inventory"] = str(inventory)
        return data, inventory

    def test_runtime_inventory_hash_binding_and_bom_resolution_are_explicit(self):
        (self.source / "build.gradle").write_text("implementation platform('example:bom:1')", encoding="utf-8")
        self.resolved()
        row = dependency_inventory(self.cfg, "demo")
        self.assertEqual("RESOLVED_RUNTIME_WITH_HASH_BINDING", row["coverage"])
        self.assertEqual([], row["unresolved"])
        self.assertTrue(row["declaration_limits_superseded_for_runtime"])
        self.assertFalse(row["build_binding"]["deployed_build_verified"])

    def test_runtime_inventory_rejects_stale_sources_and_changed_application(self):
        self.resolved()
        source = self.source / "Api.java"
        before = source.read_bytes()
        source.write_bytes(b"class Changed {}")
        with self.assertRaisesRegex(ProductError, "SOURCE_MISMATCH"):
            dependency_inventory(self.cfg, "demo")
        source.write_bytes(before)
        (self.source / "build/libs/app.jar").write_bytes(b"modified")
        with self.assertRaisesRegex(ProductError, "ARTIFACT_MISMATCH"):
            dependency_inventory(self.cfg, "demo")

    def test_runtime_inventory_rejects_unlisted_or_changed_runtime_jar(self):
        self.resolved()
        extra = self.source / "build/runtime/extra.jar"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ProductError, "RUNTIME_SET_MISMATCH"):
            dependency_inventory(self.cfg, "demo")
        extra.unlink()
        (self.source / "build/runtime/lib.jar").write_bytes(b"modified")
        with self.assertRaisesRegex(ProductError, "ARTIFACT_MISMATCH"):
            dependency_inventory(self.cfg, "demo")

    def test_inventory_cannot_claim_binding_without_inputs_or_escape_root(self):
        data, path = self.resolved()
        data["build"]["inputs"] = {}
        save_json(path, data, replace=True)
        with self.assertRaisesRegex(ProductError, "BINDING_REQUIRED"):
            dependency_inventory(self.cfg, "demo")
        data["build"]["inputs"] = {p: digest(raw) for p, raw in Snapshot.read(self.source).files.items()}
        data["packages"][0]["runtime_path"] = "../outside.jar"
        save_json(path, data, replace=True)
        with self.assertRaisesRegex(ProductError, "PATH_ESCAPE"):
            dependency_inventory(self.cfg, "demo")

    def test_malformed_inventory_rows_and_build_object_fail_with_product_errors(self):
        data, path = self.resolved()
        data["packages"] = ["invalid"]
        save_json(path, data, replace=True)
        with self.assertRaisesRegex(ProductError, "PACKAGE_LIST_INVALID"):
            dependency_inventory(self.cfg, "demo")
        data["packages"] = []
        data["build"] = []
        save_json(path, data, replace=True)
        with self.assertRaisesRegex(ProductError, "BUILD_INVALID"):
            dependency_inventory(self.cfg, "demo")

    def test_required_isolation_never_falls_back_to_local_process(self):
        with self.assertRaisesRegex(ProductError, "OS_ISOLATION_REQUIRED"):
            validate_server({"require_os_isolation": True}, self.source, [])
        spec = {"project_root": str(self.source), "authorized_disposable_environment": True, "acknowledge_command_execution": True,
                "isolation_backend": "docker", "docker_executable": str(self.root / "missing.exe")}
        with self.assertRaisesRegex(ProductError, "ENGINE_UNAVAILABLE_NO_LOCAL_FALLBACK"):
            ContainerServer(spec, self.source, self.root / "run", [])

    def test_container_requires_image_digest_nonroot_and_no_host_environment(self):
        spec = {"project_root": str(self.source), "authorized_disposable_environment": True, "acknowledge_command_execution": True,
                "docker_executable": sys.executable, "base_url": "http://127.0.0.1:18880", "command": ["/usr/bin/java", "-jar", "/workspace/app.jar"],
                "image": "local/image@sha256:" + "a" * 64}
        targets = [{"base_url": spec["base_url"], "authorized_disposable_environment": True}]
        server = ContainerServer(spec, self.source, self.root / "run", targets)
        self.assertFalse(server.metadata["isolation_verified"])
        for changes, error in (({"image": "image:latest"}, "DIGEST_REQUIRED"), ({"user": "0:0"}, "NON_ROOT"), ({"environment_from": ["HOME"]}, "ENVIRONMENT_NOT_SUPPORTED")):
            with self.assertRaisesRegex(ProductError, error):
                ContainerServer({**spec, **changes}, self.source, self.root / "run", targets)

    def test_container_command_restrictions_are_inspected_and_cleanup_idempotent(self):
        folder = self.root / "container-run"
        folder.mkdir()
        spec = {"project_root": str(self.source), "authorized_disposable_environment": True, "acknowledge_command_execution": True,
                "docker_executable": sys.executable, "base_url": "http://127.0.0.1:18880", "command": ["/usr/bin/java", "-jar", "{project_copy}/app.jar"],
                "image": "local/image@sha256:" + "a" * 64}
        spec['network_policy']='internal'
        server = ContainerServer(spec, self.source, folder, [{"base_url": spec["base_url"], "authorized_disposable_environment": True}])
        calls = []
        def engine(*args):
            calls.append(args)
            if args[0] == "info":
                return '{"OSType":"linux"}'
            if args[0] == "inspect":
                return json.dumps([{"HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "Memory": 512*1_048_576,
                    "MemorySwap": 512*1_048_576, "PidsLimit": 128, "NanoCpus": 1_000_000_000, "CapDrop": ["ALL"], "LogConfig": {"Type": "none"},
                    "SecurityOpt": ["no-new-privileges"], "PortBindings": {}, "NetworkMode":server.network,
                    "Sysctls":{'net.ipv6.conf.all.disable_ipv6':'1','net.ipv6.conf.default.disable_ipv6':'1'}},
                    "Config": {"User": "10001:10001"}, "Mounts": [{"Type": "bind", "Destination": "/workspace", "RW": False, "Source": str(server.copy)}]}])
            if args[:2] == ("network", "inspect"):
                return '[{"Internal":true}]'
            return '[]'
        original = httpx.AsyncClient
        async def check():
            with patch.object(server, "cli", side_effect=engine), patch("localcode_review_mcp.container_server.ContainerRelay") as relay, patch("localcode_review_mcp.container_server.httpx.AsyncClient",
                    side_effect=lambda **kwargs: original(transport=httpx.MockTransport(lambda request: httpx.Response(200)), **kwargs)):
                relay.return_value.start=AsyncMock(return_value={"listener_verified":True})
                relay.return_value.stop=AsyncMock()
                await server.start()
                self.assertTrue(server.metadata["isolation_verified"])
                await server.stop()
                await server.stop()
        asyncio.run(check())
        run = next(c for c in calls if c[0] == "run")
        for flag in ("--pull=never", "--read-only", "--cap-drop=ALL", "--memory-swap", "--log-driver=none", "--no-healthcheck"):
            self.assertIn(flag, run)
        self.assertNotIn("--privileged", run)
        self.assertNotIn("--publish", run)
        self.assertEqual(1, sum(c[:2] == ("network", "rm") for c in calls))
        self.assertTrue(server.metadata["workspace_removed"])

    def test_patch_checks_all_preimages_before_writing_any_file(self):
        first = self.source / "Api.java"
        other = self.source / "Other.java"
        other.write_bytes(b"class Other {}")
        bundle = {"version": 1, "edits": [
            {"path": "Api.java", "before_sha256": digest(first.read_bytes()), "old": "class Api {}", "new": "class Fixed {}"},
            {"path": "Other.java", "before_sha256": "0" * 64, "old": "class Other {}", "new": "changed"}]}
        with self.assertRaisesRegex(ProductError, "PREIMAGE_MISMATCH"):
            apply_bundle(self.source, bundle)
        self.assertEqual(b"class Api {}", first.read_bytes())

    def test_patch_rejects_escape_duplicate_and_ambiguous_edits(self):
        edit = {"path": "Api.java", "before_sha256": digest((self.source / "Api.java").read_bytes()), "old": "class", "new": "final class"}
        with self.assertRaisesRegex(ProductError, "PATH_ESCAPE"):
            apply_bundle(self.source, {"version": 1, "edits": [{**edit, "path": "../Api.java"}]})
        with self.assertRaisesRegex(ProductError, "PATH_INVALID"):
            apply_bundle(self.source, {"version": 1, "edits": [edit, edit]})
        with self.assertRaisesRegex(ProductError, "UNIQUE_MATCH"):
            apply_bundle(self.source, {"version": 1, "edits": [{**edit, "old": "absent"}]})
        changes = apply_bundle(self.source, {"version": 1, "edits": [edit]})
        self.assertEqual(b"final class Api {}", (self.source / "Api.java").read_bytes())
        self.assertNotEqual(changes[0]["before_sha256"], changes[0]["after_sha256"])

    def test_fix_requires_operator_profile_and_rejects_unknown_job_kind(self):
        with self.assertRaisesRegex(ProductError, "OPERATOR_PROFILE_REQUIRED"):
            asyncio.run(FixVerifications(self.cfg).start(str(self.source)))

    def test_fix_cancel_before_start_does_not_run_build_or_leave_lock(self):
        bundle = self.root / "bundle.json"
        save_json(bundle, {"version": 1, "edits": []})
        self.cfg.scan_profiles["test"] = {"project_root": str(self.source), "fix_verification": {
            "authorized_copy_only_verification": True, "acknowledge_build_execution": True,
            "bundle_file": str(bundle), "bundle_sha256": digest(bundle.read_bytes()),
            "build_commands": [{"argv": [sys.executable, "-c", "raise RuntimeError('must not run')"]}]}}
        async def check():
            jobs = FixVerifications(self.cfg)
            start = await jobs.start(str(self.source))
            return await jobs.cancel(start["job_id"])
        report = asyncio.run(check())
        self.assertEqual("CANCELLED", report["state"])
        self.assertEqual("NOT_RUN", report["verification"])
        self.assertFalse(report["source_modified"])
        self.assertFalse((self.cfg.results / "control/fix-verification.lock").exists())

    def test_fix_build_refuses_shell_and_original_path(self):
        bad = self.root / "script.cmd"
        bad.write_text("exit", encoding="utf-8")
        with self.assertRaisesRegex(ProductError, "TRUSTED_EXECUTABLE"):
            asyncio.run(run_build({"argv": [str(bad)]}, self.root, self.source, self.root))
        with self.assertRaisesRegex(ProductError, "ORIGINAL_PATH_FORBIDDEN"):
            asyncio.run(run_build({"argv": [sys.executable, str(self.source / "Api.java")]}, self.root, self.source, self.root))

    def test_http_literal_assertion_records_only_hash_and_boolean(self):
        plan = {"version": 1, "scenarios": [{"id": "html", "setup": [{"path": "/reset", "method": "POST", "actor": "observer"}],
            "before": {"path": "/state", "actor": "observer", "json_pointer": "/value", "expected": False},
            "request": {"path": "/html", "actor": "observer", "body_must_not_contain": ["<script>"], "body_must_contain": ["&lt;script&gt;"]},
            "after": {"path": "/state", "actor": "observer", "json_pointer": "/value", "expected": False},
            "cleanup": [{"path": "/reset", "method": "POST", "actor": "observer"}],
            "cleanup_verify": {"path": "/state", "actor": "observer", "json_pointer": "/value", "expected": False}}]}
        path = self.root / "plan.json"
        save_json(path, plan)
        target = {"base_url": "http://127.0.0.1:18880", "authorized_disposable_environment": True, "plan_file": str(path),
                  "allowed_paths": ["/reset", "/state", "/html"], "actors": {"observer": {}}, "max_requests": 20}
        self.cfg.http_targets["html"] = target
        original = httpx.AsyncClient
        def respond(request):
            return httpx.Response(200, content=b"<script>private</script>" if request.url.path == "/html" else b'{"value":false}')
        with patch("localcode_review_mcp.http_checks.httpx.AsyncClient", side_effect=lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs)):
            report = asyncio.run(run_http_checks(self.cfg, "html"))
        self.assertEqual("BEHAVIOR_DISCREPANCY", report["scenarios"][0]["status"])
        self.assertFalse(report["scenarios"][0]["request"]["body_assertions_match"])
        raw = json.dumps(report)
        self.assertNotIn("private", raw)
        self.assertNotIn("<script>", raw)
        self.assertEqual("COMPLETED", report["scenarios"][0]["cleanup_status"])
        plan["scenarios"][0]["request"]["body_must_contain"] = [""]
        with self.assertRaisesRegex(ProductError, "BODY_ASSERTION_INVALID"):
            validate_plan(target, plan)


if __name__ == "__main__":
    unittest.main()

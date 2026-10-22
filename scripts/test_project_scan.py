"""폴더 통합 검사·미실행 이유·권한/예산 경계·서버 종료의 회귀 테스트. 실제 생성/외부 조회 없음."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.disposable import copy_workspace, validate_server
from localcode_review_mcp.project_scan import ProjectScans, acknowledge_scan, folder_config, markdown
from localcode_review_mcp.workspace import ProductConfig, ProductError, ProductStore, Snapshot, digest, save_json


class ProjectScanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "project"
        self.source.mkdir()
        (self.source / "Api.java").write_text("class Api {}", encoding="utf-8")
        self.cfg = ProductConfig(self.root / "config.json", {}, None, self.root / "results", {})
        save_json(self.cfg.path, {"version": 1, "projects": {}, "results_dir": str(self.cfg.results)})
        self.original_config = self.cfg.path.read_bytes()

    def prepared(self, endpoints=2):
        snapshot = Snapshot.read(self.source)
        rows = [{"endpoint_id": "ep-" + str(i), "http_method": "POST", "http_path": "/items/" + str(i), "mapping_status": "AST_LITERAL"}
                for i in range(endpoints)]
        identifier = folder_config(self.cfg, str(self.source))[1]
        return snapshot, {}, {"project_id": identifier, "snapshot": snapshot.metadata(), "snapshot_sha256": digest(snapshot.metadata()),
                              "support": "SUPPORTED_SUBSET", "support_reasons": [], "endpoints": rows}

    async def cves(self, config, project, online):
        return {"status": "PARTIAL", "report_id": "cve-test", "queries_sent": 0,
                "inventory": {"packages": [{"name": "example:lib", "version": "1"}], "coverage": "DECLARATIONS_ONLY", "unresolved": []},
                "packages": [{"status": "NOT_QUERIED_NO_CACHE", "vulnerabilities": None}]}

    def collected(self, config, project, endpoint, **kwargs):
        return {"collection_id": "collection-" + endpoint, "evidence": [{"id": "E001"}], "unresolved_calls": []}

    async def execute(self, endpoints=2, **limits):
        prepared = self.prepared(endpoints)
        with patch("localcode_review_mcp.project_scan.inventory", return_value=prepared), \
             patch("localcode_review_mcp.project_scan.collect", side_effect=self.collected), \
             patch("localcode_review_mcp.project_scan.scan_cves", side_effect=self.cves):
            jobs = ProjectScans(self.cfg)
            started = await jobs.start(str(self.source), **limits)
            await jobs.tasks[started["job_id"]]
            return jobs, jobs.report(started["job_id"])

    def test_folder_only_produces_report_without_registration_or_implicit_approvals(self):
        _, report = asyncio.run(self.execute())
        self.assertEqual("COMPLETED", report["execution_state"])
        self.assertEqual("PARTIAL", report["coverage_status"])
        self.assertEqual(2, len(report["endpoints"]))
        self.assertEqual("SKIPPED", report["checks"]["ai"]["status"])
        self.assertEqual("MODEL_AUTHORIZATION_REQUIRED", report["checks"]["ai"]["reason"])
        self.assertEqual("PARTIAL", report["checks"]["cve"]["status"])
        self.assertEqual("SKIPPED", report["checks"]["dynamic"]["status"])
        self.assertEqual("NOT_ASSESSED", report["security_verdict"])
        self.assertEqual(0, report["model_calls_sent"])
        self.assertEqual(self.original_config, self.cfg.path.read_bytes())
        self.assertTrue(Path(report["artifact_paths"]["markdown"]).is_file())
        self.assertFalse((self.cfg.results / "control/project-scan.lock").exists())

    def test_unsupported_languages_and_zero_packages_are_not_reported_clean(self):
        (self.source / "Api.java").unlink()
        (self.source / "app.py").write_text("print('example')", encoding="utf-8")
        async def empty(config, project, online):
            data = await self.cves(config, project, online)
            data["inventory"]["packages"] = []
            return data
        prepared = self.prepared(0)
        prepared[2].update(support="PARTIAL", support_reasons=["NO_JAVA_SOURCES"])
        async def check():
            with patch("localcode_review_mcp.project_scan.inventory", return_value=prepared), \
                 patch("localcode_review_mcp.project_scan.scan_cves", side_effect=empty):
                jobs = ProjectScans(self.cfg)
                started = await jobs.start(str(self.source))
                await jobs.tasks[started["job_id"]]
                return jobs.report(started["job_id"])
        report = asyncio.run(check())
        self.assertIn("Python", report["languages"]["unsupported_source"])
        self.assertEqual("UNSUPPORTED", report["checks"]["source"]["status"])
        self.assertEqual("NO_SUPPORTED_RESOLVED_MAVEN_PACKAGES", report["checks"]["cve"]["reason"])
        self.assertEqual("PARTIAL", report["coverage_status"])

    def test_explicit_endpoint_limit_and_collection_errors_remain_visible(self):
        _, report = asyncio.run(self.execute(endpoints=3, max_endpoints=1, max_ai_endpoints=0))
        self.assertEqual(2, report["checks"]["source"]["endpoints_omitted_by_limit"])
        self.assertEqual("PARTIAL", report["checks"]["source"]["status"])
        self.assertEqual("AI_ENDPOINT_LIMIT", report["endpoints"][0]["ai_skip_reason"])

    def test_source_failure_does_not_hide_cve_or_skip_reasons(self):
        async def check():
            with patch("localcode_review_mcp.project_scan.inventory", side_effect=ProductError("JAVA_BRIDGE_FAILED")), \
                 patch("localcode_review_mcp.project_scan.scan_cves", side_effect=self.cves):
                jobs = ProjectScans(self.cfg)
                start = await jobs.start(str(self.source))
                await jobs.tasks[start["job_id"]]
                return jobs.report(start["job_id"])
        report = asyncio.run(check())
        self.assertEqual("INCOMPLETE", report["checks"]["source"]["status"])
        self.assertEqual("cve-test", report["checks"]["cve"]["report_id"])
        self.assertEqual("COMPLETED", report["execution_state"])
        self.assertEqual("PARTIAL", report["coverage_status"])

    def test_ai_observations_are_sequential_and_failure_stops_later_generations(self):
        case = self
        sequence = []
        class FakeReviews:
            def __init__(self, config):
                self.tasks, self.states = {}, {}
                self.store = ProductStore(config.results)
            async def start(self, project, collection, policy):
                case.assertEqual("NOT_PROVIDED", policy)
                sequence.append(collection)
                identifier = self.store.create("review", {"kind": "endpoint-review"})
                async def execute():
                    self.states[identifier] = {"state": "FAILED", "request_sent": True, "remote_completion": "UNKNOWN", "reason": "MOCK_TIMEOUT"}
                self.tasks[identifier] = asyncio.create_task(execute())
                return {"job_id": identifier}
            def status(self, identifier):
                return self.states[identifier]
        with patch("localcode_review_mcp.project_scan.ai_permission", return_value=None), \
             patch("localcode_review_mcp.project_scan.ReviewJobs", FakeReviews):
            _, report = asyncio.run(self.execute(endpoints=3))
        self.assertEqual(1, len(sequence))
        self.assertEqual(1, report["model_calls_sent"])
        self.assertEqual(["FAILED", "SKIPPED", "SKIPPED"], [row["ai_status"] for row in report["endpoints"]])
        self.assertEqual("PARTIAL", report["checks"]["ai"]["status"])

    def test_successful_ai_children_are_in_report_without_semantic_approval(self):
        class FakeReviews:
            def __init__(self, config):
                self.tasks, self.states = {}, {}
                self.store = ProductStore(config.results)
            async def start(self, project, collection, policy):
                identifier = self.store.create("review", {"kind": "endpoint-review"})
                async def execute():
                    save_json(self.store.folder(identifier) / "report.json", {"observation": {"identity_assurance_status": "UNRESOLVED"},
                              "pipeline": {"verdict": "POLICY_UNDETERMINED"}, "semantic_review_status": "NOT_REVIEWED", "diagnostic_saved": False})
                    self.states[identifier] = {"state": "COMPLETED", "request_sent": True, "remote_completion": "COMPLETED"}
                self.tasks[identifier] = asyncio.create_task(execute())
                return {"job_id": identifier}
            def status(self, identifier):
                return self.states[identifier]
        with patch("localcode_review_mcp.project_scan.ai_permission", return_value=None), \
             patch("localcode_review_mcp.project_scan.ReviewJobs", FakeReviews):
            _, report = asyncio.run(self.execute(endpoints=2))
        self.assertEqual(2, report["checks"]["ai"]["completed"])
        self.assertEqual(2, report["model_calls_sent"])
        self.assertTrue(all(row["semantic_review_status"] == "NOT_REVIEWED" for row in report["endpoints"]))
        self.assertEqual("NOT_ASSESSED", report["security_verdict"])

    def test_dynamic_failure_keeps_child_report_reference_and_stops_owned_server(self):
        class FakeServer:
            def __init__(self, *args):
                self.metadata = {"started": True, "stopped": False}
            async def start(self):
                return self.metadata
            async def stop(self):
                self.metadata["stopped"] = True
        async def failed_http(*args):
            return {"report_id": "http-failure", "status": "INCOMPLETE", "scenarios": []}
        self.cfg.http_targets["test"] = {"base_url": "http://127.0.0.1:18080"}
        self.cfg.scan_profiles["test"] = {"project_root": str(self.source), "http_target_ids": ["test"], "disposable_server": {}}
        with patch("localcode_review_mcp.project_scan.DisposableServer", FakeServer), \
             patch("localcode_review_mcp.project_scan.run_http_checks", side_effect=failed_http):
            _, report = asyncio.run(self.execute(endpoints=0))
        self.assertEqual("INCOMPLETE", report["checks"]["dynamic"]["status"])
        self.assertEqual("http-failure", report["checks"]["dynamic"]["targets"][0]["report_id"])
        self.assertTrue(report["disposable_server"]["stopped"])

    def test_project_config_cannot_enable_execution_and_profile_is_root_bound(self):
        (self.source / "localcode-review.json").write_text('{"scan_profiles":{"evil":{"command":["arbitrary"]}}}', encoding="utf-8")
        self.cfg.scan_profiles["other"] = {"project_root": str(self.root / "different"), "disposable_server": {"command": ["arbitrary"]}}
        with patch("localcode_review_mcp.project_scan.DisposableServer") as server:
            _, report = asyncio.run(self.execute())
            server.assert_not_called()
        self.assertEqual("NO_OPERATOR_REGISTERED_SCAN_PROFILE", report["checks"]["dynamic"]["reason"])

    def test_cancel_before_start_releases_own_lock_and_reports_not_run(self):
        async def check():
            jobs = ProjectScans(self.cfg)
            started = await jobs.start(str(self.source))
            await jobs.cancel(started["job_id"])
            return jobs.report(started["job_id"])
        report = asyncio.run(check())
        self.assertEqual("CANCELLED", report["execution_state"])
        self.assertTrue(all(stage["status"] == "NOT_RUN" for stage in report["checks"].values()))
        self.assertFalse((self.cfg.results / "control/project-scan.lock").exists())

    def test_cancel_during_disposable_start_still_stops_server(self):
        async def check():
            entered = asyncio.Event()
            instances = []
            class FakeServer:
                def __init__(self, *args):
                    self.metadata = {"started": True, "stopped": False}
                    instances.append(self)
                async def start(self):
                    entered.set()
                    await asyncio.Future()
                async def stop(self):
                    self.metadata["stopped"] = True
            self.cfg.http_targets["test"] = {"base_url": "http://127.0.0.1:18080"}
            self.cfg.scan_profiles["test"] = {"project_root": str(self.source), "http_target_ids": ["test"], "disposable_server": {}}
            with patch("localcode_review_mcp.project_scan.inventory", return_value=self.prepared(0)), \
                 patch("localcode_review_mcp.project_scan.scan_cves", side_effect=self.cves), \
                 patch("localcode_review_mcp.project_scan.DisposableServer", FakeServer):
                jobs = ProjectScans(self.cfg)
                started = await jobs.start(str(self.source))
                await asyncio.wait_for(entered.wait(), 10)
                await jobs.cancel(started["job_id"])
                return jobs.report(started["job_id"]), instances
        report, instances = asyncio.run(check())
        self.assertEqual("CANCELLED", report["execution_state"])
        self.assertTrue(instances[0].metadata["stopped"])

    def test_restart_does_not_resume_or_release_unconfirmed_lock(self):
        async def create():
            jobs = ProjectScans(self.cfg)
            start = await jobs.start(str(self.source))
            await jobs.cancel(start["job_id"])
            return start["job_id"]
        identifier = asyncio.run(create())
        jobs = ProjectScans(self.cfg)
        folder = jobs.store.folder(identifier)
        state = load(folder / "status.json")
        state.update(state="RUNNING", owner_pid=99999999)
        save_json(folder / "status.json", state, replace=True)
        (self.cfg.results / "control/project-scan.lock").write_text(identifier, encoding="utf-8")
        with patch("localcode_review_mcp.project_scan.process_alive", return_value=False):
            self.assertEqual("INTERRUPTED", jobs.status(identifier)["state"])
        self.assertTrue((self.cfg.results / "control/project-scan.lock").exists())
        with self.assertRaises(ProductError):
            acknowledge_scan(self.cfg, identifier, False)
        approval = self.cfg.results / "control/model-authorization.json"
        save_json(approval, {"calls_consumed": 1})
        before = approval.read_bytes()
        acknowledge_scan(self.cfg, identifier, True)
        self.assertEqual(before, approval.read_bytes())

    def test_folder_path_and_result_boundaries(self):
        for path in ("relative", str(self.source / "Api.java")):
            with self.assertRaises((ProductError, OSError)):
                folder_config(self.cfg, path)
        self.cfg.results = self.source / "results"
        with self.assertRaisesRegex(ProductError, "RESULTS_MUST_BE_OUTSIDE"):
            folder_config(self.cfg, str(self.source))

    def test_unpinned_dirty_snapshot_can_be_checked_but_byte_changes_are_blocked(self):
        identity = {"commit": "a" * 40, "basis": "COMMIT_AND_WORKING_FILE_HASHES", "worktree": "DIRTY"}
        snapshot = Snapshot(self.source, identity, {"Api.java": (self.source / "Api.java").read_bytes()}, [])
        with patch("localcode_review_mcp.workspace.git_identity", return_value=identity) as git:
            snapshot.verify()
            git.assert_called_once_with(self.source)
        (self.source / "Api.java").write_text("class Api { int changed; }", encoding="utf-8")
        with patch("localcode_review_mcp.workspace.git_identity", return_value=identity):
            with self.assertRaisesRegex(ProductError, "SOURCE_CHANGED"):
                snapshot.verify()

    def test_markdown_treats_untrusted_endpoint_as_text_not_a_link(self):
        report = {"report_id": "scan-test", "execution_state": "COMPLETED", "coverage_status": "PARTIAL", "checks": {},
                  "endpoints": [{"http_method": "GET", "http_path": "/![external](https://example.invalid/image)"}],
                  "findings": [], "limitations": []}
        output = markdown(report)
        self.assertNotIn("![external](", output)
        self.assertIn("\\!\\[external\\]\\(", output)

    def test_disposable_copy_filters_sensitive_files_and_preserves_source(self):
        (self.source / ".env").write_text("secret", encoding="utf-8")
        (self.source / "private.key").write_text("secret", encoding="utf-8")
        (self.source / "application.yml").write_text("password: very-secret-value", encoding="utf-8")
        before = (self.source / "Api.java").read_bytes()
        copy = self.root / "copy"
        result = copy_workspace(self.source, copy)
        self.assertTrue((copy / "Api.java").exists())
        self.assertFalse((copy / ".env").exists())
        self.assertFalse((copy / "private.key").exists())
        self.assertFalse((copy / "application.yml").exists())
        self.assertEqual(before, (self.source / "Api.java").read_bytes())
        self.assertTrue(result["excluded"])

    def test_disposable_execution_requires_local_opt_in_and_matching_target(self):
        spec = {"project_root": str(self.source), "authorized_disposable_environment": True,
                "acknowledge_command_execution": True, "command": [sys.executable, "{project_copy}/server.py"],
                "base_url": "http://127.0.0.1:18080"}
        targets = [{"base_url": spec["base_url"], "authorized_disposable_environment": True}]
        validate_server(spec, self.source, targets)
        for changed in ({"acknowledge_command_execution": False}, {"base_url": "http://127.0.0.1:11434"},
                        {"command": ["python", "server.py"]}, {"project_root": str(self.root / "other")}):
            with self.assertRaises(ProductError):
                validate_server({**spec, **changed}, self.source, targets)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

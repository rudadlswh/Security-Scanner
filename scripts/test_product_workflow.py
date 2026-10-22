"""한글 기능 설명: 사용자 실행용 제품 경계·AST 수집·관찰·규칙·CVE·HTTP 계약 회귀 테스트.
실제 Ollama/OSV/HTTP 서버에는 요청하지 않는다. Java AST/규칙 검증은 prepareProductRuntime 후 활성화된다.
"""
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.collector import bridge, collect, inventory
from localcode_review_mcp.dependencies import dependency_inventory, scan_cves, summarize_vulnerability
from localcode_review_mcp.http_checks import pointer, run_http_checks, validate_path, validate_plan
from localcode_review_mcp.network import loopback_url
from localcode_review_mcp.observation import evaluate, validate_observation
from localcode_review_mcp.reviews import ReviewJobs, authorize_model
from localcode_review_mcp.token_budget import measure_input, MODEL_DIGEST, SERVER_VERSION
from localcode_review_mcp.workspace import ProductConfig, ProductError, ProductStore, REPO, Snapshot, digest, save_json


def observation():
    return {"observation_id": "ep-test", "authentication": "ENFORCED", "ownership": "NOT_FOUND", "admin_exception": "NOT_FOUND",
            "identity_binding": "NOT_REQUIRED", "enforcement_order": "BEFORE_MUTATION", "additional_restrictions": "NOT_FOUND",
            "evidence_ids": ["E001"], "protection_evidence_ids": ["E001"], "explanation": "검사한 경로에 소유자 조건을 발견하지 못했습니다."}


class ProductTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.config = ProductConfig(self.root / "localcode-review.json", {"demo": {"root": str(self.source)}},
                                    Path(os.environ["JAVA_HOME"]) if os.environ.get("JAVA_HOME") else None,
                                    self.root / "results", {"name": "qwen3.5:9b", "digest": "a" * 64})

    def test_large_input_uses_pinned_tokens_without_truncation_or_generation(self):
        request = {"model": "qwen3.5:9b", "messages": [{"role": "system", "content": "관찰"},
                   {"role": "user", "content": "코드" * 5000}], "format": {"type": "object"},
                   "options": {"num_predict": 2048, "num_ctx": 16384}, "think": False}
        before = digest(request)
        measured = {"local_rendered_input_tokens": 5000, "schema_separate_tokens": 100,
                    "required_server_version": SERVER_VERSION}
        with patch("localcode_review_mcp.token_budget.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(measured).encode(), stderr=b"")) as worker:
            result = measure_input(request, {"name": "qwen3.5:9b", "digest": MODEL_DIGEST})
        self.assertEqual(before, digest(request))
        self.assertEqual(8724, result["remaining_tokens"])
        self.assertEqual(5000, result["exact_local_token_count"])
        self.assertEqual(request, json.loads(worker.call_args.kwargs["input"]))
        self.assertNotIn("/api/chat", str(worker.call_args))
        with patch("localcode_review_mcp.token_budget.subprocess.run") as worker:
            with self.assertRaisesRegex(ProductError, "TOKENIZER_PROFILE_UNAVAILABLE"):
                measure_input(request, {"name": "qwen3.5:9b", "digest": "a" * 64})
            worker.assert_not_called()
        measured["local_rendered_input_tokens"] = 16000
        with patch("localcode_review_mcp.token_budget.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(measured).encode(), stderr=b"")):
            with self.assertRaisesRegex(ProductError, "CONTEXT_BUDGET_EXCEEDED"):
                measure_input(request, {"name": "qwen3.5:9b", "digest": MODEL_DIGEST})

    def test_tokenizer_server_mismatch_stops_before_charge_and_generation(self):
        async def check():
            identifier, snapshot = self.collection_fixture()
            authorize_model(self.config, calls=1, minutes=5)
            with patch("localcode_review_mcp.reviews.Snapshot.read", return_value=snapshot), patch.object(snapshot, "verify"), \
                 patch("localcode_review_mcp.reviews.measure_input", return_value={"exact_local_token_count": 100,
                       "required_server_version": SERVER_VERSION}), \
                 patch("localcode_review_mcp.reviews.access_boundary", return_value={}), \
                 patch("localcode_review_mcp.reviews.json_request", new_callable=AsyncMock, side_effect=[
                       {"models": [{"name": "qwen3.5:9b", "digest": "a" * 64}]}, {"version": "changed"}]) as request:
                jobs = ReviewJobs(self.config)
                started = await jobs.start("demo", identifier)
                await jobs.tasks[started["job_id"]]
                status = jobs.status(started["job_id"])
            self.assertFalse(status["request_sent"])
            self.assertEqual("TOKENIZER_SERVER_VERSION_MISMATCH", status["reason"])
            self.assertTrue(all(call.args[1] == "GET" for call in request.await_args_list))
            authorization = json.loads((self.config.results / "control/model-authorization.json").read_text())
            self.assertEqual(0, authorization["calls_consumed"])
        asyncio.run(check())

    def test_snapshot_excludes_secrets_and_detects_changes(self):
        (self.source / "Safe.java").write_text("class Safe {}", encoding="utf-8")
        (self.source / "Secret.java").write_text('class Secret { String password = "sensitive-value"; }', encoding="utf-8")
        (self.source / ".env").write_text("private", encoding="utf-8")
        snapshot = Snapshot.read(self.source)
        self.assertEqual({"Safe.java"}, set(snapshot.files))
        self.assertEqual("POTENTIAL_SECRET", snapshot.excluded[0]["reason"])
        (self.source / "Safe.java").write_text("class Safe { int changed; }", encoding="utf-8")
        with self.assertRaisesRegex(ProductError, "SOURCE_CHANGED"):
            snapshot.verify()

    def test_results_cannot_be_in_source_and_ids_are_not_paths(self):
        with self.assertRaises(ProductError):
            ProductConfig.from_data(self.config.path, {"projects": {"demo": {"root": str(self.source)}}, "results_dir": str(self.source / "results")})
        for identifier in ("../secret", "C:/secret", "", "report\n"):
            with self.assertRaises(ProductError):
                ProductStore(self.config.results).folder(identifier)

    def test_invalid_observation_missing_fields_or_evidence_is_rejected(self):
        raw = observation()
        self.assertEqual(raw, validate_observation(raw, "ep-test", {"E001"}, True))
        for update in ({"identity_binding": "WRONG"}, {"evidence_ids": ["E999"]}, {"protection_evidence_ids": ["E999"]}):
            with self.assertRaises(ProductError):
                validate_observation({**raw, **update}, "ep-test", {"E001"}, True)
        del raw["ownership"]
        with self.assertRaisesRegex(ProductError, "FORMAT_ERROR:ownership"):
            validate_observation(raw, "ep-test", {"E001"}, True)

    def test_correct_verdict_does_not_hide_wrong_observation(self):
        report = {"observation": observation(), "pipeline": {"verdict": "MATCHES_STATED_POLICY"}}
        expected = {"fields": {"ownership": "ENFORCED_ALL"}, "required_evidence_ids": ["E001", "E002"]}
        result = evaluate(expected, report)
        self.assertEqual("DISCONNECTED_RISK", result["classification"])
        self.assertEqual(["E002"], result["missing_required_evidence_ids"])
        self.assertFalse(result["preregistered_expected_matches"])

    def test_maven_properties_and_unresolved_managed_versions(self):
        (self.source / "pom.xml").write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><lib.version>1.2.3</lib.version></properties><dependencies>
          <dependency><groupId>example</groupId><artifactId>explicit</artifactId><version>${lib.version}</version></dependency>
          <dependency><groupId>example</groupId><artifactId>managed</artifactId></dependency>
        </dependencies></project>''', encoding="utf-8")
        result = dependency_inventory(self.config, "demo")
        self.assertEqual("1.2.3", result["packages"][0]["version"])
        self.assertTrue(result["unresolved"])
        self.assertFalse(result["target_build_executed"])

    def test_cyclonedx_transitive_components_and_unknown_ecosystems(self):
        path = self.root / "bom.json"
        save_json(path, {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:maven/org.example/transitive@2.3.4"}, {"purl": "pkg:npm/unsupported@1.0"}]})
        self.config.projects["demo"]["dependency_inventory"] = str(path)
        result = dependency_inventory(self.config, "demo")
        self.assertEqual("org.example:transitive", result["packages"][0]["name"])
        self.assertEqual("PROVIDED_COMPONENTS_ONLY", result["coverage"])
        self.assertTrue(result["unresolved"])

    def test_cve_no_cache_and_failed_lookup_are_not_clean(self):
        save_json(self.root / "resolved.json", {"packages": [{"name": "example:lib", "version": "1.0"}]})
        self.config.projects["demo"]["dependency_inventory"] = str(self.root / "resolved.json")
        result = asyncio.run(scan_cves(self.config, "demo", False))
        self.assertEqual("PARTIAL", result["status"])
        self.assertEqual("NOT_QUERIED_NO_CACHE", result["packages"][0]["status"])
        self.config.allow_osv_network = True
        import httpx
        with patch("localcode_review_mcp.dependencies._query_page", new_callable=AsyncMock, side_effect=httpx.ConnectError("offline")):
            result = asyncio.run(scan_cves(self.config, "demo", True))
        self.assertEqual("INCOMPLETE", result["packages"][0]["status"])
        self.assertIsNone(result["packages"][0]["vulnerabilities"])

    def test_fix_versions_are_filtered_to_matching_package(self):
        vuln = {"id": "GHSA-example", "aliases": ["CVE-2026-0001"], "affected": [
            {"package": {"ecosystem": "Maven", "name": "other:lib"}, "ranges": [{"events": [{"fixed": "99.0"}]}]},
            {"package": {"ecosystem": "Maven", "name": "example:lib"}, "ranges": [{"events": [{"fixed": "1.2"}]}]}]}
        result = summarize_vulnerability(vuln, {"ecosystem": "Maven", "name": "example:lib"})
        self.assertEqual(["1.2"], result["fixed_versions_from_matching_package"])
        self.assertEqual("NOT_TESTED", result["exploitability"])

    def test_loopback_and_request_boundaries(self):
        self.assertEqual("http://127.0.0.1:8080", loopback_url("http://127.0.0.1:8080/"))
        for url in ("http://localhost:8080", "http://0.0.0.0:8080", "https://example.com:443", "http://127.0.0.1:8080/other", "http://user:pass@127.0.0.1:8080"):
            with self.assertRaises(ProductError):
                loopback_url(url)
        for path in ("//example.com", "/a/%2e%2e/b", "/a\\b", "/x\r\nHeader: x"):
            with self.assertRaises(ProductError):
                validate_path(path, {path})
        self.assertEqual(False, pointer({"items": [{"exists": False}]}, "/items/0/exists"))

    def test_http_plan_requires_state_readback_cleanup_and_explicit_environment(self):
        plan = json.loads((REPO / "mcp/http-plan.example.json").read_text(encoding="utf-8"))
        target = {"base_url": "http://127.0.0.1:8080", "authorized_disposable_environment": True,
                  "allowed_paths": ["/test/fixtures/item", "/test/fixtures/item/state", "/api/items/lcr-disposable-001"],
                  "actors": {"observer": {}, "non_owner": {}}}
        validate_plan(target, plan)
        with self.assertRaises(ProductError):
            validate_plan({**target, "authorized_disposable_environment": False}, plan)
        del plan["scenarios"][0]["after"]
        with self.assertRaises(ProductError):
            validate_plan(target, plan)

    def test_model_authorization_is_explicit_bounded_and_cumulative(self):
        first = authorize_model(self.config, calls=1, minutes=5)
        self.assertEqual(0, first["calls_consumed"])
        first["calls_consumed"] = 1
        save_json(self.config.results / "control/model-authorization.json", first, replace=True)
        second = authorize_model(self.config, calls=2, minutes=5)
        self.assertEqual(1, second["prior_cumulative_calls"])
        with self.assertRaises(ProductError):
            authorize_model(self.config, calls=0, minutes=5)

    def test_restart_marks_interrupted_and_never_resends(self):
        store = ProductStore(self.config.results)
        identifier = store.create("review", {"kind": "endpoint-review"})
        save_json(store.folder(identifier) / "status.json", {"state": "RUNNING", "request_sent": True})
        jobs = ReviewJobs(self.config)
        status = jobs.status(identifier)
        self.assertEqual("INTERRUPTED", status["state"])
        self.assertEqual("UNKNOWN", status["remote_completion"])
        self.assertFalse(jobs.tasks)

    def collection_fixture(self):
        (self.source / "Api.java").write_text("class Api {}", encoding="utf-8")
        snapshot = Snapshot(self.source, {"commit": None, "basis": "FILE_HASHES", "worktree": "UNVERIFIED"}, {"Api.java": b"class Api {}"}, [])
        store = ProductStore(self.config.results)
        identifier = store.create("collection", {"kind": "collection", "project_id": "demo"})
        data = {"collection_id": identifier, "project_id": "demo", "endpoint": {"http_method": "DELETE", "http_path": "/items/1", "endpoint_id": "ep-test", "mapping_status": "AST_LITERAL"},
                "snapshot_sha256": digest(snapshot.metadata()), "evidence": [{"id": "E001", "path": "Api.java", "start": 1, "end": 1, "class_start": 1}],
                "edges": [], "unresolved_calls": [], "ledger": {}}
        data["collection_sha256"] = digest(data)
        save_json(store.folder(identifier) / "report.json", data)
        return identifier, snapshot

    def test_cancel_after_send_consumes_call_and_blocks_unknown_remote(self):
        async def check():
            identifier, snapshot = self.collection_fixture()
            authorize_model(self.config, calls=2, minutes=5)
            entered = asyncio.Event()
            async def request(client, method, url, **kwargs):
                if url.endswith("/api/tags"):
                    return {"models": [{"name": "qwen3.5:9b", "digest": "a" * 64}]}
                entered.set()
                await asyncio.Future()
            with patch("localcode_review_mcp.reviews.Snapshot.read", return_value=snapshot), patch.object(snapshot, "verify"), \
                 patch("localcode_review_mcp.reviews.access_boundary", return_value={}), patch("localcode_review_mcp.reviews.json_request", side_effect=request):
                jobs = ReviewJobs(self.config)
                started = await jobs.start("demo", identifier)
                await asyncio.wait_for(entered.wait(), timeout=5)
                status = await jobs.cancel(started["job_id"])
            self.assertEqual("CANCELLED", status["state"])
            self.assertEqual("UNKNOWN", status["remote_completion"])
            state = json.loads((self.config.results / "control/model-authorization.json").read_text())
            self.assertEqual(1, state["calls_consumed"])
            self.assertTrue(state["blocked"])
            self.assertTrue((self.config.results / "control/review.lock").exists())
        asyncio.run(check())

    def test_format_failure_is_not_retried_or_refunded(self):
        async def check():
            identifier, snapshot = self.collection_fixture()
            authorize_model(self.config, calls=2, minutes=5)
            response = {"done": True, "done_reason": "stop", "message": {"content": "{bad-json"}, "prompt_eval_count": 100}
            with patch("localcode_review_mcp.reviews.Snapshot.read", return_value=snapshot), patch.object(snapshot, "verify"), \
                 patch("localcode_review_mcp.reviews.access_boundary", return_value={}), \
                 patch("localcode_review_mcp.reviews.json_request", new_callable=AsyncMock, side_effect=[{"models": [{"name": "qwen3.5:9b", "digest": "a" * 64}]}, response]) as request:
                jobs = ReviewJobs(self.config)
                started = await jobs.start("demo", identifier)
                await jobs.tasks[started["job_id"]]
                status = jobs.status(started["job_id"])
            self.assertEqual(2, request.await_count)  # one tags read, one generation, no retry
            self.assertEqual("FAILED", status["state"])
            self.assertEqual("COMPLETED", status["remote_completion"])
            state = json.loads((self.config.results / "control/model-authorization.json").read_text())
            self.assertEqual(1, state["calls_consumed"])
            self.assertTrue(state["blocked"])
            self.assertFalse((self.config.results / "control/review.lock").exists())
        asyncio.run(check())

    def test_http_state_probe_catches_unauthorized_mutation_even_with_success_status(self):
        async def check():
            import httpx
            plan = json.loads((REPO / "mcp/http-plan.example.json").read_text(encoding="utf-8"))
            path = self.root / "plan.json"
            save_json(path, plan)
            self.config.http_targets["fixture"] = {"base_url": "http://127.0.0.1:8080", "authorized_disposable_environment": True,
                "plan_file": str(path), "allowed_paths": ["/test/fixtures/item", "/test/fixtures/item/state", "/api/items/lcr-disposable-001"],
                "actors": {"observer": {}, "non_owner": {}}}
            state = {"exists": False}
            def handler(request):
                if request.method == "POST":
                    state["exists"] = True
                    return httpx.Response(201, json={})
                if request.method == "DELETE":
                    state["exists"] = False  # deliberate broken authorization
                    return httpx.Response(204)
                return httpx.Response(200, json=state)
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            with patch("localcode_review_mcp.http_checks.httpx.AsyncClient", return_value=client), patch("localcode_review_mcp.http_checks.asyncio.sleep", new_callable=AsyncMock):
                report = await run_http_checks(self.config, "fixture")
            self.assertEqual("COMPLETED", report["status"])
            self.assertEqual("BEHAVIOR_DISCREPANCY", report["scenarios"][0]["status"])
            self.assertFalse(report["scenarios"][0]["after"]["state_matches"])
            self.assertEqual("http-expectations/2", report["evidence_contract"])
            self.assertEqual([403, 404], report["scenarios"][0]["request"]["expected_status_codes"])
            self.assertEqual({"value_visibility": "BOOLEAN_ONLY", "json_pointer": "/exists", "expected": True,
                              "actual": False, "actual_availability": "AVAILABLE"}, report["scenarios"][0]["after"]["state_probe"])
            self.assertEqual("COMPLETED", report["scenarios"][0]["cleanup_status"])
            self.assertEqual(6, report["requests_sent"])
        asyncio.run(check())


@unittest.skipUnless((REPO / "build/product/classes/dev/localcodereview/ProductBridge.class").exists() and os.environ.get("JAVA_HOME"), "prepareProductRuntime and JAVA_HOME required")
class JavaProductTest(ProductTest):
    def test_ast_preserves_inferred_types_as_unresolved_without_false_links(self):
        (self.source / "Api.java").write_text('''import org.springframework.web.bind.annotation.*;
@RestController
class Api {
  private Service service;
  @DeleteMapping("/inferred")
  void remove() {
    var service = factory();
    service.remove();
    java.util.List.of("x").forEach(value -> value.trim());
  }
  Service factory() { return null; }
}
class Service { void remove() {} }
''', encoding="utf-8")
        _, ast, info = inventory(self.config, "demo")
        api = next(row for row in ast["classes"] if row["name"] == "Api")
        method = next(row for row in api["methods"] if row["name"] == "remove")
        self.assertEqual("<UNRESOLVED_TYPE>", method["locals"]["service"])
        self.assertEqual("<UNRESOLVED_TYPE>", method["locals"]["value"])
        self.assertFalse(ast["errors"])
        result = collect(self.config, "demo", info["endpoints"][0]["endpoint_id"])
        self.assertNotIn("Service.remove", {row["symbol"] for row in result["evidence"]})
        self.assertTrue(any(row["receiver"] == "service" and row["method"] == "remove"
                            for row in result["unresolved_calls"]))

    def test_ast_only_follows_called_helper_and_captures_query_declaration(self):
        (self.source / "Api.java").write_text('''import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/items")
class Api {
  private Service service;
  @DeleteMapping("/{id}")
  void remove(long id) { service.remove(id, 7L); }
  void unusedOwnerHelper() { throw new SecurityException(); }
}
class Service {
  private Repo repo;
  void remove(long id, long userId) { repo.deleteByIdAndOwnerId(id, userId); }
}
interface Repo {
  @Query("delete from Item i where i.id = :id and i.owner.id = :ownerId")
  void deleteByIdAndOwnerId(long id, long ownerId);
}
''', encoding="utf-8")
        _, _, info = inventory(self.config, "demo")
        self.assertEqual("/items/{id}", info["endpoints"][0]["http_path"])
        result = collect(self.config, "demo", info["endpoints"][0]["endpoint_id"])
        symbols = {row["symbol"] for row in result["evidence"]}
        self.assertIn("Service.remove", symbols)
        self.assertIn("Repo.deleteByIdAndOwnerId", symbols)
        self.assertNotIn("Api.unusedOwnerHelper", symbols)

    def test_existing_java_rules_and_both_consistency_blocks(self):
        path = self.source / "Evidence.java"
        path.write_text("class Evidence {}", encoding="utf-8")
        ledger = {"endpoint": "DELETE /items/1", "commit": "test-snapshot", "artifacts": [{"id": "E001", "relativePath": "Evidence.java", "sha256": digest(path.read_bytes())}],
                  "areas": [{"area": area, "evidenceIds": ["E001"], "unresolvedLinks": []} for area in ("SECURITY", "PRINCIPAL", "CALL_CHAIN", "MUTATION", "PERSISTENCE", "RESTRICTIONS")], "unsupportedPaths": []}
        for identity, expected_gate in (("VERIFIED", "CONFLICT"), ("UNRESOLVED", "UNCERTAIN"), ("NOT_REQUIRED", "PASS")):
            raw = {**observation(), "identity_binding": identity}
            result = bridge(self.config, {"operation": "compare", "root": str(self.source), "observation": raw, "ledger": ledger, "policy": "authenticated_anyone"})
            self.assertEqual(expected_gate, result["gate_status"])
            self.assertEqual("MATCHES_STATED_POLICY" if expected_gate == "PASS" else "POLICY_UNDETERMINED", result["verdict"])


if __name__ == "__main__":
    unittest.main()

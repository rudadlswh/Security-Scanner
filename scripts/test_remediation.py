"""AI 해결 제안의 근거 연결·예산·원문OFF·실패·취소·통합 출력 검증. 실제 생성/외부 요청 없음."""
import asyncio
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.remediation import finding_context, generate, prepare_request, validate_advice
from localcode_review_mcp.remediation_compact import VERSION as CURRENT_REMEDIATION_VERSION
from localcode_review_mcp.project_scan import ProjectScans, markdown, reserve_remediation_call
from localcode_review_mcp.reviews import acknowledge_failure
from localcode_review_mcp.workspace import ProductConfig, ProductError, ProductStore, Snapshot, digest, load_json, save_json


def advice():
    cite = ["E-F001-H1"]
    return {"finding_id": "F001",
            "observed_evidence_ids": cite,
            "cause_hypotheses": [{"text": "삭제 경로의 소유자 검사가 빠졌을 가능성이 있습니다.", "evidence_ids": cite,
                                  "confirmation_needed": "서비스의 삭제 전 소유자 비교 경로를 확인합니다."}],
            "recommended_changes": [{"text": "인증 주체와 대상 소유자를 삭제 전에 비교하고 불일치면 차단합니다.",
                "scope": "OBSERVED_TARGET_ONLY", "focus": "RESOURCE_OWNERSHIP", "evidence_ids": cite,
                "ownership_check": {"caller_identity_verification": "서버 인증 계층이 검증한 현재 사용자를 가져올 방법을 확인합니다.",
                    "resource_owner_lookup": "요청 대상 리소스의 소유자 ID를 서버에서 조회할 경로를 확인합니다.",
                    "comparison_rule": "검증된 호출자 ID와 조회된 대상 소유자 ID가 다르면 변경 전에 거부합니다.",
                    "execution_order": "BEFORE_MUTATION",
                    "owner_source": "SERVER_AUTHORITATIVE_STORE",
                    "source_confirmation": "서버 원장에서 요청 대상 ID의 현재 소유자를 조회하는 경로와 신뢰된 호출자 확보 경로를 확인합니다.",
                    "owner_lookup_order": "BEFORE_MUTATION",
                    "caller_source": "SERVER_VERIFIED_PRINCIPAL",
                    "mismatch_action": "DENY_WITHOUT_MUTATION",
                    "lookup_failure_action": "DENY_WITHOUT_MUTATION"},
                "assumptions": ["이 경로의 소유자 전용 기대 조건을 책임자에게 확인합니다."]}],
            "policy_questions": [],
            "additional_checks": [{"text": "소유자 정상 요청과 익명 요청도 별도 확인합니다.", "evidence_ids": cite}],
            "cautions": ["소스와 정책을 확인한 뒤 적용해야 하며 제안은 미검토입니다."]}


def response(value):
    return {"contract_version": "security-remediation/11", "recommendations": value}


class RemediationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "project"
        self.source.mkdir()
        (self.source / "Api.java").write_text("class Api {}", encoding="utf-8")
        self.model = {"name": "qwen3.5:9b", "digest": "a" * 64, "base_url": "http://127.0.0.1:11434"}
        self.cfg = ProductConfig(self.root / "config.json", {"test": {"root": str(self.source)}}, None,
                                 self.root / "results", self.model)
        self.store = ProductStore(self.cfg.results)
        child = self.store.create("http", {"kind": "http-security"})
        save_json(self.store.folder(child) / "report.json", {"kind": "http-security", "target_id": "test", "scenarios": [{
            "id": "non-owner", "status": "BEHAVIOR_DISCREPANCY", "cleanup_status": "COMPLETED",
            "before": {"state_matches": True, "response_body": "DO_NOT_SEND", "expected_status_codes": [200],
                "state_probe": {"value_visibility": "BOOLEAN_ONLY", "json_pointer": "/exists", "expected": True, "actual": True, "actual_availability": "AVAILABLE"}},
            "request": {"method": "DELETE", "path": "/items/one", "actor": "non_owner", "status_code": 204,
                        "expected_status_codes": [403], "status_matches": False, "headers": {"Authorization": "DO_NOT_SEND"}},
            "after": {"state_matches": False, "expected_status_codes": [200],
                "state_probe": {"value_visibility": "BOOLEAN_ONLY", "json_pointer": "/exists", "expected": True, "actual": False, "actual_availability": "AVAILABLE"}}}]})
        self.report = {"report_id": "scan-test", "project_id": "test", "findings": [{"finding_id": "F001",
            "kind": "DYNAMIC_BEHAVIOR_DISCREPANCY", "target_id": "test", "basis": "CONFIGURED_HTTP_AND_STATE_EXPECTATIONS",
            "identifiers": ["non-owner"], "report_id": child}]}
        self.approval_path = self.cfg.results / "control/model-authorization.json"
        save_json(self.approval_path, {"model": self.model["name"], "digest": self.model["digest"], "calls_consumed": 0,
            "calls_cap": 2, "blocked": False, "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat(),
            "diagnostic_save": False})
        self.response = {"done": True, "done_reason": "stop", "prompt_eval_count": 250,
                         "message": {"content": json.dumps({"contract_version": CURRENT_REMEDIATION_VERSION, "recommendations": [{"finding_id": "F001", "evidence_ids": ["E-F001-H1"], "focus": "RESOURCE_OWNERSHIP"}]}, ensure_ascii=False)}}
        self.sent, self.posted = 0, 0
        self.stage = {}

    async def json_request(self, client, method, url, **kwargs):
        if method == "GET":
            return {"models": [self.model]}
        self.posted += 1
        return copy.deepcopy(self.response)

    def sent_callback(self):
        self.sent += 1

    async def run_generation(self, request=None, verify=lambda: None):
        with patch("localcode_review_mcp.remediation.json_request", side_effect=request or self.json_request), \
             patch("localcode_review_mcp.remediation.access_boundary", return_value={"listeners": ["127.0.0.1"]}), \
             patch("localcode_review_mcp.remediation.measure_input", return_value={"exact_local_token_count": 250}):
            await generate(self.cfg, self.report, self.stage, verify, self.sent_callback)

    def test_request_contains_only_confirmed_evidence_and_constrained_schema(self):
        items = finding_context(self.report, self.store)
        request = prepare_request(items, self.model)
        raw = json.dumps(request)
        self.assertNotIn("DO_NOT_SEND", raw)
        self.assertNotIn("source_code", raw)
        self.assertFalse(request["think"])
        self.assertEqual("object", request["format"]["type"])
        self.assertEqual(2048, request["options"]["num_predict"])
        self.assertEqual("F001", items[0]["finding_id"])

    def test_cve_context_preserves_branch_fix_candidates_without_new_version_claim(self):
        package = {"ecosystem": "Maven", "name": "example:library", "version": "1.0"}
        child = self.store.create("cve", {"kind": "dependency-cve"})
        save_json(self.store.folder(child) / "report.json", {"kind": "dependency-cve", "project_id": "test", "packages": [
            {"package": package, "vulnerability_groups": [{"identifiers": ["CVE-TEST"], "advisories": [
                {"id": "CVE-TEST", "fixed_versions_from_matching_package": ["1.1", "2.1"], "untrusted_extra": "DO_NOT_SEND"}]}]}]})
        self.report["findings"] = [{"finding_id": "F001", "kind": "DEPENDENCY_VERSION_MATCH", "basis": "VERSION_MATCH_NOT_EXPLOITABILITY",
            "identifiers": ["CVE-TEST"], "report_id": child, "package": package, "lookup_status": "CHECKED_CACHED"}]
        item = finding_context(self.report, self.store)[0]
        self.assertEqual(["1.1", "2.1"], item["advisories"][0]["fixed_versions_from_matching_package"])
        self.assertNotIn("DO_NOT_SEND", json.dumps(item))

    def test_unknown_duplicate_missing_and_extra_output_fields_are_rejected(self):
        valid = response([advice()])
        bad = [dict(valid, extra="patch"), response([advice(), advice()]), response([]),
               response([dict(advice(), finding_id="F002")]), response([dict(advice(), patch="automatic edit")])]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ProductError):
                validate_advice(json.dumps(value), {"F001"})
        with self.assertRaises(ProductError):
            validate_advice('{"recommendations":[],"recommendations":[]}', {"F001"})

    def test_sensitive_output_and_mismatched_child_are_blocked(self):
        with self.assertRaisesRegex(ProductError, "SENSITIVE_OUTPUT"):
            validate_advice(json.dumps(response([dict(advice(), cautions=["password: should-not-be-saved"])])), {"F001"})
        self.report["findings"][0]["target_id"] = "different"
        with self.assertRaisesRegex(ProductError, "EVIDENCE_MISMATCH"):
            finding_context(self.report, self.store)

    def test_success_consumes_one_shared_call_preserves_structured_advice_only(self):
        asyncio.run(self.run_generation())
        self.assertEqual("COMPLETED", self.stage["status"])
        self.assertEqual(1, load_json(self.approval_path)["calls_consumed"])
        self.assertEqual((1, 1), (self.sent, self.posted))
        self.assertFalse((self.cfg.results / "control/review.lock").exists())
        folder = self.store.folder(self.stage["report_id"])
        self.assertFalse((folder / "response.diagnostic.json").exists())
        result = load_json(folder / "report.json")
        self.assertEqual("NOT_REVIEWED", result["semantic_review_status"])
        self.assertFalse(result["recommendations"][0]["automatic_apply"])
        self.assertEqual(self.report["findings"][0]["report_id"], result["recommendations"][0]["evidence_report_id"])

    def test_timeout_blocks_next_calls_retains_lock_and_can_be_acknowledged_without_refund(self):
        async def failed(client, method, url, **kwargs):
            if method == "GET":
                return {"models": [self.model]}
            raise TimeoutError()
        asyncio.run(self.run_generation(failed))
        self.assertEqual("INCOMPLETE", self.stage["status"])
        self.assertEqual("UNKNOWN", self.stage["remote_completion"])
        self.assertTrue(load_json(self.approval_path)["blocked"])
        self.assertTrue((self.cfg.results / "control/review.lock").exists())
        ack = acknowledge_failure(self.cfg, self.stage["report_id"], True)
        self.assertEqual(0, ack["calls_refunded"])
        self.assertEqual(1, ack["calls_consumed"])

    def test_invalid_completed_response_blocks_budget_without_saving_recommendations(self):
        self.response["message"]["content"] = '{"recommendations":[]}'
        asyncio.run(self.run_generation())
        self.assertEqual("INCOMPLETE", self.stage["status"])
        self.assertEqual("COMPLETED", self.stage["remote_completion"])
        self.assertNotIn("recommendations", self.stage)
        self.assertTrue(load_json(self.approval_path)["blocked"])
        self.assertFalse((self.cfg.results / "control/review.lock").exists())

    def test_exhausted_authorization_does_not_send_or_consume(self):
        value = load_json(self.approval_path)
        value["calls_consumed"] = 2
        save_json(self.approval_path, value, replace=True)
        asyncio.run(self.run_generation())
        self.assertEqual((0, 0), (self.sent, self.posted))
        self.assertEqual(2, load_json(self.approval_path)["calls_consumed"])
        self.assertEqual("NOT_SENT", self.stage["remote_completion"])

    def test_digest_and_token_preflight_fail_before_consumption(self):
        async def mismatch(client, method, url, **kwargs):
            return {"models": [dict(self.model, digest="b" * 64)]}
        asyncio.run(self.run_generation(mismatch))
        self.assertEqual("INSTALLED_MODEL_DIGEST_MISMATCH", self.stage["reason"])
        self.assertEqual(0, self.sent)
        with patch("localcode_review_mcp.remediation.measure_input", side_effect=ProductError("CONTEXT_BUDGET_EXCEEDED")):
            asyncio.run(generate(self.cfg, self.report, self.stage, lambda: None, self.sent_callback))
        self.assertEqual("CONTEXT_BUDGET_EXCEEDED", self.stage["reason"])
        self.assertEqual(0, load_json(self.approval_path)["calls_consumed"])

    def test_cancel_after_transmission_retains_unknown_state(self):
        async def check():
            entered = asyncio.Event()
            async def waiting(client, method, url, **kwargs):
                if method == "GET":
                    return {"models": [self.model]}
                entered.set()
                await asyncio.Future()
            task = asyncio.create_task(self.run_generation(waiting))
            await asyncio.wait_for(entered.wait(), 5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        asyncio.run(check())
        self.assertEqual("UNKNOWN", self.stage["remote_completion"])
        self.assertEqual(1, load_json(self.approval_path)["calls_consumed"])
        self.assertTrue(load_json(self.approval_path)["blocked"])

    def test_thinking_and_token_delta_are_not_accepted_as_advice(self):
        self.response["message"]["thinking"] = "reasoning"
        asyncio.run(self.run_generation())
        self.assertEqual("THINKING_CONTRACT_VIOLATION", self.stage["reason"])
        self.response["message"].pop("thinking")
        value = load_json(self.approval_path)
        value["blocked"] = False
        save_json(self.approval_path, value, replace=True)
        self.response["prompt_eval_count"] = 300
        asyncio.run(self.run_generation())
        self.assertEqual("SERVER_INPUT_TOKEN_DELTA_EXCEEDED", self.stage["reason"])

    def test_last_call_reservation_and_markdown_escaping(self):
        self.assertFalse(reserve_remediation_call(self.cfg))
        value = load_json(self.approval_path)
        value["calls_consumed"] = 1
        save_json(self.approval_path, value, replace=True)
        self.assertTrue(reserve_remediation_call(self.cfg))
        row = dict(advice(), title="![image](https://example.invalid/pixel)", evidence_report_id="http-test")
        from localcode_review_mcp.remediation_contract import bind_advice
        bind_advice(row, finding_context(self.report, self.store)[0])
        report = dict(self.report, execution_state="COMPLETED", coverage_status="PARTIAL", endpoints=[], limitations=[],
                      checks={"remediation": {"status": "COMPLETED", "recommendations": [row]}})
        text = markdown(report)
        self.assertIn("AI 검토 제안", text)
        self.assertIn("AI의 추가 확인 제안", text)
        self.assertNotIn("![image](", text)

    def test_scan_without_findings_does_not_generate_remediation(self):
        snapshot = Snapshot.read(self.source)
        info = {"snapshot": snapshot.metadata(), "snapshot_sha256": digest(snapshot.metadata()),
                "support": "SUPPORTED_SUBSET", "support_reasons": [], "endpoints": []}
        async def cves(*args):
            return {"status": "COMPLETED_FOR_LISTED_PACKAGES", "report_id": "cve-test", "queries_sent": 0,
                    "inventory": {"packages": [], "coverage": "DECLARATIONS_ONLY", "unresolved": []}, "packages": []}
        async def run():
            with patch("localcode_review_mcp.project_scan.inventory", return_value=(snapshot, {}, info)), \
                 patch("localcode_review_mcp.project_scan.scan_cves", side_effect=cves), \
                 patch("localcode_review_mcp.project_scan.generate_remediation") as generation:
                jobs = ProjectScans(self.cfg)
                start = await jobs.start(str(self.source))
                await jobs.tasks[start["job_id"]]
                generation.assert_not_called()
                return jobs.report(start["job_id"])
        report = asyncio.run(run())
        self.assertEqual("NO_CONFIRMED_FINDINGS", report["checks"]["remediation"]["reason"])
        self.assertEqual(0, report["model_calls_sent"])

    def test_single_scan_cve_uses_fixed_guidance_without_consuming_reserved_call(self):
        value = load_json(self.approval_path)
        value["calls_cap"] = 1
        save_json(self.approval_path, value, replace=True)
        snapshot = Snapshot.read(self.source)
        endpoint = {"endpoint_id": "ep-test", "http_method": "DELETE", "http_path": "/items/one", "mapping_status": "AST_LITERAL"}
        info = {"snapshot": snapshot.metadata(), "snapshot_sha256": digest(snapshot.metadata()),
                "support": "SUPPORTED_SUBSET", "support_reasons": [], "endpoints": [endpoint]}
        package = {"ecosystem": "Maven", "name": "example:library", "version": "1.0"}
        child = self.store.create("cve", {"kind": "dependency-cve"})
        cve = {"kind": "dependency-cve", "project_id": "test", "status": "COMPLETED_FOR_LISTED_PACKAGES",
               "report_id": child, "queries_sent": 0, "inventory": {"packages": [package], "coverage": "PROVIDED", "unresolved": []},
               "packages": [{"package": package, "status": "CHECKED_CACHED", "vulnerability_groups": [
                   {"identifiers": ["CVE-TEST"], "advisories": [{"id": "CVE-TEST", "fixed_versions_from_matching_package": ["1.1"]}]}]}]}
        save_json(self.store.folder(child) / "report.json", cve)
        cve_advice = advice()
        cve_advice["observed_evidence_ids"] = ["E-F001-C1"]
        for key in ("cause_hypotheses", "recommended_changes"):
            for entry in cve_advice[key]:
                entry["evidence_ids"] = ["E-F001-C1"]
        for change in cve_advice["recommended_changes"]:
            change.update(focus="DEPENDENCY_UPDATE", ownership_check=None)
        cve_advice["additional_checks"] = [{"text": "제공된 수정 버전 후보의 호환성과 회귀를 확인합니다.", "evidence_ids": ["E-F001-C1"]}]
        self.response["message"]["content"] = json.dumps(response([cve_advice]), ensure_ascii=False)
        async def cv(*args):
            return cve
        async def run():
            with patch("localcode_review_mcp.project_scan.inventory", return_value=(snapshot, {}, info)), \
                 patch("localcode_review_mcp.project_scan.collect", return_value={"collection_id": "collection-test", "evidence": [], "unresolved_calls": []}), \
                 patch("localcode_review_mcp.project_scan.scan_cves", side_effect=cv), \
                 patch("localcode_review_mcp.remediation.json_request", side_effect=self.json_request), \
                 patch("localcode_review_mcp.remediation.access_boundary", return_value={}), \
                 patch("localcode_review_mcp.remediation.measure_input", return_value={"exact_local_token_count": 250}):
                jobs = ProjectScans(self.cfg)
                start = await jobs.start(str(self.source))
                await jobs.tasks[start["job_id"]]
                return jobs.report(start["job_id"]), jobs.store.folder(start["job_id"]) / "report.md"
        report, path = asyncio.run(run())
        self.assertEqual("MODEL_CALL_RESERVED_FOR_REMEDIATION", report["endpoints"][0]["ai_skip_reason"])
        self.assertEqual(0, report["model_calls_sent"])
        self.assertEqual(0, self.posted)
        self.assertEqual("COMPLETED", report["checks"]["remediation"]["status"])
        self.assertEqual("F001", report["checks"]["remediation"]["recommendations"][0]["finding_id"])
        self.assertIn("의존성 버전 영향 일치", path.read_text(encoding="utf-8"))
        self.assertEqual("NOT_ASSESSED", report["security_verdict"])
        self.assertFalse((self.cfg.results / "control/project-scan.lock").exists())


if __name__ == "__main__":
    unittest.main()

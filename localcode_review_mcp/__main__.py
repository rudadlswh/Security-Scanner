"""한글 기능 설명: 제품 설정·조사·수집·로컬 실행 승인·결과 대조의 명령행 진입점."""
from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
from pathlib import Path
import sys

from .collector import collect, inventory
from .dependencies import dependency_inventory, scan_cves
from .http_checks import acknowledge_http, run_http_checks
from .observation import evaluate
from .reviews import ReviewJobs, acknowledge_failure, authorize_model, authorize_scope, preflight_review
from .project_scan import ProjectScans, acknowledge_scan
from .fix_verification import FixVerifications
from .workspace import ProductConfig, ProductError, ProductStore, REPO, load_json, save_json
from .assurance import freeze_benchmark, run_benchmark, validate_source_proposal, record_review
from .audit import record_audit_review
from .audit_verifier import authorize_verifier, verify_candidates, acknowledge_verifier
from .reviews import SourceReviewJobs


def main():
    parser = argparse.ArgumentParser(description="LocalCode Review project workflow (product/1)")
    parser.add_argument("--config", type=Path, default=REPO / "localcode-review.json")
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("configure", help="프로젝트 경로와 JDK를 로컬 설정에 등록")
    configure.add_argument("--project", required=True)
    configure.add_argument("--root", type=Path, required=True)
    configure.add_argument("--jdk", type=Path)
    configure.add_argument("--commit")
    configure.add_argument("--model")
    configure.add_argument("--digest")
    commands.add_parser("doctor", help="설정과 빌드 산출물 진단; 네트워크 요청 없음")
    freeze = commands.add_parser('freeze-benchmark', help='새 평가 계획·기대값·소스 해시 사전 고정')
    freeze.add_argument('--plan',type=Path,required=True);freeze.add_argument('--output',type=Path,required=True)
    bench = commands.add_parser('benchmark', help='고정한 외부/자체 사례의 수집·검색 기준선 측정; 생성 없음')
    bench.add_argument('--frozen',type=Path,required=True)
    proposal = commands.add_parser('validate-source-proposal', help='저장된 AI 소스 원인 가설의 근거 연결 검증; 의미 승인이 아님')
    proposal.add_argument('collection_id');proposal.add_argument('--proposal',type=Path,required=True)
    analyze = commands.add_parser('analyze-source',help='명시 로컬 승인·진단 저장·예산으로 소스 원인 가설 1회; 자동 적용 없음')
    analyze.add_argument('project_id');analyze.add_argument('collection_id')
    review = commands.add_parser('record-independent-review', help='독립 검토자의 로컬 선언·해시·사례별 판정 저장')
    review.add_argument('report_id');review.add_argument('--review',type=Path,required=True)
    audit = commands.add_parser('record-audit-review', help='소스·검토 해시에 묶인 범위/후보 판정 로컬 선언 저장; 원래 보고서 불변')
    audit.add_argument('report_id');audit.add_argument('--review',type=Path,required=True)
    verifier_grant = commands.add_parser('authorize-audit-verifier', help='특정 검사 보고서의 검증 전용 신규 승인; 기존 예산 불변')
    verifier_grant.add_argument('report_id');verifier_grant.add_argument('--calls',type=int,required=True);verifier_grant.add_argument('--minutes',type=int,required=True)
    verifier = commands.add_parser('verify-audit-candidates', help='별도 모델과 전용 승인으로 소스 후보 검토; 자동 확정 없음')
    verifier.add_argument('report_id');verifier.add_argument('grant_id')
    verifier_ack = commands.add_parser('acknowledge-audit-failure', help='원격 유휴 확인 후 검증 잠금 해제; 호출 환급 없음')
    verifier_ack.add_argument('grant_id');verifier_ack.add_argument('--remote-idle-confirmed',action='store_true',required=True)
    fix = commands.add_parser("verify-fix", help="승인된 프로필의 복사본 수정·빌드·전후 검사; 원본 변경 없음")
    fix.add_argument("project_path")
    scan = commands.add_parser("scan", help="폴더 하나의 승인된 검사와 통합 보고서 실행; 완료까지 대기")
    scan.add_argument("project_path")
    scan.add_argument("--max-endpoints", type=int, default=100)
    scan.add_argument("--max-ai-endpoints", type=int, default=20)
    scan.add_argument("--no-remediation", action="store_true", help="AI 해결방안 단계를 생략")
    for name in ("scan-status", "scan-report"):
        item = commands.add_parser(name)
        item.add_argument("job_id")
    scan_ack = commands.add_parser("acknowledge-scan", help="중단된 일회용 프로세스/데이터 확인 후 통합 잠금만 해제")
    scan_ack.add_argument("job_id")
    scan_ack.add_argument("--processes-stopped-and-cleanup-confirmed", action="store_true", required=True)
    for name in ("inspect", "dependencies", "cves"):
        command = commands.add_parser(name)
        command.add_argument("project_id")
        if name == "cves":
            command.add_argument("--online", action="store_true")
    collection = commands.add_parser("collect")
    collection.add_argument("project_id")
    collection.add_argument("endpoint_id")
    preflight = commands.add_parser("preflight", help="로컬 입력 길이 실측; 생성·네트워크·예산 변경 없음")
    preflight.add_argument("project_id")
    preflight.add_argument("collection_id")
    authorization = commands.add_parser("authorize-model", help="이후 실제 생성에 쓸 새 제품 예산 등록")
    authorization.add_argument("--calls", type=int, required=True)
    authorization.add_argument("--minutes", type=int, required=True)
    authorization.add_argument("--diagnostic", action="store_true", help="로컬 요청/응답 원문 진단 저장 명시 허용")
    scope = commands.add_parser("confirm-scope")
    scope.add_argument("collection_id")
    scope.add_argument("--file", type=Path, required=True)
    review = commands.add_parser("review")
    review.add_argument("project_id")
    review.add_argument("collection_id")
    review.add_argument("--policy", choices=["NOT_PROVIDED", "owner_only", "owner_or_admin", "authenticated_anyone"], default="NOT_PROVIDED")
    status = commands.add_parser("status")
    status.add_argument("job_id")
    report = commands.add_parser("report")
    report.add_argument("report_id")
    grading = commands.add_parser("evaluate")
    grading.add_argument("report_id")
    grading.add_argument("--expected", type=Path, required=True)
    acknowledgement = commands.add_parser("acknowledge-model-failure")
    acknowledgement.add_argument("job_id")
    acknowledgement.add_argument("--remote-idle-confirmed", action="store_true", required=True)
    http = commands.add_parser("http-check")
    http.add_argument("target_id")
    acknowledge = commands.add_parser("acknowledge-http")
    acknowledge.add_argument("report_id")
    acknowledge.add_argument("--cleanup-and-idle-confirmed", action="store_true", required=True)
    args = parser.parse_args()
    try:
        if args.command == "configure":
            data = load_json(args.config) if args.config.exists() else {"version": 1, "projects": {}, "model": {}, "http_targets": {}, "allow_osv_network": False}
            project = data.setdefault("projects", {}).setdefault(args.project, {})
            project["root"] = str(args.root.expanduser().resolve(strict=True))
            if args.commit:
                project["commit"] = args.commit
            if args.jdk:
                data["jdk"] = str(args.jdk.expanduser().resolve(strict=True))
            if args.model:
                data.setdefault("model", {})["name"] = args.model
            if args.digest:
                data.setdefault("model", {})["digest"] = args.digest
            data.setdefault("model", {}).setdefault("base_url", "http://127.0.0.1:11434")
            # Validate before replacing an existing config; preserve a local backup.
            ProductConfig.from_data(args.config, data)
            if args.config.exists():
                import time
                backup = args.config.with_name(args.config.name + ".backup-" + str(time.time_ns()))
                with backup.open("xb") as stream:
                    stream.write(args.config.read_bytes())
            save_json(args.config, data, replace=True)
            result = {"configured_project": args.project, "configuration_file": str(args.config.resolve()), "network_calls": 0, "model_calls": 0}
        else:
            cfg = ProductConfig.read(args.config)
            store = ProductStore(cfg.results)
            if args.command == "doctor":
                result = {"configuration_exists": args.config.is_file(), "projects": list(cfg.projects), "python": sys.version.split()[0],
                          "dependencies": {name: importlib.metadata.version(name) for name in ("mcp", "pydantic", "httpx")},
                          "jdk_configured": cfg.jdk is not None, "java_exists": bool(cfg.jdk and (cfg.jdk / "bin" / ("java.exe" if sys.platform == "win32" else "java")).exists()),
                          "product_bridge_built": (REPO / "build/product/classes/dev/localcodereview/ProductBridge.class").exists(),
                          "results_directory": str(cfg.results), "network_calls": 0, "model_calls": 0}
            elif args.command == "inspect":
                result = inventory(cfg, args.project_id)[2]
            elif args.command == 'freeze-benchmark':
                result = freeze_benchmark(cfg,load_json(args.plan),args.output)
            elif args.command == 'benchmark':
                result = run_benchmark(cfg,load_json(args.frozen))
            elif args.command == 'validate-source-proposal':
                result = validate_source_proposal(cfg,args.collection_id,load_json(args.proposal))
            elif args.command == 'analyze-source':
                async def analyze_source():
                    jobs=SourceReviewJobs(cfg);started=await jobs.start(args.project_id,args.collection_id)
                    await jobs.tasks[started['job_id']]
                    return jobs.status(started['job_id'])
                result=asyncio.run(analyze_source())
            elif args.command == 'record-independent-review':
                result = record_review(cfg,args.report_id,load_json(args.review))
            elif args.command == 'record-audit-review':
                result = record_audit_review(cfg,args.report_id,load_json(args.review))
            elif args.command == 'authorize-audit-verifier':
                result = authorize_verifier(cfg,args.report_id,args.calls,args.minutes)
            elif args.command == 'verify-audit-candidates':
                result = asyncio.run(verify_candidates(cfg,args.report_id,args.grant_id))
            elif args.command == 'acknowledge-audit-failure':
                result = acknowledge_verifier(cfg,args.grant_id,args.remote_idle_confirmed)
            elif args.command == "scan":
                async def scan_folder():
                    jobs = ProjectScans(cfg)
                    started = await jobs.start(args.project_path, args.max_endpoints, args.max_ai_endpoints, not args.no_remediation)
                    print(json.dumps(started), file=sys.stderr, flush=True)
                    await jobs.tasks[started["job_id"]]
                    return jobs.report(started["job_id"])
                result = asyncio.run(scan_folder())
            elif args.command == "verify-fix":
                async def verify_copy():
                    jobs = FixVerifications(cfg)
                    started = await jobs.start(args.project_path)
                    print(json.dumps(started), file=sys.stderr, flush=True)
                    await jobs.tasks[started["job_id"]]
                    return jobs.status(started["job_id"])
                result = asyncio.run(verify_copy())
            elif args.command == "scan-status":
                result = ProjectScans(cfg).status(args.job_id)
            elif args.command == "scan-report":
                result = ProjectScans(cfg).report(args.job_id)
            elif args.command == "acknowledge-scan":
                result = acknowledge_scan(cfg, args.job_id, args.processes_stopped_and_cleanup_confirmed)
            elif args.command == "collect":
                result = collect(cfg, args.project_id, args.endpoint_id)
            elif args.command == "preflight":
                result = preflight_review(cfg, args.project_id, args.collection_id)
            elif args.command == "dependencies":
                result = dependency_inventory(cfg, args.project_id)
            elif args.command == "cves":
                result = asyncio.run(scan_cves(cfg, args.project_id, args.online))
            elif args.command == "authorize-model":
                result = authorize_model(cfg, calls=args.calls, minutes=args.minutes, diagnostic=args.diagnostic)
            elif args.command == "confirm-scope":
                result = authorize_scope(cfg, args.collection_id, load_json(args.file))
            elif args.command == "review":
                async def run():
                    jobs = ReviewJobs(cfg)
                    started = await jobs.start(args.project_id, args.collection_id, args.policy)
                    print(json.dumps(started), file=sys.stderr, flush=True)
                    await jobs.tasks[started["job_id"]]
                    return jobs.status(started["job_id"])
                result = asyncio.run(run())
            elif args.command == "status":
                result = ReviewJobs(cfg).status(args.job_id)
            elif args.command == "report":
                result = store.read(args.report_id)
            elif args.command == "evaluate":
                result = evaluate(load_json(args.expected), store.read(args.report_id))
            elif args.command == "acknowledge-model-failure":
                result = acknowledge_failure(cfg, args.job_id, args.remote_idle_confirmed)
            elif args.command == "http-check":
                result = asyncio.run(run_http_checks(cfg, args.target_id))
            elif args.command == "acknowledge-http":
                result = acknowledge_http(cfg, args.report_id, args.cleanup_and_idle_confirmed)
            else:
                raise ProductError("UNKNOWN_COMMAND")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.command == "verify-fix" and (result.get("state") != "COMPLETED" or result.get("verification") != "MATCHES_FROZEN_CHECKS"):
            return 2
        return 0
    except (ProductError, OSError, ValueError, KeyError) as error:
        print(json.dumps({"status": "INCOMPLETE", "error": str(error) if isinstance(error, ProductError) else type(error).__name__}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())

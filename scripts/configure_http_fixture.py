"""한글 기능 설명: 사용자 테스트용 HTTP/SQLite 예제를 제품 설정에 등록한다. 서버/검사는 실행하지 않는다."""
import argparse
import copy
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.workspace import ProductConfig, REPO, load_json, save_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=REPO / "localcode-review.json")
    parser.add_argument("--unsafe", action="store_true", help="의도한 결함을 재현하는 예제 경로 등록")
    args = parser.parse_args()
    config = load_json(args.config) if args.config.exists() else {"version": 1, "projects": {}, "model": {}}
    cfg = ProductConfig.from_data(args.config, config)
    plan = copy.deepcopy(load_json(REPO / "mcp/http-plan.example.json"))
    target_id = "fixture-unsafe" if args.unsafe else "fixture-safe"
    if args.unsafe:
        plan["scenarios"][0]["request"]["path"] = "/api/unsafe/items/lcr-disposable-001"
    target = load_json(REPO / "mcp/http-target.example.json")
    plan_path = cfg.results / "http-fixture-plans" / (target_id + "-" + str(time.time_ns()) + ".json")
    save_json(plan_path, plan)
    target["plan_file"] = str(plan_path)
    config.setdefault("http_targets", {})[target_id] = target
    if args.config.exists():
        backup = args.config.with_name(args.config.name + ".backup-" + str(time.time_ns()))
        with backup.open("xb") as stream:
            stream.write(args.config.read_bytes())
    save_json(args.config, config, replace=True)
    print("Configured " + target_id + "; start tools/http-fixture/server.py separately. No requests sent.")


if __name__ == "__main__":
    main()

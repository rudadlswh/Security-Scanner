# [한글 기능 설명]
# 기능: 지정한 합성 예제의 직접 실행과 JDK 보안 공지 버전 대조를 수행한다.
# 시작점/입력: --target/--jdk/--output; 해시로 고정한 Java 두 파일.
# 이어지는 기능: 소스 복사 → javac → 기존 테스트/SecurityProbe → jdeps → Oracle 공지 → report.json.
# 주의: 예제 전용이다. 범용 HTTP DAST/SCA나 CVE 악용 검증이 아니며 모델을 호출하지 않는다.

"""Fixture-only dynamic checks + Oracle advisory version matching; no LLM or generic DAST.

Only the two previously authored, hash-pinned files may execute. No target build
scripts/plugins are run; target files remain read-only. Third-party SCA is not
implemented: this fixture has no external dependencies. Runtime CVE matches are
version matches from ONE dated vendor advisory, not proof of exploitability.
"""
import argparse
import datetime as dt
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import urllib.request

SOURCE_HASHES = {
    "ReviewSample.java": "e370d7e8b6b0319db25a185b4b5f6fffcacc3722364851f14afae9c35d02e29f",
    "ReviewSampleTest.java": "d4eb5d4fbadfecdc8eff409242517dd95d63cef5d14fc9a3aa5c16a97aefcba7",
}
ADVISORY = "https://www.oracle.com/security-alerts/cpuapr2026.html"
REPO = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Rows(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = [], None, None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []

    def handle_data(self, text):
        if self.cell is not None:
            self.cell.append(text)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row, self.cell = None, None


def advisory_matches(html, version):
    parser = Rows()
    parser.feed(html)
    matches = []
    for row in parser.rows:
        if len(row) < 4 or not re.fullmatch(r"CVE-\d{4}-\d+", row[0]):
            continue
        if "Oracle Java SE" not in [p.strip() for p in row[1].split(",")]:
            continue
        affected = next((cell for cell in row if "Oracle Java SE:" in cell), "")
        java_only = affected.split("Oracle Java SE:")[-1].split(";")[0]
        if version not in re.findall(r"(?<![\w.])\d+\.\d+\.\d+(?![\w.])", java_only):
            continue
        matches.append({"id": row[0], "component": row[2], "version": version,
                        "status": "VENDOR_AFFECTED_VERSION_MATCH",
                        "exploitability_in_sample": "NOT_DEMONSTRATED",
                        "source": ADVISORY})
    return matches


def run(command, output, name, cwd):
    result = subprocess.run([str(x) for x in command], cwd=cwd,
                            capture_output=True, timeout=60)
    (output / (name + ".stdout.txt")).write_bytes(result.stdout)
    (output / (name + ".stderr.txt")).write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f"{name} failed: exit={result.returncode}; see saved stderr")
    return result.stdout.decode("utf-8", errors="replace")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--target", required=True, type=Path)
    cli.add_argument("--jdk", required=True, type=Path)
    cli.add_argument("--output", required=True, type=Path)
    cli.add_argument("--skip-runtime-cves", action="store_true",
                     help="Run local behavior/dependency checks without fetching the Oracle advisory")
    args = cli.parse_args()
    target, output = args.target.resolve(), args.output.resolve()
    if output == target or target in output.parents:
        raise ValueError("Output must be outside the read-only target")
    snapshots = {name: (target / name).read_bytes() for name in SOURCE_HASHES}
    for name, data in snapshots.items():
        if sha(data) != SOURCE_HASHES[name]:
            raise ValueError(f"Unsupported/changed fixture: {name}; no execution")
    output.mkdir(parents=True, exist_ok=False)
    sources, classes = output / "sources", output / "classes"
    sources.mkdir()
    classes.mkdir()
    for name, data in snapshots.items():
        (sources / name).write_bytes(data)
    probe = REPO / "tools/review-sample/SecurityProbe.java"
    (sources / probe.name).write_bytes(probe.read_bytes())
    java, javac, jdeps = [args.jdk / "bin" / (name + ".exe") for name in ("java", "javac", "jdeps")]
    release = dict(line.split("=", 1) for line in (args.jdk / "release").read_text().splitlines() if "=" in line)
    version, vendor = json.loads(release["JAVA_VERSION"]), json.loads(release["IMPLEMENTOR"])
    run([java, "-version"], output, "java-version", output)
    run([javac, "-encoding", "UTF-8", "-proc:none", "-Xlint:all", "-classpath", classes,
         "-sourcepath", sources, "-d", classes, *sorted(sources.glob("*.java"))], output, "compile", output)
    tests = run([java, "-cp", classes, "ReviewSampleTest"], output, "regression", output)
    probe_text = run([java, "-cp", classes, "SecurityProbe"], output, "dynamic", output)
    scenarios = [json.loads(line) for line in probe_text.splitlines() if line.strip()]
    if len(scenarios) != 8 or "RESULT: 8 passed, 0 failed" not in tests:
        raise RuntimeError("Unexpected fixture/probe output")
    for row in scenarios:
        expected = {"owner": "DELETED", "non_owner": "DENIED", "anonymous": "DENIED", "missing": "NOT_FOUND"}[row["actor"]]
        row["owner_only_expected"] = expected
        row["policy_matches"] = row["outcome"] == expected
    findings = [row for row in scenarios if not row["policy_matches"]]
    deps = run([jdeps, "-verbose:class", "-filter:none", "-classpath", classes, classes], output, "jdeps", output)
    manifests = [str(p.relative_to(target)) for p in target.rglob("*") if p.is_file() and
                 (p.name in {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "package.json"}
                  or p.suffix.lower() in {".jar", ".war"})]
    dependency_status = "NO_EXTERNAL_DEPENDENCIES_IN_PINNED_FIXTURE"
    if manifests or any("not found" in line for line in deps.splitlines()):
        dependency_status = "UNRESOLVED_DEPENDENCY_INVENTORY"
    runtime = {"vendor": vendor, "version": version, "source": ADVISORY,
               "coverage": "April 2026 Oracle Java SE matrix only; not a comprehensive/current CVE database"}
    # MCP 기본 호출은 로컬 검사만 수행한다. 공지 조회는 별도 선택 시에만 실행한다.
    if args.skip_runtime_cves:
        runtime.update(status="SKIPPED_BY_REQUEST", matches=[])
    else:
        try:
            if vendor != "Oracle Corporation":
                raise ValueError("Vendor differs; Oracle advisory matching not applicable")
            request = urllib.request.Request(ADVISORY, headers={"User-Agent": "LocalCodeReview-fixture-check/1"})
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.url != ADVISORY:
                    raise ValueError("Unexpected advisory redirect")
                raw = response.read(4_000_001)
            if len(raw) > 4_000_000:
                raise ValueError("Advisory too large")
            html = raw.decode("utf-8")
            if "Oracle Java SE Risk Matrix" not in html:
                raise ValueError("Advisory layout not recognized")
            runtime.update(status="VENDOR_ADVISORY_CHECKED", fetched_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                           advisory_sha256=sha(raw), matches=advisory_matches(html, version))
            if version == "17.0.18" and not runtime["matches"]:
                raise ValueError("Expected affected rows absent; do not interpret as clean")
        except Exception as error:
            runtime.update(status="INCOMPLETE", error=type(error).__name__ + ": " + str(error))
    unchanged = all((target / name).read_bytes() == data for name, data in snapshots.items())
    report = {"tool": "LocalCode Review fixture security adapter/1", "target": str(target),
              "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "target_sha256": SOURCE_HASHES, "target_unchanged": unchanged,
              "model_calls": 0, "http_DAST": "NOT_APPLICABLE_NO_HTTP_SERVER",
              "regression": {"passed": 8, "failed": 0, "includes_deliberate_flaw_reproduction": True},
              "dynamic": {"method": "Direct execution of copied original Java methods; trusted Caller fixture",
                          "scenarios": scenarios, "policy_violations": findings, "finding_count": len(findings)},
              "dependency_CVE": {"status": dependency_status, "external_dependencies": [],
                                 "manifest_or_archive_files": manifests, "generic_SCA_scanner": False},
              "runtime_CVE": runtime,
              "limits": ["Known synthetic fixture only; no generic project runner or HTTP DAST.",
                         "Method-level authorization reproduction, not identity-provider validation.",
                         "JDK affected-version matches do not establish reachable exploits in this sample.",
                         "No modifications to frozen experiments, model budget or target sources."]}
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output / "report.json"), "dynamic_findings": len(findings),
                      "runtime_CVE_status": runtime["status"], "runtime_version_matches": len(runtime.get("matches", [])),
                      "target_unchanged": unchanged}))
    return 0 if (unchanged and runtime["status"] in {"VENDOR_ADVISORY_CHECKED", "SKIPPED_BY_REQUEST"}
                 and dependency_status == "NO_EXTERNAL_DEPENDENCIES_IN_PINNED_FIXTURE") else 2


if __name__ == "__main__":
    raise SystemExit(main())

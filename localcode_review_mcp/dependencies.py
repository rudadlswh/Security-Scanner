"""한글 기능 설명: 빌드 실행 없는 Maven/Gradle/잠금/SBOM 목록과 OSV 버전 영향 조회."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import time
from urllib.parse import unquote
import xml.etree.ElementTree as ET

import httpx

from .workspace import ProductConfig, ProductError, ProductStore, Snapshot, digest, inside, load_json, now, save_json

OSV_QUERY = "https://api.osv.dev/v1/query"
EXACT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,119}\Z")
COORDINATE = re.compile(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+\Z")


def verify_resolved_build(root: Path, data: dict, snapshot: Snapshot) -> dict:
    """해결된 runtime 목록을 소스·빌드 산출물·실제 JAR 바이트에 연결한다. 빌드를 실행하지 않는다."""
    build = data.get("build", {})
    if not isinstance(build, dict):
        raise ProductError("RESOLVED_INVENTORY_BUILD_INVALID")
    inputs = build.get("inputs")
    if build.get("resolved") is not True or build.get("configuration") != "runtimeClasspath" or not isinstance(inputs, dict) or not inputs:
        raise ProductError("RESOLVED_INVENTORY_BUILD_BINDING_REQUIRED")
    expected_inputs = {p: digest(raw) for p, raw in snapshot.files.items()}
    if inputs != expected_inputs:
        raise ProductError("RESOLVED_INVENTORY_SOURCE_MISMATCH")
    paths = set()
    total = 0
    def check(relative, expected):
        nonlocal total
        if not isinstance(relative, str) or not relative or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ProductError("RESOLVED_INVENTORY_HASH_REQUIRED")
        path = inside(root, relative)
        if not path.is_file():
            raise ProductError("RESOLVED_INVENTORY_ARTIFACT_MISMATCH")
        total += path.stat().st_size
        if total > 536_870_912:
            raise ProductError("RESOLVED_INVENTORY_ARTIFACT_BUDGET")
        if path.stat().st_size > 134_217_728 or digest(path.read_bytes()) != expected:
            raise ProductError("RESOLVED_INVENTORY_ARTIFACT_MISMATCH")
        paths.add(relative)
    check(build.get("artifact"), build.get("sha256"))
    for item in data.get("packages", []):
        check(item.get("runtime_path"), item.get("sha256"))
    if len(paths) != len(data.get("packages", [])) + 1:
        raise ProductError("RESOLVED_INVENTORY_DUPLICATE_ARTIFACT")
    runtime_dir = build.get("runtime_directory")
    if not isinstance(runtime_dir, str):
        raise ProductError("RESOLVED_INVENTORY_RUNTIME_DIRECTORY_REQUIRED")
    directory = inside(root, runtime_dir)
    actual = {p.relative_to(root).as_posix() for p in directory.rglob("*.jar")}
    declared = {item["runtime_path"] for item in data["packages"]}
    if not actual or actual != declared:
        raise ProductError("RESOLVED_INVENTORY_RUNTIME_SET_MISMATCH")
    return {"artifact": build["artifact"], "sha256": build["sha256"], "source_inputs_verified": len(inputs),
            "runtime_jars_verified": len(declared), "configuration": "runtimeClasspath",
            "completeness_basis": "OPERATOR_EXPORTER_AND_EXACT_RUNTIME_DIRECTORY", "deployed_build_verified": False}


def dependency_inventory(config: ProductConfig, project_id: str) -> dict:
    root, settings = config.project(project_id)
    snapshot = Snapshot.read(root, settings.get("commit"))
    packages, unresolved, sources = {}, [], []

    def add(name, version, source, basis, scope="UNKNOWN"):
        if not isinstance(name, str) or not COORDINATE.fullmatch(name):
            unresolved.append({"source": source, "reason": "PACKAGE_COORDINATE_UNRESOLVED"})
            return
        if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version) or version.upper() in {"LATEST", "RELEASE"} or "+" in version:
            unresolved.append({"package": name, "source": source, "reason": "EXACT_VERSION_UNRESOLVED"})
            return
        key = (name, version)
        row = packages.setdefault(key, {"ecosystem": "Maven", "name": name, "version": version, "sources": [], "bases": [], "scope": scope})
        row["sources"].append(source)
        if basis not in row["bases"]:
            row["bases"].append(basis)

    for relative, raw in snapshot.files.items():
        name = Path(relative).name
        if name not in {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}:
            continue
        text = raw.decode("utf-8-sig")
        sources.append({"path": relative, "sha256": digest(raw)})
        if name == "pom.xml":
            if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
                raise ProductError("XML_ENTITIES_NOT_ALLOWED")
            try:
                document = ET.fromstring(text)
            except ET.ParseError:
                unresolved.append({"source": relative, "reason": "POM_XML_INVALID"})
                continue
            ns = {"m": document.tag.split("}")[0].strip("{")} if "}" in document.tag else {}
            prefix = "m:" if ns else ""
            properties = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in document.findall(prefix + "properties/*", ns)}

            def get(node, field):
                value = node.findtext(prefix + field, "", ns).strip()
                for _ in range(10):
                    updated = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m[1], m[0]), value)
                    if updated == value:
                        break
                    value = updated
                return value
            for dependency in document.findall(prefix + "dependencies/" + prefix + "dependency", ns):
                add(get(dependency, "groupId") + ":" + get(dependency, "artifactId"), get(dependency, "version"), relative, "DECLARED_DIRECT_NOT_RESOLVED", get(dependency, "scope") or "compile")
            if document.find(prefix + "parent", ns) is not None or document.find(prefix + "dependencyManagement", ns) is not None:
                unresolved.append({"source": relative, "reason": "PARENT_OR_BOM_REQUIRES_RESOLVED_INVENTORY"})
        elif name.startswith("build.gradle"):
            literal_count = 0
            for match in re.finditer(r"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]", text):
                literal_count += 1
                add(match[2] + ":" + match[3], match[4], relative, "GRADLE_LITERAL_DECLARATION_NOT_RESOLVED", match[1])
            unresolved.append({"source": relative, "reason": "GRADLE_DECLARATIONS_DO_NOT_RESOLVE_BOMS_TRANSITIVES_OR_DYNAMIC_DSL", "literal_coordinates": literal_count})
        else:
            for line in text.splitlines():
                match = re.fullmatch(r"([^:#\s]+):([^:\s]+):([^=\s]+)=(.*)", line)
                if match:
                    add(match[1] + ":" + match[2], match[3], relative, "GRADLE_LOCKFILE", match[4])
    external = settings.get("dependency_inventory")
    build_binding, declaration_limits = None, []
    if external:
        # Only the operator-configured file is opened, never a model-supplied arbitrary path.
        path = Path(external).expanduser().resolve(strict=True)
        with path.open("rb") as stream:
            raw = stream.read(4_194_305)
        if len(raw) > 4_194_304:
            raise ProductError("DEPENDENCY_INVENTORY_SIZE_LIMIT")
        data = load_json(path)
        sources.append({"path": "operator-provided-inventory", "sha256": digest(raw)})
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            for item in data.get("components", []):
                purl = item.get("purl", "")
                match = re.fullmatch(r"pkg:maven/([^/]+)/([^@?#]+)(?:@([^?#]+))?(?:\?[^#]*)?(?:#.*)?", purl)
                if match:
                    add(unquote(match[1]) + ":" + unquote(match[2]), unquote(match[3] or item.get("version", "")), "operator-provided-inventory", "CYCLONEDX_COMPONENT")
                else:
                    unresolved.append({"source": "operator-provided-inventory", "reason": "NON_MAVEN_OR_UNSUPPORTED_PURL"})
        elif isinstance(data, dict) and isinstance(data.get("packages"), list):
            if len(data["packages"]) > 10_000 or any(not isinstance(item, dict) for item in data["packages"]):
                raise ProductError("DEPENDENCY_INVENTORY_PACKAGE_LIST_INVALID")
            if data.get("format") == "lcr-resolved-inventory/1":
                build_binding = verify_resolved_build(root, data, snapshot)
                declaration_limits = unresolved
                packages, unresolved = {}, []
            for item in data["packages"]:
                if item.get("ecosystem", "Maven") != "Maven":
                    unresolved.append({"reason": "ECOSYSTEM_UNSUPPORTED"})
                    continue
                add(item.get("name"), item.get("version"), "operator-provided-inventory", "OPERATOR_RESOLVED_INVENTORY", item.get("scope", "UNKNOWN"))
        else:
            raise ProductError("DEPENDENCY_INVENTORY_FORMAT_UNSUPPORTED")
        if path.read_bytes() != raw:
            raise ProductError("DEPENDENCY_INVENTORY_CHANGED")
    snapshot.verify()
    return {"project_id": project_id, "packages": list(packages.values()), "unresolved": unresolved, "sources": sources,
            "coverage": "RESOLVED_RUNTIME_WITH_HASH_BINDING" if build_binding else "PROVIDED_COMPONENTS_ONLY" if external else "DECLARATIONS_ONLY_TRANSITIVES_INCOMPLETE",
            "build_binding": build_binding, "declaration_limits_superseded_for_runtime": declaration_limits,
            "snapshot_sha256": digest(snapshot.metadata()), "target_build_executed": False, "model_calls": 0}


def summarize_vulnerability(vulnerability: dict, package: dict) -> dict:
    if not isinstance(vulnerability.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", vulnerability["id"]):
        raise ProductError("OSV_VULNERABILITY_ID_INVALID")
    fixes = set()
    for affected in vulnerability.get("affected", []):
        identity = affected.get("package", {})
        if identity.get("ecosystem") != package["ecosystem"] or identity.get("name") != package["name"]:
            continue
        for affected_range in affected.get("ranges", []):
            for event in affected_range.get("events", []):
                if "fixed" in event:
                    fixes.add(event["fixed"])
    return {"id": vulnerability["id"], "aliases": sorted(set(vulnerability.get("aliases", []))),
            "modified": vulnerability.get("modified"), "published": vulnerability.get("published"),
            "fixed_versions_from_matching_package": sorted(fixes),
            "fix_selection": "CHECK_BRANCH_AND_DEPENDENCY_COMPATIBILITY", "impact": "OSV_REPORTED_VERSION_MATCH",
            "exploitability": "NOT_TESTED", "source": "https://osv.dev/vulnerability/" + vulnerability["id"]}


async def _query_page(client: httpx.AsyncClient, payload: dict) -> dict:
    async with client.stream("POST", OSV_QUERY, json=payload) as response:
        response.raise_for_status()
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            raw.extend(chunk)
            if len(raw) > 4_194_304:
                raise ProductError("OSV_RESPONSE_SIZE_LIMIT")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
        raise ProductError("OSV_RESPONSE_FORMAT_INVALID")
    return data


async def scan_cves(config: ProductConfig, project_id: str, online: bool = False) -> dict:
    inventory = await asyncio.to_thread(dependency_inventory, config, project_id)
    if online and not config.allow_osv_network:
        raise ProductError("OSV_NETWORK_DISABLED: enable allow_osv_network in local configuration")
    cache = config.results / "osv-cache"
    cache.mkdir(parents=True, exist_ok=True)
    rows, deadline, requests_sent = [], time.monotonic() + 120, 0
    async with httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False) as client:
        for package in inventory["packages"][:100]:
            key = digest({k: package[k] for k in ("ecosystem", "name", "version")})
            path = cache / (key + ".json")
            try:
                if online:
                    vulnerabilities, page, seen_pages = [], None, set()
                    for _ in range(5):
                        if time.monotonic() >= deadline or requests_sent >= 100:
                            raise ProductError("OSV_QUERY_BUDGET_EXHAUSTED")
                        payload = {"package": {"ecosystem": package["ecosystem"], "name": package["name"]}, "version": package["version"]}
                        if page:
                            payload["page_token"] = page
                        requests_sent += 1
                        data = await asyncio.wait_for(_query_page(client, payload), timeout=min(25, deadline - time.monotonic()))
                        vulnerabilities.extend(data.get("vulns", []))
                        if len(vulnerabilities) > 1000:
                            raise ProductError("OSV_VULNERABILITY_COUNT_LIMIT")
                        page = data.get("next_page_token")
                        if not page:
                            break
                        if page in seen_pages:
                            raise ProductError("OSV_PAGINATION_LOOP")
                        seen_pages.add(page)
                    else:
                        raise ProductError("OSV_PAGINATION_LIMIT")
                    cached = {"query": {k: package[k] for k in ("ecosystem", "name", "version")}, "fetched_at": now(), "vulnerabilities": vulnerabilities}
                    if len(json.dumps(cached).encode("utf-8")) > 4_194_304:
                        raise ProductError("OSV_CACHE_SIZE_LIMIT")
                    save_json(path, cached, replace=True)
                    status = "CHECKED_ONLINE"
                elif path.exists():
                    cached = load_json(path)
                    import datetime as dt
                    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(cached["fetched_at"])
                    status = "CHECKED_CACHED" if age.total_seconds() <= 86_400 else "STALE_CACHE_NOT_CURRENT"
                else:
                    rows.append({"package": package, "status": "NOT_QUERIED_NO_CACHE", "vulnerabilities": None})
                    continue
                assert cached["query"] == {k: package[k] for k in ("ecosystem", "name", "version")}
                matches = [summarize_vulnerability(v, package) for v in cached["vulnerabilities"] if not v.get("withdrawn")]
                # Alias equivalence merges duplicate advisories within a package without discarding the source IDs.
                groups = []
                for match in matches:
                    identities = {match["id"], *match["aliases"]}
                    overlapping = [group for group in groups if identities.intersection(group["identifiers"])]
                    merged = {"identifiers": sorted(identities), "advisories": [match]}
                    for group in overlapping:
                        merged["identifiers"] = sorted(set(merged["identifiers"]) | set(group["identifiers"]))
                        merged["advisories"].extend(group["advisories"])
                        groups.remove(group)
                    groups.append(merged)
                rows.append({"package": package, "status": status, "fetched_at": cached["fetched_at"], "vulnerability_groups": groups,
                             "no_known_match_in_this_query": not groups, "comprehensive_clean_result": False})
            except (httpx.HTTPError, ValueError, KeyError, TypeError, OSError, AssertionError, TimeoutError) as error:
                rows.append({"package": package, "status": "INCOMPLETE", "error_code": str(error) if isinstance(error, ProductError) else type(error).__name__, "vulnerabilities": None})
    incomplete = any(row["status"] not in {"CHECKED_ONLINE", "CHECKED_CACHED"} for row in rows) or len(inventory["packages"]) > 100 or bool(inventory["unresolved"])
    report = {"kind": "dependency-cve", "project_id": project_id, "recorded_at": now(), "status": "PARTIAL" if incomplete else "COMPLETED_FOR_LISTED_PACKAGES",
              "inventory": inventory, "packages": rows, "package_limit": 100, "queries_sent": requests_sent,
              "source": OSV_QUERY, "runtime_JDK_CVE": "USE_SEPARATE_RUNTIME_ADVISORY_CHECK", "model_calls": 0,
              "limits": ["Version matches do not establish exploitability.", "SBOM and resolved inventories must match the deployed build."]}
    store = ProductStore(config.results)
    identifier = store.create("cve", {"kind": "dependency-cve", "project_id": project_id})
    report["report_id"] = identifier
    save_json(store.folder(identifier) / "report.json", report)
    return report

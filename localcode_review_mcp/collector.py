"""한글 기능 설명: Java AST 메타데이터로 엔드포인트와 제한된 선언 기반 호출 관계를 수집한다."""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import re
import subprocess

from .workspace import ProductConfig, ProductError, ProductStore, REPO, Snapshot, digest

MAPPINGS = {name + "Mapping": name.upper() for name in ("Get", "Post", "Put", "Patch", "Delete")}
AREAS = ("SECURITY", "PRINCIPAL", "CALL_CHAIN", "MUTATION", "PERSISTENCE", "RESTRICTIONS")


def bridge(config: ProductConfig, value: dict) -> dict:
    from .provenance import execution_receipt
    execution_receipt()
    classes = REPO / "build/product/classes"
    if not (classes / "dev/localcodereview/ProductBridge.class").is_file():
        raise ProductError("PRODUCT_RUNTIME_NOT_BUILT: run gradlew prepareProductRuntime")
    receipt_path=REPO/'build/product/build-receipt.json'
    if receipt_path.exists():
        from .workspace import load_json, inside
        receipt=load_json(receipt_path)
        for relative,expected in {**receipt['inputs'],**receipt['outputs']}.items():
            if digest(inside(REPO,relative).read_bytes())!=expected:
                raise ProductError('PRODUCT_RUNTIME_BUILD_BINDING_MISMATCH')
    classpath = os.pathsep.join([str(classes), str(REPO / "build/product/lib/*")])
    try:
        result = subprocess.run([str(config.java()), "-Xmx384m", "-cp", classpath, "dev.localcodereview.ProductBridge"],
                                input=json.dumps(value, ensure_ascii=False).encode("utf-8"), capture_output=True,
                                timeout=120, cwd=REPO, stdin=None)
    except subprocess.TimeoutExpired:
        raise ProductError("JAVA_BRIDGE_TIMEOUT") from None
    if len(result.stdout) > 20 * 1_048_576:
        raise ProductError("JAVA_BRIDGE_OUTPUT_LIMIT")
    if result.returncode:
        # 원본 코드·경로·예외 메시지를 노출하지 않고 Java 표준 예외 종류만 진단에 남긴다.
        failure = re.search(r'(?:Exception in thread "[^"\r\n]*" |Caused by: )(java\.[A-Za-z0-9_$.]+(?:Exception|Error))\b',
                            result.stderr.decode("utf-8", errors="replace"))
        kind = failure.group(1) if failure else "UNCLASSIFIED"
        raise ProductError(f"JAVA_BRIDGE_FAILED: exit={result.returncode}, kind={kind}; check JDK17 and prepareProductRuntime")
    return json.loads(result.stdout)


def annotation_name(cls: dict, annotation: dict) -> str:
    name = annotation["name"]
    if "." in name:
        return name
    exact = [entry for entry in cls["imports"] if entry.endswith("." + name)]
    if len(exact) == 1:
        return exact[0]
    if "org.springframework.web.bind.annotation.*" in cls["imports"] and name in {*MAPPINGS, "RequestMapping", "RestController"}:
        return "org.springframework.web.bind.annotation." + name
    return name


def mappings(cls: dict, annotations: list) -> list[tuple[list[str], list[str]]]:
    result = []
    for annotation in annotations:
        qualified = annotation_name(cls, annotation)
        if not qualified.startswith("org.springframework.web.bind.annotation."):
            continue
        name = qualified.rsplit(".", 1)[-1]
        if name not in {*MAPPINGS, "RequestMapping"}:
            continue
        values = annotation["values"]
        paths = values.get("path", values.get("value", [""]))
        methods = [MAPPINGS[name]] if name in MAPPINGS else [x.rsplit(".", 1)[-1] for x in values.get("method", ["ANY"])]
        result.append((methods, paths))
    return result


def discover(ast: dict) -> list[dict]:
    result = []
    for cls in ast["classes"]:
        controller = any(annotation_name(cls, a) in {"org.springframework.web.bind.annotation.RestController", "org.springframework.stereotype.Controller"} for a in cls["annotations"])
        if not controller:
            continue
        bases = mappings(cls, cls["annotations"]) or [(["ANY"], [""])]
        for method in cls["methods"]:
            for (base_methods, prefixes), (verbs, suffixes) in itertools.product(bases, mappings(cls, method["annotations"])):
                for verb, prefix, suffix in itertools.product(verbs, prefixes, suffixes):
                    if len(result) >= 5000:
                        raise ProductError("ENDPOINT_ENUMERATION_LIMIT")
                    path = "/" + "/".join(x.strip("/") for x in (prefix, suffix) if x.strip("/"))
                    unresolved = "<UNRESOLVED_EXPRESSION>" in path or "${" in path or "#{" in path or base_methods != ["ANY"]
                    key = {"class": cls["qualified_name"], "method": method["name"], "arity": method["arity"], "verb": verb, "path": path, "line": method["start"]}
                    result.append({"endpoint_id": "ep-" + digest(key)[:20], "http_method": verb, "http_path": path,
                                   "class": cls["qualified_name"], "method": method["name"], "arity": method["arity"],
                                   "file": cls["path"], "start": method["start"], "end": method["end"],
                                   "mapping_status": "UNRESOLVED" if unresolved or verb == "ANY" else "AST_LITERAL",
                                   "class_method_constraints": base_methods})
    return sorted(result, key=lambda row: (row["http_path"], row["http_method"], row["class"], row["start"]))


def inventory(config: ProductConfig, project_id: str) -> tuple[Snapshot, dict, dict]:
    root, project = config.project(project_id)
    snapshot = Snapshot.read(root, project.get("commit"))
    java_files = [name for name in snapshot.files if name.endswith(".java")]
    ast = bridge(config, {"operation": "parse", "root": str(root), "files": java_files}) if java_files else {"classes": [], "errors": []}
    snapshot.verify()
    reasons = []
    kotlin = any(p.endswith(".kt") for p in snapshot.files)
    poms = [p for p in snapshot.files if p.endswith("pom.xml")]
    text = "\n".join(v.decode("utf-8-sig") for p, v in snapshot.files.items() if p.endswith(("gradle", "gradle.kts", "pom.xml")))
    if kotlin:
        reasons.append("KOTLIN_OUT_OF_SCOPE")
    if len(poms) > 1 or "<modules>" in text or re.search(r"(?m)^\s*include\s*\(?", text):
        reasons.append("MULTI_MODULE_OUT_OF_SCOPE")
    if "webflux" in text.lower():
        reasons.append("WEBFLUX_OUT_OF_SCOPE")
    if "mybatis" in text.lower():
        reasons.append("MYBATIS_XML_OUT_OF_SCOPE")
    if ast["errors"]:
        reasons.append("JAVA_PARSE_ERRORS")
    if not java_files:
        reasons.append("NO_JAVA_SOURCES")
    if snapshot.excluded:
        reasons.append("EXCLUDED_SOURCE_OR_LINKS")
    result = {"project_id": project_id, "snapshot": snapshot.metadata(), "snapshot_sha256": digest(snapshot.metadata()),
              "support": "PARTIAL" if reasons else "SUPPORTED_SUBSET", "support_reasons": reasons,
              "parser": ast.get("parser"), "parser_runtime": ast.get("runtime"), "class_count": len(ast["classes"]),
              "endpoints": discover(ast), "limitations": ["DECLARATION_BASED_TYPE_LINKING_NOT_FULL_CLASSPATH_RESOLUTION", "DEPLOYMENT_CONFIG_NOT_PROVEN"]}
    return snapshot, ast, result


def _bare(value: str) -> str:
    return re.sub(r"<.*>|\[\]|\?", "", value).strip()


def declared_types(name: str, context: dict, classes: list[dict]) -> list[dict]:
    name = _bare(name)
    possible = {name, (context["package"] + "." if context["package"] else "") + name}
    possible.update(x for x in context["imports"] if x.endswith("." + name))
    possible.update(x[:-1] + name for x in context["imports"] if x.endswith(".*"))
    direct = [c for c in classes if c["qualified_name"] in possible]
    if len(direct) != 1:
        return []
    return direct


def ancestors(cls, classes, seen=None):
    seen = set() if seen is None else set(seen)
    if cls['qualified_name'] in seen:
        return []
    seen.add(cls['qualified_name'])
    result = []
    for parent in cls['parents']:
        for target in declared_types(parent, cls, classes):
            result.append(target)
            result.extend(ancestors(target, classes, seen))
    return result


def resolve_type(name: str, context: dict, classes: list[dict]) -> list[dict]:
    direct = declared_types(name, context, classes)
    if len(direct) != 1 or direct[0]['kind'] != 'INTERFACE':
        return direct
    implementations = [c for c in classes if c['kind'] == 'CLASS' and
                       any(p['qualified_name'] == direct[0]['qualified_name'] for p in ancestors(c, classes))]
    return implementations if len(implementations) == 1 else direct


def method_targets(candidates, call, classes):
    destinations = []
    for cls in candidates:
        levels, seen = [cls], set()
        signatures = set()
        while levels:
            following = []
            for owner in levels:
                if owner['qualified_name'] in seen: continue
                seen.add(owner['qualified_name'])
                for member in owner['methods']:
                    signature = (member['name'], tuple(member.get('parameter_types', member['parameters'].values())))
                    if signature in signatures: continue
                    if member['name'] == call['name'] and (call['arity'] == -1 or member['arity'] == call['arity']):
                        destinations.append((owner, member))
                        signatures.add(signature)
                for parent in owner['parents']: following.extend(declared_types(parent, owner, classes))
            levels = following
    if len(destinations) > 1 and call.get('argument_types') is not None:
        def qualified(t, owner):
            if any(mark in t for mark in ('<','[','?')):return t
            if t in {'String','Object','Boolean','Integer','Long'}:return 'java.lang.'+t
            resolved = declared_types(t, owner, classes)
            return resolved[0]['qualified_name'] if len(resolved)==1 else t
        # Exact declared types only; unknown/boxing/varargs remain unresolved.
        destinations = [(c,m) for c,m in destinations if '<UNKNOWN>' not in call['argument_types'] and
            [qualified(t,c) for t in m.get('parameter_types',m['parameters'].values())] ==
            [qualified(t,call.get('_context',c)) for t in call['argument_types']]]
    return destinations


def collect(config: ProductConfig, project_id: str, endpoint_id: str, *, prepared=None) -> dict:
    # 통합 검사는 한 번 파싱한 스냅샷을 공유한다. 기존 단건 호출과 해시 검증은 유지한다.
    snapshot, ast, info = inventory(config, project_id) if prepared is None else prepared
    if info["project_id"] != project_id:
        raise ProductError("PREPARED_PROJECT_MISMATCH")
    selected = [e for e in info["endpoints"] if e["endpoint_id"] == endpoint_id]
    if len(selected) != 1:
        raise ProductError("ENDPOINT_NOT_FOUND_OR_AMBIGUOUS")
    endpoint = selected[0]
    classes = ast["classes"]
    cls = next(c for c in classes if c["qualified_name"] == endpoint["class"])
    method = next(m for m in cls["methods"] if m["start"] == endpoint["start"])
    pending, visited, evidence, edges, unresolved = [(cls, method, "ENDPOINT")], set(), [], [], []
    while pending:
        current, member, reason = pending.pop(0)
        key = (current["qualified_name"], member["name"], member["start"])
        if key in visited:
            continue
        visited.add(key)
        if len(visited) > 100:
            raise ProductError("CALL_GRAPH_LIMIT")
        eid = "E" + str(len(evidence) + 1).zfill(3)
        evidence.append({"id": eid, "path": current["path"], "start": member["start"], "end": member["end"],
                         "class_start": current["start"], "symbol": current["qualified_name"] + "." + member["name"],
                         "reason": reason, "file_sha256": info["snapshot"]["files"][current["path"]]})
        variables = {**current["fields"], **member["parameters"], **member["locals"]}
        for call in member["calls"]:
            if call["receiver"] == "this":
                candidates = [current]
            elif call["receiver"] in variables:
                candidates = resolve_type(variables[call["receiver"]], current, classes)
            else:
                candidates = []
            destinations = method_targets(candidates, {**call,'_context':current}, classes)
            if len(destinations) == 1:
                target, target_method = destinations[0]
                edges.append({"from": eid, "line": call["line"], "target": target["qualified_name"] + "." + target_method["name"],
                              "target_path":target['path'],"target_line":target_method['start'],
                              "execution_context":call.get('execution_context','LEXICAL_CALL'),
                              "runtime_dispatch_proven":False,"link_basis": "UNIQUE_DECLARED_SIGNATURE_OR_INHERITED_CANDIDATE"})
                pending.append((target, target_method, "DECLARED_CALL_TARGET"))
            else:
                if len(unresolved) >= 5000:
                    raise ProductError("UNRESOLVED_CALL_LIMIT")
                unresolved.append({"source_id": eid, "line": call["line"], "receiver": call["receiver"], "method": call["name"],
                                   "execution_context":call.get('execution_context','LEXICAL_CALL'),
                                   "reason": "REFLECTION_DYNAMIC_TARGET" if call['name'] in {'forName','getMethod','getDeclaredMethod','invoke','newInstance'} else
                                   "DEFERRED_TARGET_UNRESOLVED" if call.get('kind')=='METHOD_REFERENCE' else
                                   "EXTERNAL_OR_UNRESOLVED_CALL" if not destinations else "OVERLOADED_OR_AMBIGUOUS_CALL"})
                for candidate in candidates:
                    if candidate["kind"] == "INTERFACE":
                        pending.append((candidate, {"name": "<interface-declaration>", "start": candidate["start"], "end": candidate["end"],
                                                    "parameters": {}, "locals": {}, "calls": []}, "UNRESOLVED_REPOSITORY_DECLARATION_CONTEXT"))
    # Security chains are relevant context, never declared to protect a particular route merely by existing.
    security = [c for c in classes if any("SecurityFilterChain" in m["return_type"] for m in c["methods"])]
    for current in security:
        for member in current["methods"]:
            if "SecurityFilterChain" not in member["return_type"]:
                continue
            evidence.append({"id": "E" + str(len(evidence) + 1).zfill(3), "path": current["path"], "start": member["start"], "end": member["end"],
                             "class_start": current["start"], "symbol": current["qualified_name"] + "." + member["name"],
                             "reason": "SECURITY_CONTEXT_NOT_ROUTE_PROOF", "file_sha256": info["snapshot"]["files"][current["path"]]})
    artifacts = [{"id": e["id"], "relativePath": e["path"], "sha256": e["file_sha256"]} for e in evidence]
    if len(evidence) > 150:
        raise ProductError("EVIDENCE_COUNT_LIMIT")
    ledger = {"endpoint": endpoint["http_method"] + " " + endpoint["http_path"],
              "commit": info["snapshot"]["identity"]["commit"] or "file-snapshot:" + info["snapshot_sha256"],
              "artifacts": artifacts, "areas": [{"area": area, "evidenceIds": [e["id"] for e in evidence],
                                                  "unresolvedLinks": ["OPERATOR_SCOPE_REVIEW_REQUIRED"]} for area in AREAS],
              "unsupportedPaths": list(info["support_reasons"])}
    data = {"project_id": project_id, "endpoint": endpoint, "snapshot": info["snapshot"], "snapshot_sha256": info["snapshot_sha256"],
            "evidence": evidence, "edges": edges, "unresolved_calls": unresolved, "ledger": ledger,
            "collection_method": "JDK_AST_DECLARED_INHERITANCE_SIGNATURE_CALLBACK_CONTEXT", "scope_status": "REQUIRES_REVIEW",
            "execution_completeness_proven":False,
            "support_reasons": info["support_reasons"]}
    snapshot.verify()
    store = ProductStore(config.results)
    identifier = store.create("collection", {"kind": "collection", "project_id": project_id})
    data["collection_id"] = identifier
    data["collection_sha256"] = digest(data)
    from .workspace import save_json
    save_json(store.folder(identifier) / "report.json", data)
    return data


def evidence_text(snapshot: Snapshot, collection: dict) -> list[dict]:
    result = []
    for evidence in collection["evidence"]:
        lines = snapshot.files[evidence["path"]].decode("utf-8-sig").splitlines()
        # Includes class imports/annotations/declaration context as well as the selected method.
        spans = [(1, min(evidence["start"] - 1, evidence["class_start"] + 12)), (evidence["start"], evidence["end"])]
        selected = sorted({n for first, last in spans for n in range(first, last + 1)})
        result.append({"id": evidence["id"], "path": evidence["path"], "lines": "\n".join(f"{n}: {lines[n - 1]}" for n in selected if 0 < n <= len(lines))})
    return result

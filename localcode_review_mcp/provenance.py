"""실행 시작 시 제품 코드/런타임 해시·PID·UTC를 묶고 오래된 서버의 새 작업을 거부한다.

로컬 무결성 영수증이며 원격 증명/서명이나 OS 프로세스 생성시각 증명이 아니다.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
from .loading import LOADED

ROOT = Path(__file__).resolve().parents[1]


def fingerprint(root=ROOT):
    entries = {}
    for directory, pattern in (("localcode_review_mcp", "*.py"), ("src/product", "*.java"),
                               ("build/product/classes", "*.class"), ("build/product/lib", "*.jar")):
        for path in sorted((root / directory).rglob(pattern)):
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("LINKED_PRODUCT_CODE")
            entries[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('Json','ScopeAudit','PolicyRules','PolicyComparison'):
        path=root/f'src/main/java/dev/localcodereview/{name}.java'
        if path.is_file():entries[path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    receipt=root/'build/product/build-receipt.json'
    if receipt.exists():entries['build/product/build-receipt.json']=hashlib.sha256(receipt.read_bytes()).hexdigest()
    value = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"files": entries, "sha256": hashlib.sha256(value).hexdigest()}


BOOT = {"contract": "execution-provenance/1", "instance_id": uuid.uuid4().hex,
        "pid": os.getpid(), "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "python_version": sys.version.split()[0], "code": fingerprint(),
        "capture_scope": "PRODUCT_IMPORT_START; NOT_OS_PROCESS_CREATION_OR_REMOTE_ATTESTATION"}


def status():
    current = fingerprint()
    loaded_match=all(BOOT['code']['files'].get(name)==value for name,value in LOADED.items())
    return {"contract": BOOT["contract"], "instance_id": BOOT["instance_id"], "pid": BOOT["pid"],
            "captured_at_utc": BOOT["captured_at_utc"], "loaded_snapshot_sha256": BOOT["code"]["sha256"],
            "disk_snapshot_sha256": current["sha256"],
            "loaded_source_matches_snapshot":loaded_match,
            "restart_required": current != BOOT["code"] or not loaded_match, "automatic_reload": False}


def execution_receipt():
    if status()["restart_required"]:
        from .workspace import ProductError
        raise ProductError("PRODUCT_CODE_CHANGED_RESTART_REQUIRED")
    return {**BOOT, "execution_started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "compiled_python_sources":dict(LOADED),
            "disk_matches_import_snapshot": True}

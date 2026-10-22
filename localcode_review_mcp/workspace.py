"""한글 기능 설명: 프로젝트 등록·읽기 전용 스냅샷·민감정보 제외·제품 결과 저장 경계."""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any
import uuid

REPO = Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\Z")
SKIP_DIRS = {".git", ".gradle", ".idea", ".vscode", "node_modules", "build", "target", "out", "logs", "backup", "backups", ".env", ".ssh"}
NAMES = {"pom.xml", "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "gradle.lockfile"}
SENSITIVE = re.compile(r"(?im)(-----BEGIN [^-]*PRIVATE KEY-----|(?:password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[\"']?[^\s\"';]{4,}|\bAKIA[A-Z0-9]{16}\b)")


class ProductError(ValueError):
    """제품에 노출해도 되는 고정 코드와 설명만 담는다. 소스/응답 원문은 담지 않는다."""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value: bytes | dict | list) -> str:
    if not isinstance(value, bytes):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path, maximum: int = 4_194_304) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProductError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ProductError("JSON_SIZE_LIMIT")
    return json.loads(data, object_pairs_hook=unique)


def replace_local_file(source, destination) -> None:
    """Windows 조회 프로세스가 잠깐 잡은 파일의 교체만 유한 대기한다. 원격 호출 재시도가 아니다."""
    for attempt in range(7):
        try:
            os.replace(source, destination)
            return
        except PermissionError as error:
            if os.name != "nt" or getattr(error, "winerror", None) not in {5, 32, 33} or attempt == 6:
                raise
            time.sleep(min(0.01 * (2 ** attempt), 0.1))


def save_json(path: Path, value: Any, *, replace: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if not replace:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
        return
    fd, temporary = tempfile.mkstemp(prefix=".localcode-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
        replace_local_file(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def inside(root: Path, relative: str) -> Path:
    candidate = root / relative
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ProductError("PATH_ESCAPE")
    current = candidate
    while current != root:
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise ProductError("LINK_NOT_ALLOWED")
        if current.parent == current:
            raise ProductError("PATH_ESCAPE")
        current = current.parent
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ProductError("PATH_ESCAPE")
    return resolved


@dataclass
class ProductConfig:
    path: Path
    projects: dict[str, dict] = field(default_factory=dict)
    jdk: Path | None = None
    results: Path = REPO / "results/product"
    model: dict = field(default_factory=dict)
    http_targets: dict = field(default_factory=dict)
    allow_osv_network: bool = False
    scan_profiles: dict = field(default_factory=dict)

    @classmethod
    def read(cls, path: Path, jdk: Path | None = None):
        data = load_json(path) if path.exists() else {}
        return cls.from_data(path, data, jdk)

    @classmethod
    def from_data(cls, path: Path, data: dict, jdk: Path | None = None):
        if not isinstance(data, dict) or data.get("version", 1) != 1:
            raise ProductError("CONFIG_VERSION_UNSUPPORTED")
        projects = data.get("projects", {})
        if not isinstance(projects, dict) or any(not IDENTIFIER.fullmatch(k) or not isinstance(v, dict) for k, v in projects.items()):
            raise ProductError("PROJECT_REGISTRY_INVALID")
        selected_jdk = data.get("jdk") or jdk or os.environ.get("JAVA_HOME")
        result = Path(data.get("results_dir", REPO / "results/product")).expanduser().resolve()
        for project in projects.values():
            root = Path(project["root"]).expanduser().resolve()
            if result == root or result.is_relative_to(root):
                raise ProductError("RESULTS_MUST_BE_OUTSIDE_SOURCE_ROOT")
        profiles = data.get("scan_profiles", {})
        if not isinstance(profiles, dict) or any(not IDENTIFIER.fullmatch(k) or not isinstance(v, dict) for k, v in profiles.items()):
            raise ProductError("SCAN_PROFILE_REGISTRY_INVALID")
        return cls(path.resolve(), projects, Path(selected_jdk).resolve() if selected_jdk else None,
                   result, data.get("model", {}), data.get("http_targets", {}), data.get("allow_osv_network") is True, profiles)

    def project(self, project_id: str) -> tuple[Path, dict]:
        if project_id not in self.projects:
            raise ProductError("PROJECT_NOT_REGISTERED: configure this project locally first")
        value = self.projects[project_id]
        root = Path(value["root"]).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ProductError("PROJECT_ROOT_INVALID")
        return root, value

    def java(self) -> Path:
        if self.jdk is None:
            raise ProductError("JDK_NOT_CONFIGURED")
        java = self.jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
        if not java.is_file():
            raise ProductError("JAVA_NOT_FOUND")
        return java


def git_identity(root: Path, expected: str | None = None) -> dict:
    """고정된 읽기 명령만 실행하며 hooks/사용자 Git fsmonitor는 비활성화한다."""
    prefix = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-C", str(root)]
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}
    try:
        result = subprocess.run(prefix + ["rev-parse", "--verify", "HEAD"], capture_output=True, timeout=10, env=env, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        if expected:
            raise ProductError("GIT_REQUIRED_FOR_COMMIT_PIN") from None
        return {"commit": None, "basis": "FILE_HASHES", "worktree": "UNVERIFIED"}
    if result.returncode:
        if expected:
            raise ProductError("COMMIT_UNAVAILABLE")
        return {"commit": None, "basis": "FILE_HASHES", "worktree": "UNVERIFIED"}
    commit = result.stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit) or (expected and commit != expected):
        raise ProductError("COMMIT_CHANGED")
    status = subprocess.run(prefix + ["status", "--porcelain=v1", "--untracked-files=no"], capture_output=True, timeout=10, env=env, stdin=subprocess.DEVNULL)
    if status.returncode:
        raise ProductError("GIT_STATUS_UNAVAILABLE")
    if expected and status.stdout:
        raise ProductError("PINNED_COMMIT_WORKTREE_DIRTY")
    return {"commit": commit, "basis": "COMMIT_AND_WORKING_FILE_HASHES", "worktree": "DIRTY" if status.stdout else "CLEAN"}


@dataclass
class Snapshot:
    root: Path
    identity: dict
    files: dict[str, bytes]
    excluded: list[dict]

    @classmethod
    def read(cls, root: Path, expected_commit: str | None = None):
        identity = git_identity(root, expected_commit)
        blobs = None
        if expected_commit:
            tree = subprocess.run(["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(root),
                                   "ls-tree", "-r", "-z", expected_commit], capture_output=True, timeout=15,
                                  env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0"}, stdin=subprocess.DEVNULL)
            if tree.returncode:
                raise ProductError("COMMIT_TREE_UNAVAILABLE")
            blobs = {}
            for entry in tree.stdout.split(b"\0"):
                if not entry:
                    continue
                description, name = entry.split(b"\t", 1)
                mode, kind, oid = description.split()
                if kind == b"blob" and mode in {b"100644", b"100755"}:
                    blobs[name.decode("utf-8")] = oid.decode("ascii")
        files, excluded = {}, []
        total, lines, java_count, walked = 0, 0, 0, 0
        for parent, dirs, names in os.walk(root, followlinks=False):
            kept = []
            for name in sorted(dirs):
                child = Path(parent) / name
                if name in SKIP_DIRS or name.startswith("."):
                    continue
                if child.is_symlink() or (hasattr(child, "is_junction") and child.is_junction()):
                    excluded.append({"path": child.relative_to(root).as_posix(), "reason": "DIRECTORY_LINK"})
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(names):
                walked += 1
                if walked > 20_000:
                    raise ProductError("PROJECT_FILE_INVENTORY_LIMIT")
                path = Path(parent) / name
                if path.suffix not in {".java", ".kt"} and name not in NAMES:
                    continue
                relative = path.relative_to(root).as_posix()
                if blobs is not None and relative not in blobs:
                    excluded.append({"path": relative, "reason": "UNTRACKED_OR_UNSUPPORTED_COMMIT_ENTRY"})
                    continue
                try:
                    checked = inside(root, relative)
                except ProductError:
                    excluded.append({"path": relative, "reason": "FILE_LINK"})
                    continue
                with checked.open("rb") as stream:
                    content = stream.read(1_048_577)
                if len(content) > 1_048_576:
                    raise ProductError("FILE_SIZE_LIMIT")
                if blobs is not None:
                    variants = (content, content.replace(b"\r\n", b"\n"))
                    expected_blob = blobs[relative]
                    hash_function = hashlib.sha1 if len(expected_blob) == 40 else hashlib.sha256
                    if not any(hash_function(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest() == expected_blob for data in variants):
                        raise ProductError("COMMIT_BLOB_MISMATCH")
                try:
                    text = content.decode("utf-8-sig")
                except UnicodeDecodeError:
                    excluded.append({"path": relative, "reason": "NON_UTF8"})
                    continue
                if SENSITIVE.search(text):
                    excluded.append({"path": relative, "reason": "POTENTIAL_SECRET"})
                    continue
                total += len(content)
                if path.suffix == ".java":
                    java_count += 1
                    lines += len(text.splitlines())
                if java_count > 500 or lines > 50_000 or total > 20 * 1_048_576:
                    raise ProductError("PROJECT_SOURCE_LIMIT")
                files[relative] = content
        return cls(root, identity, files, excluded)

    def metadata(self) -> dict:
        return {"identity": self.identity, "files": {p: digest(v) for p, v in self.files.items()}, "excluded": self.excluded}

    def verify(self):
        # 커밋 고정은 read(expected_commit)에서 검사했다. 고정하지 않은 폴더는
        # 최초 DIRTY 상태 자체를 허용하되 HEAD/작업 상태와 수집 바이트의 변화는 차단한다.
        if git_identity(self.root) != self.identity:
            raise ProductError("PROJECT_IDENTITY_CHANGED")
        for name, expected in self.files.items():
            with inside(self.root, name).open("rb") as stream:
                actual = stream.read(len(expected) + 1)
            if actual != expected:
                raise ProductError("SOURCE_CHANGED")


class ProductStore:
    def __init__(self, root: Path):
        self.root = root

    def folder(self, identifier: str) -> Path:
        if not IDENTIFIER.fullmatch(identifier):
            raise ProductError("INVALID_RESULT_ID")
        return inside(self.root, identifier)

    def create(self, kind: str, metadata: dict) -> str:
        identifier = kind + "-" + uuid.uuid4().hex
        directory = self.folder(identifier)
        directory.mkdir(parents=True, exist_ok=False)
        save_json(directory / "metadata.json", {**metadata, "id": identifier, "created_at": now()})
        return identifier

    def read(self, identifier: str, name: str = "report.json") -> dict:
        if name not in {"metadata.json", "report.json", "status.json"}:
            raise ProductError("INVALID_RESULT_TYPE")
        return load_json(inside(self.folder(identifier), name))


def redact(text: str) -> str:
    return SENSITIVE.sub("[REDACTED]", text)

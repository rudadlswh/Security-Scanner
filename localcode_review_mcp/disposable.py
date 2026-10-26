"""한글 기능 설명: 운영자가 명시 등록한 명령을 프로젝트 복사본에서 시작하고 프로세스 트리를 종료한다.

프로젝트 안의 지시/설정을 자동 실행하지 않는다. 명령은 로컬 설정만 읽으며 OS 보안 샌드박스는 아니다.
Windows Job Object와 시작 핸드셰이크로 자식 생성 전에 종료 경계를 설정한다.
"""
from __future__ import annotations

import asyncio
import ctypes as C
from ctypes import wintypes as W
import json
import ipaddress
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
from urllib.parse import urlsplit

import httpx

from .network import loopback_url
from .workspace import ProductError, SENSITIVE, digest, inside

COPY_SKIP = {".git", ".gradle", ".idea", ".vscode", "node_modules", ".ssh", "logs", "backup", "backups", "__pycache__"}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".sqlite", ".sqlite3", ".db", ".log", ".dump"}
TEXT_SUFFIXES = {".java", ".kt", ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".properties", ".xml", ".gradle", ".kts", ".txt"}


def validate_server(spec: dict, project_root: Path, targets: list[dict]) -> dict:
    if spec.get("require_os_isolation") is True:
        raise ProductError("OS_ISOLATION_REQUIRED_USE_CONTAINER_PROFILE: local process guard is not a sandbox")
    if spec.get("authorized_disposable_environment") is not True or spec.get("acknowledge_command_execution") is not True:
        raise ProductError("DISPOSABLE_SERVER_EXPLICIT_AUTHORIZATION_REQUIRED")
    if Path(spec.get("project_root", "")).resolve() != project_root:
        raise ProductError("DISPOSABLE_SERVER_PROJECT_MISMATCH")
    argv = spec.get("command")
    if not isinstance(argv, list) or not argv or len(argv) > 100 or any(not isinstance(x, str) or not x or "\0" in x or len(x) > 8192 for x in argv):
        raise ProductError("DISPOSABLE_SERVER_ARGV_REQUIRED")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.is_file() or executable.suffix.lower() in {".bat", ".cmd", ".ps1", ".sh"}:
        raise ProductError("DISPOSABLE_SERVER_ABSOLUTE_EXECUTABLE_REQUIRED")
    if executable.resolve().is_relative_to(project_root):
        raise ProductError("EXECUTABLE_MUST_BE_OUTSIDE_ORIGINAL_PROJECT")
    base = loopback_url(spec.get("base_url", ""))
    parsed = urlsplit(base)
    if not 1 <= parsed.port <= 65535 or parsed.port == 11434:
        raise ProductError("OLLAMA_IS_NOT_A_DISPOSABLE_TARGET")
    if not targets or any(loopback_url(t.get("base_url", "")) != base or t.get("authorized_disposable_environment") is not True for t in targets):
        raise ProductError("DISPOSABLE_SERVER_TARGET_MISMATCH")
    health = spec.get("health_path", "/")
    if not isinstance(health, str) or not health.startswith("/") or health.startswith("//") or any(c in health for c in "\r\n?#\\"):
        raise ProductError("DISPOSABLE_HEALTH_PATH_INVALID")
    statuses = spec.get("health_statuses", [200])
    if not isinstance(statuses, list) or not statuses or any(type(x) is not int or not 100 <= x <= 599 for x in statuses):
        raise ProductError("DISPOSABLE_HEALTH_STATUS_INVALID")
    startup = spec.get("startup_timeout_seconds", 60)
    if type(startup) not in {int, float} or not 1 <= startup <= 120:
        raise ProductError("DISPOSABLE_STARTUP_BUDGET_INVALID")
    environment = spec.get("environment", {})
    inherit = spec.get("environment_from", [])
    if not isinstance(environment, dict) or len(environment) > 100 or any(not isinstance(k, str) or not k or "=" in k or not isinstance(v, str) or "\0" in k + v for k, v in environment.items()):
        raise ProductError("DISPOSABLE_ENVIRONMENT_INVALID")
    if not isinstance(inherit, list) or len(inherit) > 100 or any(not isinstance(k, str) or k not in os.environ for k in inherit):
        raise ProductError("DISPOSABLE_ENVIRONMENT_VARIABLE_MISSING")
    return {"base_url": base, "health_path": health, "health_statuses": statuses, "startup_timeout_seconds": startup}


def copy_workspace(source: Path, destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=False)
    count, total, excluded = 0, 0, []
    for parent, dirs, files in os.walk(source, followlinks=False):
        kept = []
        for name in sorted(dirs):
            path = Path(parent) / name
            if name.startswith(".") or name in COPY_SKIP:
                continue
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                excluded.append({"path": path.relative_to(source).as_posix(), "reason": "LINK"})
                continue
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            relative = (Path(parent) / name).relative_to(source).as_posix()
            path = inside(source, relative)
            if name.startswith(".") or path.suffix.lower() in SECRET_SUFFIXES:
                excluded.append({"path": relative, "reason": "SECRET_DATA_OR_HIDDEN_FILE"})
                continue
            count += 1
            size = path.stat().st_size
            total += size
            if count > 20_000 or total > 536_870_912 or size > 134_217_728:
                raise ProductError("DISPOSABLE_COPY_BUDGET_EXCEEDED")
            if path.suffix.lower() in TEXT_SUFFIXES:
                with path.open("rb") as stream:
                    text = stream.read(min(size, 1_048_576)).decode("utf-8-sig", errors="replace")
                if SENSITIVE.search(text):
                    excluded.append({"path": relative, "reason": "POTENTIAL_SECRET"})
                    continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    return {"copied_files": count - len([e for e in excluded if e["reason"] == "POTENTIAL_SECRET"]),
            "considered_bytes": total, "excluded": excluded, "copy_is_security_sandbox": False}


class WindowsJob:
    def __init__(self, process):
        class Basic(C.Structure):
            _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64), ("flags", W.DWORD),
                        ("min_working", C.c_size_t), ("max_working", C.c_size_t), ("active_limit", W.DWORD),
                        ("affinity", C.c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]
        class IO(C.Structure):
            _fields_ = [(name, C.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
        class Extended(C.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", C.c_size_t), ("job_memory", C.c_size_t),
                        ("peak_process", C.c_size_t), ("peak_job", C.c_size_t)]
        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [C.c_void_p, W.LPCWSTR]
        kernel.CreateJobObjectW.restype = W.HANDLE
        kernel.SetInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
        kernel.SetInformationJobObject.restype = W.BOOL
        kernel.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
        kernel.AssignProcessToJobObject.restype = W.BOOL
        kernel.CloseHandle.argtypes = [W.HANDLE]
        kernel.CloseHandle.restype = W.BOOL
        self.kernel, self.handle = kernel, kernel.CreateJobObjectW(None, None)
        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.handle or not kernel.SetInformationJobObject(self.handle, 9, C.byref(limits), C.sizeof(limits)) or not kernel.AssignProcessToJobObject(self.handle, W.HANDLE(int(process._handle))):
            self.close()
            raise ProductError("DISPOSABLE_PROCESS_TREE_GUARD_UNAVAILABLE")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def process_ids(self):
        buffer = C.create_string_buffer(65_536)
        self.kernel.QueryInformationJobObject.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p]
        self.kernel.QueryInformationJobObject.restype = W.BOOL
        if not self.kernel.QueryInformationJobObject(self.handle, 3, buffer, len(buffer), None):
            raise ProductError("DISPOSABLE_PROCESS_TREE_QUERY_FAILED")
        count = C.c_uint32.from_buffer(buffer, 4).value
        if count > (len(buffer) - 8) // C.sizeof(C.c_size_t):
            raise ProductError("DISPOSABLE_PROCESS_TREE_QUERY_FAILED")
        return set((C.c_size_t * count).from_buffer(buffer, 8))


class DisposableServer:
    def __init__(self, spec: dict, root: Path, run_dir: Path, targets: list[dict]):
        self.spec, self.root, self.run_dir = spec, root, run_dir.resolve()
        self.settings = validate_server(spec, root, targets)
        self.process, self.job = None, None
        self.copy = self.run_dir / "server-workspace"
        self.metadata = {"started": False, "stopped": False, "workspace_removed": False,
                         "command_sha256": digest(spec["command"]), "environment_names": sorted(set(spec.get("environment", {})) | set(spec.get("environment_from", []))),
                         "os_security_sandbox": False, "process_tree_guard": "WINDOWS_JOB" if os.name == "nt" else "POSIX_PROCESS_GROUP"}

    async def start(self):
        parsed = urlsplit(self.settings["base_url"])
        family = socket.AF_INET6 if ":" in parsed.hostname else socket.AF_INET
        with socket.socket(family) as probe:
            try:
                probe.bind((parsed.hostname, parsed.port))
            except OSError:
                raise ProductError("DISPOSABLE_PORT_NOT_AVAILABLE_NO_REUSE") from None
        # 복사 작업은 취소돼도 완료를 기다린 후 제거한다. 백그라운드 복사와 삭제가 경합하지 않는다.
        copying = asyncio.create_task(asyncio.to_thread(copy_workspace, self.root, self.copy))
        try:
            self.metadata["copy"] = await asyncio.shield(copying)
        except asyncio.CancelledError:
            await copying
            raise
        expected=self.spec.get('expected_source_files')
        if expected is not None:
            if not isinstance(expected,dict) or not expected or len(expected)>500:
                raise ProductError('DISPOSABLE_SOURCE_BINDING_INVALID')
            actual={}
            for name,wanted in expected.items():
                copied=inside(self.copy,name)
                if not isinstance(wanted,str) or not copied.is_file() or digest(copied.read_bytes())!=wanted:
                    raise ProductError('DISPOSABLE_COPIED_SOURCE_MISMATCH_NO_EXECUTION')
                actual[name]=wanted
            self.metadata['executed_source_files']=actual
        replacements = {"{project_copy}": str(self.copy), "{run_dir}": str(self.run_dir), "{port}": str(parsed.port)}
        def expand(value):
            for key, replacement in replacements.items():
                value = value.replace(key, replacement)
            return value
        argv = [expand(a) for a in self.spec["command"]]
        if any(str(self.root).lower() in a.lower() or self.root.as_posix().lower() in a.lower() for a in argv[1:]):
            raise ProductError("ORIGINAL_PROJECT_MUST_NOT_BE_EXECUTION_ARGUMENT")
        environment = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH"}}
        temporary = self.run_dir / "server-temp"
        temporary.mkdir()
        environment.update(TEMP=str(temporary), TMP=str(temporary))
        environment.update({k: expand(v) for k, v in self.spec.get("environment", {}).items()})
        environment.update({k: os.environ[k] for k in self.spec.get("environment_from", [])})
        self.process = subprocess.Popen([sys.executable, "-m", "localcode_review_mcp.disposable"],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
        if os.name == "nt":
            self.job = WindowsJob(self.process)
        # Job Object 배정이 끝나기 전에는 실제 프로젝트 프로세스를 시작할 수 없다.
        self.process.stdin.write(json.dumps({"command": argv, "cwd": str(self.copy), "environment": environment}).encode("utf-8"))
        self.process.stdin.close()
        self.metadata.update(started=True, owner_pid=self.process.pid)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.settings["startup_timeout_seconds"]
        async with httpx.AsyncClient(timeout=1, trust_env=False, follow_redirects=False) as client:
            while loop.time() < deadline:
                if self.process.poll() is not None:
                    raise ProductError("DISPOSABLE_SERVER_EXITED")
                try:
                    async with client.stream("GET", self.settings["base_url"] + self.settings["health_path"]) as response:
                        ready = response.status_code in self.settings["health_statuses"]
                    if ready:
                        self.metadata["listener_verification"] = await asyncio.to_thread(self.verify_listener)
                        self.metadata["ready"] = True
                        return self.metadata
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.2)
        raise ProductError("DISPOSABLE_SERVER_START_TIMEOUT")

    def verify_listener(self):
        if os.name != "nt" or self.job is None:
            raise ProductError("DISPOSABLE_LISTENER_CHECK_WINDOWS_ONLY")
        port = urlsplit(self.settings["base_url"]).port
        script = ("$ErrorActionPreference='Stop'; @((Get-NetTCPConnection -LocalPort " + str(port)
                  + " -State Listen) | Select-Object LocalAddress,OwningProcess) | ConvertTo-Json -Compress")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, stdin=subprocess.DEVNULL, timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            raise ProductError("DISPOSABLE_LISTENER_QUERY_FAILED")
        try:
            listeners = json.loads(result.stdout.decode("utf-8-sig"))
            listeners = listeners if isinstance(listeners, list) else [listeners]
            owners = self.job.process_ids()
            if not listeners or any(not ipaddress.ip_address(row["LocalAddress"]).is_loopback or row["OwningProcess"] not in owners for row in listeners):
                raise ProductError("DISPOSABLE_LISTENER_NOT_OWNED_LOOPBACK")
            return {"addresses": [row["LocalAddress"] for row in listeners], "owned_by_server_job": True,
                    "point_in_time_check": True}
        except (ValueError, KeyError, TypeError):
            raise ProductError("DISPOSABLE_LISTENER_NOT_VERIFIED") from None

    async def stop(self):
        if self.job is not None:
            self.job.close()
        elif self.process is not None and os.name != "nt":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif self.process is not None and self.process.poll() is None:
            self.process.kill()
        if self.process is not None:
            try:
                await asyncio.to_thread(self.process.wait, timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                await asyncio.to_thread(self.process.wait, timeout=10)
            self.metadata["stopped"] = self.process.poll() is not None
        else:
            self.metadata["stopped"] = True
        # 삭제할 절대 경로를 이번 실행 폴더의 정확한 하위 폴더로 확인한다.
        for name in ("server-workspace", "server-temp"):
            target = self.run_dir / name
            if target.exists():
                resolved = target.resolve()
                if target.is_symlink() or (hasattr(target, "is_junction") and target.is_junction()) or resolved.parent != self.run_dir:
                    raise ProductError("DISPOSABLE_CLEANUP_PATH_INVALID")
                shutil.rmtree(resolved)
        self.metadata["workspace_removed"] = not self.copy.exists()
        return self.metadata


if __name__ == "__main__":
    # 부모가 프로세스 트리 보호를 설정한 뒤 전달한 실행 설정만 메모리에서 사용한다.
    try:
        raw = sys.stdin.buffer.read(131_073)
        if len(raw) > 131_072:
            raise ValueError("SETTINGS_LIMIT")
        settings = json.loads(raw)
        child = subprocess.Popen(settings["command"], cwd=settings["cwd"], env=settings["environment"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise SystemExit(child.wait())
    except Exception:
        raise SystemExit(2)

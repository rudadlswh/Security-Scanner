"""한글 기능 설명: 명시 승인된 로컬 Linux Docker 엔진에서 일회용 서버를 제한 실행한다.

이미지는 digest로 고정하고 미리 설치돼 있어야 한다. 엔진/이미지 부재는 실행 차단이며 로컬 실행으로 강등하지 않는다.
이 백엔드는 OS 컨테이너 경계를 제공하지만 VM/완전한 공격 방어를 보증하지 않는다.
"""
from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid
from urllib.parse import urlsplit
import httpx
from .disposable import copy_workspace
from .network import loopback_url
from .workspace import ProductError, digest
from .container_relay import ContainerRelay


class ContainerServer:
    def __init__(self, spec, root, run_dir, targets):
        self.spec, self.root, self.run_dir = spec, root.resolve(), run_dir.resolve()
        self.copy = self.run_dir / "server-workspace"
        if any(c in str(self.copy) for c in ",\r\n"):
            raise ProductError("CONTAINER_MOUNT_PATH_UNSUPPORTED")
        self.name = "lcr-" + uuid.uuid4().hex
        self.network = self.name + "-net"
        if spec.get("authorized_disposable_environment") is not True or spec.get("acknowledge_command_execution") is not True:
            raise ProductError("CONTAINER_EXPLICIT_AUTHORIZATION_REQUIRED")
        if Path(spec.get("project_root", "")).resolve() != self.root:
            raise ProductError("CONTAINER_PROJECT_MISMATCH")
        executable = Path(spec.get("docker_executable", ""))
        if not executable.is_absolute() or not executable.is_file() or executable.suffix.lower() in {".bat", ".cmd", ".ps1", ".sh"} or executable.resolve().is_relative_to(self.root):
            raise ProductError("CONTAINER_ENGINE_UNAVAILABLE_NO_LOCAL_FALLBACK")
        self.docker = str(executable.resolve())
        image = spec.get("image", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
            raise ProductError("CONTAINER_IMAGE_DIGEST_REQUIRED")
        command = spec.get("command")
        if not isinstance(command, list) or not command or len(command) > 100 or any(not isinstance(x, str) or not x or len(x) > 8192 or "\0" in x for x in command):
            raise ProductError("CONTAINER_ARGV_INVALID")
        if not command[0].startswith("/") or any(str(self.root).lower() in arg.lower() or "{run_dir}" in arg for arg in command):
            raise ProductError("CONTAINER_HOST_PATH_ARGUMENT_FORBIDDEN")
        self.base = loopback_url(spec.get("base_url", ""))
        parsed = urlsplit(self.base)
        if parsed.hostname != "127.0.0.1" or parsed.port == 11434 or not targets or any(loopback_url(t.get("base_url", "")) != self.base or t.get("authorized_disposable_environment") is not True for t in targets):
            raise ProductError("CONTAINER_LOOPBACK_TARGET_REQUIRED")
        for key, minimum, maximum, default in (("container_port", 1024, 65535, 8080), ("memory_mib", 128, 8192, 512), ("pids_limit", 16, 512, 128)):
            value = spec.get(key, default)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ProductError("CONTAINER_RESOURCE_LIMIT_INVALID")
        if type(spec.get("cpus", 1)) not in {int, float} or not 0.1 <= spec.get("cpus", 1) <= 8:
            raise ProductError("CONTAINER_RESOURCE_LIMIT_INVALID")
        if not re.fullmatch(r"[1-9][0-9]{0,5}:[1-9][0-9]{0,5}", spec.get("user", "10001:10001")):
            raise ProductError("CONTAINER_NON_ROOT_USER_REQUIRED")
        if spec.get("environment") or spec.get("environment_from"):
            raise ProductError("CONTAINER_ENVIRONMENT_NOT_SUPPORTED")
        health = spec.get("health_path", "/health")
        if not isinstance(health, str) or not health.startswith("/") or health.startswith("//") or any(c in health for c in "\r\n?#\\"):
            raise ProductError("CONTAINER_HEALTH_PATH_INVALID")
        if type(spec.get("startup_timeout_seconds", 60)) not in {int, float} or not 1 <= spec.get("startup_timeout_seconds", 60) <= 120:
            raise ProductError("CONTAINER_STARTUP_LIMIT_INVALID")
        self.created_network, self.started = False, False
        self.container_attempted = False
        self.network_policy = spec.get('network_policy', 'none')
        if self.network_policy not in {'none', 'internal'}:
            raise ProductError('CONTAINER_NETWORK_POLICY_INVALID')
        self.relay = None
        self.metadata = {"backend": "DOCKER_LINUX", "started": False, "stopped": False, "workspace_removed": False,
                         "os_security_sandbox": False, "isolation_verified": False, "command_sha256": digest(command),
                         "network_policy": self.network_policy,
                         "restrictions": ["READ_ONLY_ROOT", "NON_ROOT", "ALL_CAPABILITIES_DROPPED", "NO_NEW_PRIVILEGES", "NETWORK_"+self.network_policy.upper(), "RESOURCE_LIMITS", "COPY_READ_ONLY_MOUNT", "RAW_CONTAINER_LOGS_DISABLED"]}

    def cli(self, *args):
        # 외부 Docker context/DOCKER_HOST/인증 환경을 상속하지 않고 로컬 엔진 주소를 고정한다.
        endpoint = "npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///var/run/docker.sock"
        env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "HOME", "USERPROFILE"}}
        result = subprocess.run([self.docker, "--host", endpoint, *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30, env=env,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if result.returncode:
            raise ProductError("CONTAINER_ENGINE_OPERATION_FAILED:" + args[0])
        if len(result.stdout) > 1_048_576:
            raise ProductError("CONTAINER_ENGINE_OUTPUT_LIMIT")
        return result.stdout.decode("utf-8-sig")

    async def operation(self, *args):
        task = asyncio.create_task(asyncio.to_thread(self.cli, *args))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Docker 작업과 정리가 경합하지 않도록 해당 로컬 명령이 끝난 뒤 취소한다.
            await task
            raise

    async def start(self):
        engine = json.loads(await asyncio.to_thread(self.cli, "info", "--format", "{{json .}}"))
        if engine.get("OSType") != "linux":
            raise ProductError("CONTAINER_LINUX_ENGINE_REQUIRED")
        await asyncio.to_thread(self.cli, "image", "inspect", self.spec["image"])
        copying = asyncio.create_task(asyncio.to_thread(copy_workspace, self.root, self.copy))
        try:
            self.metadata["copy"] = await asyncio.shield(copying)
        except asyncio.CancelledError:
            await copying
            raise
        if self.network_policy == 'internal':
            self.created_network = True
            await self.operation("network", "create", "--internal", self.network)
        port = urlsplit(self.base).port
        internal_port = self.spec.get("container_port", 8080)
        argv = [x.replace("{project_copy}", "/workspace").replace("{port}", str(internal_port)) for x in self.spec["command"]]
        command = ["run", "--detach", "--name", self.name, "--pull=never", "--read-only", "--log-driver=none", "--no-healthcheck", "--user", self.spec.get("user", "10001:10001"),
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", str(self.spec.get("pids_limit", 128)),
                   "--memory", str(self.spec.get("memory_mib", 512)) + "m", "--memory-swap", str(self.spec.get("memory_mib", 512)) + "m", "--cpus", str(self.spec.get("cpus", 1)),
                   "--network", self.network if self.network_policy == 'internal' else 'none',
                   "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
                   "--mount", f"type=bind,src={self.copy},dst=/workspace,readonly", "--workdir", "/workspace",
                   "--tmpfs", "/tmp:rw,noexec,nosuid,size=134217728", "--entrypoint", argv[0], self.spec["image"], *argv[1:]]
        self.container_attempted = True
        await self.operation(*command)
        self.started = True
        self.metadata["started"] = True
        state = json.loads(await asyncio.to_thread(self.cli, "inspect", self.name))[0]
        host, runtime = state["HostConfig"], state["Config"]
        network = json.loads(await asyncio.to_thread(self.cli, "network", "inspect", self.network))[0] if self.network_policy == 'internal' else {}
        network_ok = (network.get('Internal') is True and host.get('NetworkMode') == self.network) if self.network_policy == 'internal' else host.get('NetworkMode') == 'none'
        bindings = host.get("PortBindings", {})
        binds = [mount for mount in state.get("Mounts", []) if mount.get("Type") == "bind"]
        mounts_ok = len(binds) == 1 and binds[0].get("Destination") == "/workspace" and binds[0].get("RW") is False and Path(binds[0].get("Source", "")).resolve() == self.copy.resolve()
        if not (host.get("ReadonlyRootfs") and not host.get("Privileged") and mounts_ok and host.get("LogConfig", {}).get("Type") == "none"
                and host.get("Memory") == self.spec.get("memory_mib", 512) * 1_048_576
                and host.get("MemorySwap") == self.spec.get("memory_mib", 512) * 1_048_576
                and host.get("PidsLimit") == self.spec.get("pids_limit", 128)
                and host.get("NanoCpus") == int(self.spec.get("cpus", 1) * 1_000_000_000)
                and runtime.get("User") == self.spec.get("user", "10001:10001") and "ALL" in host.get("CapDrop", [])
                and "no-new-privileges" in host.get("SecurityOpt", []) and network_ok
                and host.get('Sysctls', {}).get('net.ipv6.conf.all.disable_ipv6') == '1'
                and host.get('Sysctls', {}).get('net.ipv6.conf.default.disable_ipv6') == '1'
                and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('CapAdd')
                and host.get('PidMode', '') != 'host' and host.get('IpcMode', '') != 'host'
                and not any('unconfined' in option for option in host.get('SecurityOpt', []))
                and not bindings and not any(state.get("NetworkSettings", {}).get("Ports", {}).values())):
            raise ProductError("CONTAINER_ISOLATION_INSPECTION_FAILED")
        self.metadata["isolation_verified"] = True
        self.metadata["os_security_sandbox"] = True
        self.relay = ContainerRelay(self.docker, self.name, port, internal_port)
        self.metadata["relay"] = await self.relay.start()
        deadline = asyncio.get_running_loop().time() + self.spec.get("startup_timeout_seconds", 60)
        async with httpx.AsyncClient(timeout=1, trust_env=False, follow_redirects=False) as client:
            while asyncio.get_running_loop().time() < deadline:
                try:
                    async with client.stream("GET", self.base + self.spec.get("health_path", "/health")) as response:
                        if response.status_code == 200:
                            self.metadata["ready"] = True
                            return self.metadata
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.2)
        raise ProductError("CONTAINER_SERVER_START_TIMEOUT")

    async def stop(self):
        if self.relay is not None:
            await self.relay.stop()
        # run 실패도 컨테이너 생성 후 응답 유실일 수 있어 이름으로 제거를 시도한다.
        if self.container_attempted:
            try:
                await self.operation("rm", "--force", "--volumes", self.name)
            except ProductError:
                names = await asyncio.to_thread(self.cli, "ps", "--all", "--filter", "name=^/" + self.name + "$", "--format", "{{.Names}}")
                if names.strip():
                    raise ProductError("CONTAINER_CLEANUP_NOT_VERIFIED")
            self.container_attempted = False
            self.started = False
        if self.created_network:
            try:
                await self.operation("network", "rm", self.network)
            except ProductError:
                networks = await asyncio.to_thread(self.cli, "network", "ls", "--filter", "name=^" + self.network + "$", "--format", "{{.Name}}")
                if networks.strip():
                    raise ProductError("CONTAINER_NETWORK_CLEANUP_NOT_VERIFIED")
            self.created_network = False
            self.started = False
        self.metadata["stopped"] = True
        if self.copy.exists():
            if self.copy.is_symlink() or (hasattr(self.copy, "is_junction") and self.copy.is_junction()) or self.copy.resolve().parent != self.run_dir:
                raise ProductError("CONTAINER_CLEANUP_PATH_INVALID")
            shutil.rmtree(self.copy)
        self.metadata["workspace_removed"] = not self.copy.exists()
        return self.metadata

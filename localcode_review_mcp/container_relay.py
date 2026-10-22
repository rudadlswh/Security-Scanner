"""기능: Docker 내부망의 서버를 호스트 루프백 소켓에 한정해 byte stream으로 연결한다.

Docker Desktop의 내부망 포트 게시에 의존하지 않는다. 고정된 컨테이너 루프백 주소만 연결하며
요청을 shell 명령으로 해석하지 않고 stdin으로만 전달한다. 본문·인증 헤더·stderr를 저장하지 않는다.
"""
from __future__ import annotations
import asyncio
import os
import socket
import subprocess
from .workspace import ProductError

TUNNEL = '''exec 3<>/dev/tcp/127.0.0.1/$1 || exit 23
/bin/cat <&3 &
r=$!
/bin/cat <&0 >&3 &
w=$!
trap 'kill "$r" "$w" 2>/dev/null; wait "$r" "$w" 2>/dev/null' EXIT
wait -n "$r" "$w"
'''


class ContainerRelay:
    def __init__(self, docker, name, host_port, container_port):
        self.docker,self.name,self.host_port,self.container_port=docker,name,host_port,container_port
        self.server=None
        self.handlers=set()
        self.closing=False
        self.metadata={'transport':'DOCKER_EXEC_STDIN_STDOUT','listener':'127.0.0.1',
                       'container_destination':'127.0.0.1','max_connections':16,'bytes_per_direction_limit':16_777_216,
                       'raw_logs_saved':False,'stopped':False}

    async def start(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            if os.name=='nt':sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            sock.bind(('127.0.0.1',self.host_port));sock.listen(16);sock.setblocking(False)
            self.server=await asyncio.start_server(self.handle,sock=sock)
        except BaseException:
            sock.close()
            raise
        self.metadata['listener_verified']=all(s.getsockname()==('127.0.0.1',self.host_port) for s in self.server.sockets)
        if not self.metadata['listener_verified']:raise ProductError('CONTAINER_RELAY_LOOPBACK_NOT_VERIFIED')
        return self.metadata

    async def handle(self, reader, writer):
        if self.closing or len(self.handlers)>=16:
            writer.close()
            return
        task=asyncio.current_task();self.handlers.add(task)
        process=None;forwarders=[]
        try:
            endpoint='npipe:////./pipe/docker_engine' if os.name=='nt' else 'unix:///var/run/docker.sock'
            env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','HOME','USERPROFILE'}}
            launching=asyncio.create_task(asyncio.create_subprocess_exec(self.docker,'--host',endpoint,'exec','-i','--env','BASH_ENV=/dev/null',self.name,
                '/bin/bash','--noprofile','--norc','-c',TUNNEL,'lcr-relay',str(self.container_port),
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0))
            try:process=await asyncio.shield(launching)
            except asyncio.CancelledError:
                process=await launching
                raise
            async def forward(source,destination):
                total=0
                while chunk:=await source.read(16_384):
                    total+=len(chunk)
                    if total>16_777_216:raise ProductError('CONTAINER_RELAY_BYTE_LIMIT')
                    destination.write(chunk);await destination.drain()
            forwarders=[asyncio.create_task(forward(reader,process.stdin)),asyncio.create_task(forward(process.stdout,writer))]
            async with asyncio.timeout(300):
                done,_=await asyncio.wait(forwarders,return_when=asyncio.FIRST_COMPLETED)
                for finished in done:finished.result()
        except (OSError,ProductError,ConnectionError,TimeoutError):
            pass  # HTTP 호출자는 연결 오류를 받는다. 원문/자격증명을 로그에 쓰지 않는다.
        finally:
            for pending in forwarders:pending.cancel()
            if forwarders:await asyncio.gather(*forwarders,return_exceptions=True)
            if process is not None:
                process.stdin.close()
                try:await asyncio.wait_for(process.wait(),timeout=3)
                except TimeoutError:
                    try:process.kill()
                    except ProcessLookupError:pass
                    await process.wait()
            writer.close()
            try:await writer.wait_closed()
            except (OSError,ConnectionError):pass
            self.handlers.discard(task)

    async def stop(self):
        self.closing=True
        if self.server is not None:
            self.server.close()
        tasks=list(self.handlers)
        for task in tasks:task.cancel()
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)
        # Python3.12의 Server.wait_closed는 열린 연결도 기다린다. 연결 정리를 먼저 끝낸다.
        if self.server is not None:await self.server.wait_closed()
        self.metadata.update(stopped=True,active_connections=len(self.handlers))
        return self.metadata

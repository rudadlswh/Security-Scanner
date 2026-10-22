"""자체 샘플 컨테이너에서 UID/커널 제한/읽기 전용 경계를 실제 확인한다.

고정된 비밀 없는 점검 명령만 실행한다. 모델·CVE·외부 HTTP 요청·원본 수정은 없다.
컨테이너 탈출 방어 전체나 모든 네트워크 경로의 차단을 입증하는 검사가 아니다.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from localcode_review_mcp.container_server import ContainerServer
from localcode_review_mcp.workspace import load_json,save_json,now
from smoke_mcp_assurance import tree_hashes


async def verify(config_path,output):
    output.mkdir(parents=True,exist_ok=False)
    cfg=load_json(config_path)
    profile=cfg['scan_profiles']['container']
    spec=profile['disposable_server']
    root=Path(spec['project_root']).resolve()
    before=tree_hashes(root)
    save_json(output/'expectations.json',{'frozen_at':now(),'image':spec['image'],
        'uid':10001,'effective_capabilities':'0000000000000000','no_new_privileges':1,
        'memory_max':536870912,'pids_max':128,'cpu_quota_equals_period':True,
        'workspace_write_blocked':True,'root_write_blocked':True,'tmp_write_allowed':True,
        'ipv4_default_route_absent':True,'container_logs_unreadable_and_empty':True,
        'all_escape_attacks_tested':False,'source_files':before})
    server=ContainerServer(spec,root,output,[cfg['http_targets'][key] for key in profile['http_target_ids']])
    report={'started_at':now(),'state':'RUNNING','model_calls':0,'external_cve_queries':0,'checks':{}}
    async def execute(*command):
        return (await asyncio.to_thread(server.cli,'exec',server.name,*command)).strip()
    try:
        await server.start()
        checks=report['checks']
        checks['uid']=await execute('/usr/bin/id','-u')
        assert checks['uid']=='10001'
        status=await execute('/bin/cat','/proc/self/status')
        kernel={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
        checks['effective_capabilities']=kernel['CapEff'];checks['no_new_privileges']=kernel['NoNewPrivs']
        assert checks['effective_capabilities']=='0000000000000000' and checks['no_new_privileges']=='1'
        for name,path,expected in [('memory_max','/sys/fs/cgroup/memory.max','536870912'),('pids_max','/sys/fs/cgroup/pids.max','128')]:
            checks[name]=await execute('/bin/cat',path);assert checks[name]==expected
        cpu=await execute('/bin/cat','/sys/fs/cgroup/cpu.max')
        quota,period=cpu.split();checks['cpu_quota_equals_period']=quota==period
        assert checks['cpu_quota_equals_period']
        for name,path in [('workspace_write_blocked','/workspace/.lcr-runtime-write-probe'),('root_write_blocked','/.lcr-runtime-write-probe')]:
            result=await execute('/bin/sh','-c',f'if (: > {path}) 2>/dev/null; then rm -f {path}; exit 17; fi; printf blocked')
            checks[name]=result=='blocked';assert checks[name]
        result=await execute('/bin/sh','-c','p=/tmp/lcr-runtime-write-probe-$$; umask 077; printf probe > "$p" && test -f "$p" && rm -f "$p" && printf writable')
        checks['tmp_write_allowed']=result=='writable';assert checks['tmp_write_allowed']
        routes=await execute('/bin/cat','/proc/net/route')
        checks['ipv4_default_route_absent']=all(row.split()[1]!='00000000' for row in routes.splitlines()[1:] if row.strip())
        assert checks['ipv4_default_route_absent']
        log_result=await asyncio.to_thread(subprocess.run,[server.docker,'--host','npipe:////./pipe/docker_engine' if os.name=='nt' else 'unix:///var/run/docker.sock','logs',server.name],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        checks['container_logs_unreadable_and_empty']=log_result.returncode!=0 and not log_result.stdout
        assert checks['container_logs_unreadable_and_empty']
        report.update(state='PASSED',configuration_inspected=server.metadata['isolation_verified'],universal_escape_resistance=False,
            external_socket_probe_performed=False,network_conclusion='INTERNAL_NETWORK_AND_NO_IPV4_DEFAULT_ROUTE_NOT_ALL_HOST_PATHS_TESTED')
    except Exception as error:
        report.update(state='FAILED',error_type=type(error).__name__,error_code=str(error) if type(error).__name__=='ProductError' else 'RUNTIME_EXPECTATION_NOT_MET')
        raise
    finally:
        try:
            await server.stop()
            remaining_containers=(await asyncio.to_thread(server.cli,'ps','--all','--filter','name=^/'+server.name+'$','--format','{{.Names}}')).strip()
            remaining_networks=(await asyncio.to_thread(server.cli,'network','ls','--filter','name=^'+server.network+'$','--format','{{.Name}}')).strip()
            report['cleanup_verified']=not remaining_containers and not remaining_networks and not server.copy.exists()
            assert report['cleanup_verified']
            report['original_unchanged']=before==tree_hashes(root)
            assert report['original_unchanged']
        finally:
            report['server']=server.metadata;report['finished_at']=now();save_json(output/'report.json',report)
    print(json.dumps({'state':report['state'],'checks':report['checks'],'cleanup_verified':report['cleanup_verified'],'original_unchanged':report['original_unchanged']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    asyncio.run(verify(args.config.resolve(),args.output.resolve()))

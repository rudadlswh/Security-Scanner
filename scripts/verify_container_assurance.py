"""설치된 로컬 Docker와 digest 고정 이미지로 자체 샘플의 실제 컨테이너 경계를 검사한다.

설치·pull·원본 빌드·모델/CVE 호출은 하지 않는다. 엔진/이미지 부재는 실패이며 호스트 실행으로 우회하지 않는다.
"""
import argparse
import asyncio
import base64
import datetime as dt
import json
import os
from pathlib import Path
import socket
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from localcode_review_mcp.workspace import save_json,load_json,now
from smoke_mcp_assurance import plans,tree_hashes,data,PROJECT


async def verify(output,docker,image):
    output.mkdir(parents=True,exist_ok=False)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    targets={}
    # SSRF 테스트의 자기 서버 주소는 컨테이너 내부 포트이며 외부/호스트 주소가 아니다.
    plan_map=plans('http://127.0.0.1:8080')
    for key,plan in plan_map.items():
        planfile=output/(key+'-plan.json');save_json(planfile,plan)
        actions=[a for s in plan['scenarios'] for a in [*s['setup'],s['before'],s['request'],s['after'],*s['cleanup'],s['cleanup_verify']]]
        targets[key]={'base_url':base,'authorized_disposable_environment':True,'plan_file':str(planfile),
            'allowed_paths':sorted({a['path'] for a in actions}),'max_requests':100,'timeout_seconds':120,
            'actors':{'owner':{'headers_env':{'Authorization':'LCR_ASSURANCE_OWNER'}},'non_owner':{'headers_env':{'Authorization':'LCR_ASSURANCE_OTHER'}},'observer':{},'anonymous':{}}}
    spec={'project_root':str(PROJECT),'authorized_disposable_environment':True,'acknowledge_command_execution':True,
          'isolation_backend':'docker','require_os_isolation':True,'docker_executable':str(docker),'image':image,
          'command':['/opt/java/openjdk/bin/java','-Xmx256m','-cp','{project_copy}/build/libs/fixture.jar:{project_copy}/build/runtime/*',
                     'assurance.FixtureApplication','--server.address=0.0.0.0','--server.port={port}'],
          'base_url':base,'container_port':8080,'health_path':'/health','startup_timeout_seconds':90,
          'user':'10001:10001','memory_mib':512,'pids_limit':128,'cpus':1}
    from localcode_review_mcp.container_server import ContainerServer
    ContainerServer(spec,PROJECT,output/'validation',list(targets.values()))  # 전송/실행 전 입력 검증
    cfg={'version':1,'jdk':os.environ['JAVA_HOME'],'projects':{'assurance':{'root':str(PROJECT),'dependency_inventory':str(PROJECT/'build/dependency-inventory.json')}},
         'results_dir':str(output/'product'),'allow_osv_network':False,'http_targets':targets,
         'scan_profiles':{'container':{'project_root':str(PROJECT),'http_target_ids':list(targets),'disposable_server':spec}}}
    save_json(output/'config.json',cfg)
    before=tree_hashes(PROJECT)
    save_json(output/'expectations.json',{'frozen_at':now(),'project_files':before,'static_rules':3,'dynamic_scenarios':13,
        'discrepancies':4,'expected_backend':'DOCKER_LINUX','expected_inspected_isolation':True,
        'scope':'CONFIGURED_RESTRICTIONS_AND_HTTP_NOT_ESCAPE_RESISTANCE_PROOF'})
    params=StdioServerParameters(command=sys.executable,args=['-u',str(ROOT/'mcp_server.py'),'--config',str(output/'config.json')],cwd=str(ROOT),
        env={**os.environ,'LCR_ASSURANCE_OWNER':'Basic '+base64.b64encode(b'owner:fixture-only').decode(),
             'LCR_ASSURANCE_OTHER':'Basic '+base64.b64encode(b'other:fixture-only').decode()})
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write,read_timeout_seconds=dt.timedelta(seconds=120)) as session:
            await session.initialize()
            started=data(await session.call_tool('scan_project',{'project_path':str(PROJECT),'max_ai_endpoints':0,'include_remediation':False}))
            for _ in range(600):
                state=data(await session.call_tool('get_project_scan_status',{'job_id':started['job_id']}))
                if state['state'] in {'COMPLETED','FAILED','CANCELLED','INTERRUPTED'}:break
                await asyncio.sleep(.5)
            report=data(await session.call_tool('read_project_scan_report',{'job_id':started['job_id']}))
            save_json(output/'report.json',report)
    assert report['checks']['dynamic']['status']=='COMPLETED',report['checks']['dynamic']
    server=report['disposable_server']
    assert server['backend']=='DOCKER_LINUX' and server['isolation_verified'] and server['os_security_sandbox']
    assert server['stopped'] and server['workspace_removed']
    assert sum(f['kind']=='DYNAMIC_BEHAVIOR_DISCREPANCY' for f in report['findings'])==4
    assert before==tree_hashes(PROJECT)
    save_json(output/'summary.json',{'status':'PASSED','verified_at':now(),'inspected_container_restrictions':True,
        'original_unchanged':True,'server_and_network_removed':True,'universal_escape_resistance':False,'model_calls':0,'external_cve_queries':0})
    print('Container configuration, HTTP cases and cleanup passed; no escape-resistance claim.')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--docker',required=True,type=Path)
    parser.add_argument('--image',required=True,help='installed image reference with @sha256 digest')
    args=parser.parse_args()
    asyncio.run(verify(args.output.resolve(),args.docker.resolve(),args.image))

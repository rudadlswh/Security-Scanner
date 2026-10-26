"""Registered read-only Python HTTP/browser checks, bound to sources and plans."""
import asyncio
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlencode,urlsplit

import httpx

from .disposable import DisposableServer,WindowsJob
from .python_tools import tool_python
from .workspace import ProductError,ProductStore,digest,inside,load_json,save_json,now


def validate(spec,snapshot,info):
    if spec.get('authorized_read_only_checks') is not True:
        raise ProductError('PYTHON_VALIDATION_EXPLICIT_AUTHORIZATION_REQUIRED')
    path=Path(spec['plan_file']).resolve()
    if path.is_relative_to(snapshot.root):raise ProductError('PYTHON_PLAN_MUST_BE_OUTSIDE_TARGET')
    plan=load_json(path)
    if digest(plan)!=spec.get('plan_sha256') or plan.get('contract')!='python-http-validation/1':
        raise ProductError('PYTHON_HTTP_PLAN_HASH_MISMATCH')
    for name,expected in plan.get('source_files',{}).items():
        if name not in snapshot.files or digest(snapshot.files[name])!=expected:
            raise ProductError('PYTHON_HTTP_SOURCE_MISMATCH')
    if not plan.get('source_files'):raise ProductError('PYTHON_HTTP_SOURCE_BINDING_REQUIRED')
    routes={e['http_path'] for e in info['endpoints']}
    negatives=plan.get('negative_paths',[])
    if not isinstance(negatives,list) or any(not isinstance(p,str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{1,200}',p) or '..' in p or p.startswith('//') for p in negatives):
        raise ProductError('PYTHON_NEGATIVE_PATH_INVALID')
    cases=plan.get('cases',[])
    if not 1<=len(cases)<=80 or len({c.get('id') for c in cases})!=len(cases):raise ProductError('PYTHON_HTTP_CASE_LIMIT')
    for case in cases:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',case.get('id','')):raise ProductError('PYTHON_HTTP_CASE_ID')
        if case.get('path') not in routes and not (case.get('path') in negatives and case.get('expect_status')==404):raise ProductError('PYTHON_HTTP_PATH_NOT_COLLECTED')
        if case.get('method','GET')!='GET':raise ProductError('PYTHON_READ_ONLY_GET_REQUIRED')
        if case.get('expect_status') not in (200,400,401,403,404):raise ProductError('PYTHON_HTTP_STATUS_REQUIRED')
        if not isinstance(case.get('query',{}),dict) or len(urlencode(case.get('query',{})))>4096:raise ProductError('PYTHON_QUERY_LIMIT')
        if case.get('actor','anonymous') not in {'anonymous','alice','bob','invalid'}:raise ProductError('PYTHON_ACTOR_INVALID')
        headers=case.get('headers',{})
        if not isinstance(headers,dict) or any(k not in {'Host','Origin'} or not isinstance(v,str) or len(v)>256 or any(c in v for c in '\r\n\0') for k,v in headers.items()):
            raise ProductError('PYTHON_NEGATIVE_HEADER_INVALID')
        for assertion in case.get('assertions',[]):
            if assertion.get('kind') not in {'body_contains','header_contains'} or type(assertion.get('present')) is not bool or not isinstance(assertion.get('value'),str) or len(assertion['value'])>512:
                raise ProductError('PYTHON_HTTP_ASSERTION_INVALID')
        if case.get('binding'):
            b=case['binding']
            if b.get('path') not in plan['source_files'] or b.get('sha256')!=plan['source_files'][b['path']] or type(b.get('line')) is not int:
                raise ProductError('PYTHON_SINK_BINDING_INVALID')
        if case.get('forbid_rule') and case['forbid_rule'] not in {'LCR-PY-SQL-001','LCR-PY-XSS-001','LCR-PY-IDOR-001','LCR-PY-PATH-001'}:
            raise ProductError('PYTHON_NEGATIVE_RULE_INVALID')
    sessions=plan.get('session_path')
    if sessions and sessions not in routes:raise ProductError('PYTHON_SESSION_PATH_NOT_COLLECTED')
    return plan,path


def browser_worker(settings,base,cases):
    python=tool_python(settings,'browser_python')
    if not isinstance(settings.get('playwright_version'),str):raise ProductError('PLAYWRIGHT_VERSION_PIN_REQUIRED')
    script=Path(__file__).with_name('python_browser.py')
    process=subprocess.Popen([str(python),'-I','-B',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    job=None
    try:
        if os.name=='nt':job=WindowsJob(process)
        else:raise ProductError('PYTHON_BROWSER_JOB_GUARD_WINDOWS_REQUIRED')
        payload={'base_url':base,'playwright_version':settings['playwright_version'],'cases':cases}
        stdout,stderr=process.communicate(json.dumps(payload).encode(),timeout=45)
        if process.returncode or len(stdout)>1048576:raise ProductError('BROWSER_PROBE_FAILED')
        result=json.loads(stdout)
        result['worker_sha256']=digest(script.read_bytes())
        return result
    except subprocess.TimeoutExpired:
        raise ProductError('BROWSER_PROBE_TIMEOUT') from None
    finally:
        if job:job.close()
        if process.poll() is None:process.kill()
        process.wait(timeout=10)


async def run(config,project_id,snapshot,info,static,profile,parent_folder):
    spec=profile['python_validation'];plan,plan_path=validate(spec,snapshot,info)
    store=ProductStore(config.results);identifier=store.create('http',{'kind':'python-http-validation','project_id':project_id,'plan_sha256':digest(plan)})
    folder=store.folder(identifier);base=profile['disposable_server']['base_url']
    report={'kind':'python-http-validation','report_id':identifier,'project_id':project_id,'status':'RUNNING',
        'plan_sha256':digest(plan),'source_snapshot_sha256':digest(snapshot.metadata()),'source_files':plan['source_files'],
        'cases':[],'requests_sent':0,'model_calls':0,'started_at':now(),'browser':{'status':'SKIPPED','reason':'BROWSER_NOT_CONFIGURED'}}
    server_spec={**profile['disposable_server'],'expected_source_files':plan['source_files']}
    server=DisposableServer(server_spec,snapshot.root,folder,
        [{'base_url':base,'authorized_disposable_environment':True}])
    deadline=time.monotonic()+90
    async def request(client,path,**kwargs):
        if time.monotonic()>=deadline:raise ProductError('PYTHON_HTTP_TIME_LIMIT')
        if report['requests_sent']>=100:raise ProductError('PYTHON_HTTP_REQUEST_LIMIT')
        report['requests_sent']+=1
        async with client.stream('GET',base+path,**kwargs) as response:
            raw=bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw)>1048576:raise ProductError('PYTHON_HTTP_RESPONSE_LIMIT')
            return response.status_code,bytes(raw),response.headers
    try:
        snapshot.verify();await server.start()
        actors={}
        async with httpx.AsyncClient(timeout=5,trust_env=False,follow_redirects=False) as client:
            if plan.get('session_path'):
                code,raw,_=await request(client,plan['session_path'])
                if code!=200:raise ProductError('PYTHON_FIXTURE_SESSIONS_FAILED')
                actors=json.loads(raw)
                if any(not isinstance(actors.get(k),str) or len(actors[k])>256 for k in ('alice','bob')):raise ProductError('PYTHON_FIXTURE_SESSIONS_INVALID')
            for case in plan['cases']:
                if digest(load_json(plan_path))!=report['plan_sha256']:raise ProductError('PYTHON_HTTP_PLAN_CHANGED')
                headers=dict(case.get('headers',{}));actor=case.get('actor','anonymous')
                if actor!='anonymous':headers['X-Lab-Session']=actors[actor] if actor in actors else 'invalid'
                path=case['path']+('?' + urlencode(case['query']) if case.get('query') else '')
                code,raw,received=await request(client,path,headers=headers)
                assertions=[]
                for a in case.get('assertions',[]):
                    value=raw.decode('utf-8',errors='replace') if a['kind']=='body_contains' else received.get(a['header'],'')
                    present=a['value'] in value
                    assertions.append({'kind':a['kind'],'literal_sha256':digest(a['value'].encode()),
                        'expected_present':a['present'],'actual_present':present,'matches':present is a['present']})
                row={'id':case['id'],'path':case['path'],'actor':actor,'query_sha256':digest(case.get('query',{})),
                    'status_code':code,'expected_status_code':case['expect_status'],'body_sha256':digest(raw),
                    'assertions':assertions,'matches':code==case['expect_status'] and all(a['matches'] for a in assertions),
                    'intent':case.get('intent','REGISTERED_BEHAVIOR'),'binding':case.get('binding'),
                    'source_link_status':'NO_REGISTERED_SINK_BINDING'}
                if case.get('forbid_rule'):
                    forbidden=any(f['rule_id']==case['forbid_rule'] and any(e['endpoint_id'] in f.get('endpoint_ids',[]) and e['http_path']==case['path'] for e in info['endpoints']) for f in static['findings'])
                    row['negative_source_matches']=not forbidden
                    row['matches']=row['matches'] and not forbidden
                if case.get('binding'):
                    b=case['binding'];matches=[f for f in static['findings'] if f['rule_id']==b['rule_id'] and
                        f['path']==b['path'] and f['line']==b['line'] and f['file_sha256']==b['sha256'] and
                        (not f.get('endpoint_ids') or any(e['endpoint_id'] in f['endpoint_ids'] and e['http_path']==case['path'] for e in info['endpoints']))]
                    row['source_link_status']='MATCHED_STATIC_CANDIDATE' if matches else 'REGISTERED_CANDIDATE_NOT_FOUND'
                    row['static_evidence_ids']=[f['evidence_id'] for f in matches]
                report['cases'].append(row);save_json(folder/'report.json',report,replace=(folder/'report.json').exists())
        browser_cases=[]
        for case in plan['cases']:
            if case.get('browser'):
                b=case['browser']
                if not isinstance(b.get('title_marker'),str) or len(b['title_marker'])>80 or type(b.get('expected_execution')) is not bool:raise ProductError('PYTHON_BROWSER_ASSERTION_INVALID')
                browser_cases.append({'id':case['id'],'path':case['path']+'?'+urlencode(case.get('query',{})),
                    'expect_status':case['expect_status'],**b})
        if browser_cases and spec.get('browser_python'):
            task=asyncio.create_task(asyncio.to_thread(browser_worker,spec,base,browser_cases))
            try:observed=await asyncio.shield(task)
            except asyncio.CancelledError:
                await task;raise
            report['browser']={'status':'COMPLETED',**observed}
        links=all(c['source_link_status']=='MATCHED_STATIC_CANDIDATE' for c in report['cases'] if c.get('binding'))
        matches=all(c['matches'] for c in report['cases']) and all(c['matches'] for c in report['browser'].get('cases',[]))
        report['status']='COMPLETED' if matches and links else 'NEEDS_REVISION'
        if browser_cases and report['browser']['status']!='COMPLETED':
            report.update(status='PARTIAL',reason='REGISTERED_BROWSER_CASES_NOT_EXECUTED')
    except asyncio.CancelledError:
        report['status']='CANCELLED';raise
    except (Exception,) as error:
        report.update(status='INCOMPLETE',reason=str(error) if isinstance(error,ProductError) else type(error).__name__)
    finally:
        await server.stop();report['server']=server.metadata
        snapshot.verify();report['source_snapshot_unchanged']=True;report['ended_at']=now()
        save_json(folder/'report.json',report,replace=(folder/'report.json').exists())
    return report

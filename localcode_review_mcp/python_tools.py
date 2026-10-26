"""Local-only Python detector adapters. Project code is parsed, never imported.

Only an operator-configured interpreter/version is used; no automatic installs.
Bandit's source excerpts and free text are discarded before persistence.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import os
import re

from .python_source import Flow
from .workspace import ProductError, ProductStore, digest, inside, save_json


def settings_for(config,project_id):
    root,project=config.project(project_id)
    profiles=[p for p in config.scan_profiles.values() if p.get('project_root') and Path(p['project_root']).resolve()==root]
    if len(profiles)>1:raise ProductError('PROJECT_SCAN_PROFILE_AMBIGUOUS')
    return project.get('python_analysis',profiles[0].get('python_analysis',{}) if profiles else {})


def tool_python(settings,key):
    value=settings.get(key)
    if not isinstance(value,str) or not Path(value).is_absolute() or not Path(value).is_file():
        raise ProductError('PYTHON_TOOL_INTERPRETER_NOT_CONFIGURED')
    return Path(value)


def invoke(argv,cwd,timeout=60):
    # -I ignores PYTHONPATH and user/site cwd injection. Project configuration
    # files are never copied to cwd. Raw output remains in memory only.
    result=subprocess.run([str(x) for x in argv],cwd=cwd,capture_output=True,timeout=timeout,
        stdin=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    if len(result.stdout)>8*1048576:raise ProductError('PYTHON_TOOL_OUTPUT_LIMIT')
    return result


def bandit_findings(snapshot,settings,run_dir):
    if not settings.get('bandit_python'):
        return [],{'status':'SKIPPED','reason':'BANDIT_NOT_OPERATOR_CONFIGURED'}
    python=tool_python(settings,'bandit_python')
    expected=settings.get('bandit_version')
    if not isinstance(expected,str):raise ProductError('BANDIT_VERSION_PIN_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='bandit-',dir=run_dir) as temporary:
        stage=Path(temporary)
        names=[]
        for name,data in snapshot.files.items():
            if name.endswith('.py'):
                p=inside(stage,name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);names.append(p)
        version=invoke([python,'-I','-B','-c','import importlib.metadata;print(importlib.metadata.version("bandit"))'],stage,20)
        if version.returncode or version.stdout.decode().strip()!=expected:raise ProductError('BANDIT_VERSION_MISMATCH')
        result=invoke([python,'-I','-B','-m','bandit','-q','--ignore-nosec','-f','json',*names],stage)
        if result.returncode not in (0,1):raise ProductError('BANDIT_EXECUTION_FAILED')
        try:data=json.loads(result.stdout)
        except ValueError:raise ProductError('BANDIT_JSON_INVALID') from None
        if data.get('errors'):raise ProductError('BANDIT_ANALYSIS_ERRORS')
        rows=[]
        for item in data.get('results',[]):
            p=Path(item['filename']).resolve()
            if not p.is_relative_to(stage.resolve()):raise ProductError('BANDIT_RESULT_PATH_ESCAPE')
            name=p.relative_to(stage).as_posix();line=item['line_number'];rule=item['test_id']
            if name not in snapshot.files or type(line) is not int or not 1<=line<=len(snapshot.files[name].splitlines()) or not re.fullmatch(r'B[0-9]{3}',rule):
                raise ProductError('BANDIT_EVIDENCE_INVALID')
            rows.append({'kind':'STATIC_SECURITY_CANDIDATE','rule_id':rule,'path':name,'line':line,
                'file_sha256':digest(snapshot.files[name]),'engine':'BANDIT','engine_version':expected,
                'severity':item.get('issue_severity'),'confidence':item.get('issue_confidence'),
                'cwe':item.get('issue_cwe',{}).get('id'),'identifiers':[f'{rule}:{name}:{line}'],
                'basis':'BANDIT_AST_RULE_NOT_RUNTIME_PROOF','security_cause_confirmed':False,
                'endpoint_ids':[],'source_parameters':[],'remediation':{'source':'BANDIT_RULE_REFERENCE','status':'REVIEW_REQUIRED',
                    'automatic_apply':False,'change':'Review the indicated Bandit rule against the bound source.',
                    'tests':['Run rule-specific normal and negative cases; a rule match alone is not runtime proof.']}})
        return rows,{'status':'COMPLETED','engine':'BANDIT','version':expected,'interpreter_sha256':digest(python.read_bytes()),
                    'exit_code':result.returncode,'raw_source_excerpts_saved':False,'ignore_project_nosec':True,'candidate_count':len(rows)}


def scan_python_security(config,project_id,prepared):
    snapshot,parsed,info=prepared;store=ProductStore(config.results)
    identifier=store.create('sast',{'kind':'source-security','project_id':project_id})
    findings=[];errors=list(parsed['errors'])
    for endpoint in parsed['endpoints']:
        try:findings.extend(Flow(snapshot,parsed,endpoint).run().findings)
        except ProductError as error:errors.append({'endpoint_id':endpoint['endpoint_id'],'reason':str(error)})
    bandit=[];engine={'status':'NOT_RUN'}
    try:bandit,engine=bandit_findings(snapshot,settings_for(config,project_id),store.folder(identifier))
    except (ProductError,subprocess.TimeoutExpired) as error:
        engine={'status':'INCOMPLETE','reason':str(error) if isinstance(error,ProductError) else 'BANDIT_TIMEOUT'}
        errors.append({'engine':'BANDIT','reason':engine['reason']})
    findings.extend(bandit)
    if len(findings)>500:raise ProductError('PYTHON_FINDING_LIMIT')
    for i,row in enumerate(findings,1):row['evidence_id']=f'PS{i:04}'
    snapshot.verify()
    report={'kind':'source-security','report_id':identifier,'project_id':project_id,
        'source_language':'Python','status':'PARTIAL' if errors or snapshot.excluded or engine['status']!='COMPLETED' else 'COMPLETED_FOR_RULESET',
        'findings':findings,'errors':errors,'engines':{'localcode':'PYTHON_HTTP_SERVER_AST_1','bandit':engine},
        'ruleset':'PYTHON_HTTP_SERVER_AND_BANDIT_1','model_calls':0,'snapshot_sha256':digest(snapshot.metadata()),
        'source_snapshot_unchanged':True,'coverage':{'source_files':sum(n.endswith('.py') for n in snapshot.files),
        'method':'AST_LITERAL_DISPATCH_BOUNDED_FLOW_AND_OPTIONAL_BANDIT','max_call_depth':8,
        'rules':['LCR-PY-SQL-001','LCR-PY-XSS-001','LCR-PY-IDOR-001','LCR-PY-PATH-001'],
        'bandit':engine,'limits':['http.server literal dispatch only; no Flask/Django/ASGI claims.',
        'Ownership/containment guard recognition is syntactic, not caller trust proof.',
        'No complete Python type, alias, reflection, async or arbitrary sanitizer analysis.',
        'Multiple engines can report the same defect; candidate count is not distinct vulnerabilities.',
        'Python source is local-only and not eligible for existing Java AI contracts.']}}
    save_json(store.folder(identifier)/'report.json',report);return report

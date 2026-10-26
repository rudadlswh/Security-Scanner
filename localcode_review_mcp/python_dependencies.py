"""Exact PyPI manifest inventory and explicitly enabled pip-audit adapter."""
import json
from pathlib import Path
import re
import tempfile

from .python_source import PythonSnapshot
from .python_tools import settings_for,tool_python,invoke
from .workspace import ProductError,ProductStore,digest,save_json,now


def inventory(config,project_id,snapshot=None):
    root,project=config.project(project_id)
    snapshot=snapshot or PythonSnapshot.read(root,project.get('commit'))
    packages={};unresolved=[]
    for name,data in snapshot.files.items():
        if Path(name).name!='requirements.txt':continue
        for line,text in enumerate(data.decode('utf-8-sig').splitlines(),1):
            text=text.strip()
            if not text or text.startswith('#'):continue
            match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)',text)
            if not match:
                unresolved.append({'source':name,'line':line,'reason':'ONLY_EXACT_PYPI_PINS_SUPPORTED'});continue
            package,version=match.groups();package=re.sub(r'[-_.]+','-',package).lower()
            packages.setdefault((package,version),{'ecosystem':'PyPI','name':package,'version':version,
                'sources':[],'bases':['EXACT_REQUIREMENTS_PIN'],'scope':'DECLARED_NOT_RUNTIME'} )['sources'].append(name)
    snapshot.verify()
    return {'project_id':project_id,'packages':list(packages.values()),'unresolved':unresolved,
        'coverage':'DECLARATIONS_ONLY_TRANSITIVES_INCOMPLETE','snapshot_sha256':digest(snapshot.metadata()),
        'source_ecosystem':'PyPI','runtime_use_proven':False}


def scan(config,project_id,snapshot):
    listed=inventory(config,project_id,snapshot);settings=settings_for(config,project_id)
    store=ProductStore(config.results);identifier=store.create('cve',{'kind':'dependency-cve','project_id':project_id})
    rows=[];raw_count=0;queried=0
    enabled=settings.get('allow_pypi_network') is True and settings.get('pip_audit_python')
    if listed['packages'] and enabled:
        if listed['unresolved'] or len(listed['packages'])>100:raise ProductError('PYPI_EXACT_MANIFEST_REQUIRED')
        python=tool_python(settings,'pip_audit_python');expected=settings.get('pip_audit_version')
        if not isinstance(expected,str):raise ProductError('PIP_AUDIT_VERSION_PIN_REQUIRED')
        with tempfile.TemporaryDirectory(prefix='pypi-',dir=store.folder(identifier)) as temporary:
            stage=Path(temporary);manifest=stage/'requirements.txt'
            manifest.write_text('\n'.join(f"{p['name']}=={p['version']}" for p in listed['packages']),encoding='utf-8')
            version=invoke([python,'-I','-B','-c','import importlib.metadata;print(importlib.metadata.version("pip-audit"))'],stage,20)
            if version.returncode or version.stdout.decode().strip()!=expected:raise ProductError('PIP_AUDIT_VERSION_MISMATCH')
            result=invoke([python,'-I','-B','-m','pip_audit','-r',manifest,'--no-deps','--disable-pip',
                '--cache-dir',stage/'cache','--timeout','15','--progress-spinner','off','-f','json'],stage,120)
            if result.returncode not in (0,1):raise ProductError('PIP_AUDIT_EXECUTION_FAILED')
            try:data=json.loads(result.stdout)
            except ValueError:raise ProductError('PIP_AUDIT_JSON_INVALID') from None
            returned={(re.sub(r'[-_.]+','-',d['name']).lower(),d['version']):d for d in data['dependencies']}
            if set(returned)!={(p['name'],p['version']) for p in listed['packages']}:raise ProductError('PIP_AUDIT_PACKAGE_MISMATCH')
            for package in listed['packages']:
                dependency=returned[(package['name'],package['version'])]
                if dependency.get('skip_reason'):raise ProductError('PIP_AUDIT_PACKAGE_SKIPPED')
                matches=[];groups=[]
                for v in dependency.get('vulns',[]):
                    raw_count+=1
                    identities={v['id'],*v.get('aliases',[])}
                    if any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',i) for i in identities):raise ProductError('PYPI_ADVISORY_ID_INVALID')
                    match={'id':v['id'],'aliases':v.get('aliases',[]),
                        'fixed_versions_from_matching_package':v.get('fix_versions',[]),
                        'source':'https://pypi.org/pypi/'+package['name']+'/'+package['version']+'/json',
                        'fix_selection':'CHECK_BRANCH_AND_DEPENDENCY_COMPATIBILITY','exploitability':'NOT_TESTED',
                        'impact':'PYPI_REPORTED_VERSION_MATCH'}
                    matches.append(match)
                    overlapping=[g for g in groups if identities.intersection(g['identifiers'])]
                    merged={'identifiers':sorted(identities),'advisories':[match]}
                    for g in overlapping:
                        merged['identifiers']=sorted(set(merged['identifiers'])|set(g['identifiers']));groups.remove(g)
                        merged['advisories'].extend(g['advisories'])
                    groups.append(merged)
                rows.append({'package':package,'status':'CHECKED_ONLINE','vulnerabilities':matches,'vulnerability_groups':groups})
            queried=len(rows)
    else:
        rows=[{'package':p,'status':'NOT_QUERIED_NETWORK_OR_TOOL_NOT_APPROVED','vulnerabilities':None} for p in listed['packages']]
    snapshot.verify()
    report={'kind':'dependency-cve','report_id':identifier,'project_id':project_id,'recorded_at':now(),
        'status':'COMPLETED_FOR_LISTED_PACKAGES' if queried and not listed['unresolved'] else 'PARTIAL',
        'inventory':listed,'packages':rows,'queries_sent':queried,'raw_advisory_count':raw_count,
        'unique_package_advisory_count':sum(len(r.get('vulnerability_groups',[])) for r in rows),
        'model_calls':0,'package_installations':0,'source':'PyPI via pinned pip-audit',
        'limits':['Only exact direct manifest pins, no installation or transitive resolution.',
                  'A version match does not prove runtime use or exploitability.']}
    save_json(store.folder(identifier)/'report.json',report);return report

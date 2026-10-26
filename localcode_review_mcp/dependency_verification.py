"""승인된 복사본 수정의 정확한 런타임 버전·등록 CVE 재현 시나리오·호환 명령을 연결한다.
공지와 시나리오의 인과관계는 운영자 지정이며 별도 검토 없이 악용 확정으로 승격하지 않는다.
"""
from .workspace import ProductError, digest


def evaluate_dependency_fix(before, after, plan, before_http, after_http, builds):
    if plan.get('contract')!='dependency-fix-plan/1':raise ProductError('DEPENDENCY_FIX_PLAN_INVALID')
    if any(inv.get('coverage')!='RESOLVED_RUNTIME_WITH_HASH_BINDING' or inv.get('unresolved') for inv in (before,after)):
        raise ProductError('DEPENDENCY_FIX_BOUND_RUNTIME_REQUIRED')
    required=plan.get('required_versions')
    if not isinstance(required,dict) or not required or any(not isinstance(k,str) or not isinstance(v,str) or not v for k,v in required.items()):
        raise ProductError('DEPENDENCY_FIX_EXACT_VERSIONS_REQUIRED')
    before_versions={};after_versions={}
    for inv,result in ((before,before_versions),(after,after_versions)):
        for p in inv['packages']:result.setdefault(p['name'],set()).add(p['version'])
    versions=[{'package':name,'before':sorted(before_versions.get(name,set())),
               'expected_after':version,'after':sorted(after_versions.get(name,set())),
               'matches':after_versions.get(name)=={version}} for name,version in required.items()]
    passed={b['argv_sha256'] for b in builds if b.get('exit_code')==0}
    commands=plan.get('compatibility_command_sha256',[])
    if not isinstance(commands,list) or not commands or any(not isinstance(c,str) or len(c)!=64 for c in commands):
        raise ProductError('DEPENDENCY_COMPATIBILITY_COMMANDS_REQUIRED')
    def lookup(reports,target,scenario):
        rows=[s for r in reports if r.get('target_id')==target and r.get('status')=='COMPLETED'
              for s in r.get('scenarios',[]) if s.get('id')==scenario]
        if len(rows)!=1:raise ProductError('DEPENDENCY_PROBE_MISSING_OR_AMBIGUOUS')
        return rows[0]
    probes=plan.get('advisory_probes',[]);results=[]
    if not isinstance(probes,list) or not probes:raise ProductError('DEPENDENCY_ADVISORY_PROBES_REQUIRED')
    for probe in probes:
        if not probe.get('advisory_id') or not isinstance(probe.get('advisory_sha256'),str) or len(probe['advisory_sha256'])!=64:
            raise ProductError('DEPENDENCY_ADVISORY_BINDING_REQUIRED')
        a=lookup(before_http,probe['target_id'],probe['scenario_id']);b=lookup(after_http,probe['target_id'],probe['scenario_id'])
        results.append({'advisory_id':probe['advisory_id'],'advisory_sha256':probe['advisory_sha256'],
                        'scenario_id':probe['scenario_id'],'before_sha256':digest(a),'after_sha256':digest(b),
                        'before_status':a.get('status'),'after_status':b.get('status'),
                        'matches':a.get('status')=='BEHAVIOR_DISCREPANCY' and b.get('status')=='MATCHES_EXPECTED_BEHAVIOR'})
    ok=all(v['matches'] for v in versions) and all(p['matches'] for p in results) and set(commands)<=passed
    return {'contract':'dependency-fix-verification/1','status':'MATCHES_REGISTERED_CHECKS' if ok else 'NEEDS_REVISION',
            'plan_sha256':digest(plan),'before_inventory_sha256':digest(before),'after_inventory_sha256':digest(after),
            'versions':versions,'probes':results,'registered_compatibility_commands_passed':set(commands)<=passed,
            'advisory_causality':'OPERATOR_DECLARED_NOT_INDEPENDENTLY_REVIEWED',
            'deployment_compatibility_proven':False,'all_cves_fixed':False}

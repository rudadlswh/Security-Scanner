"""소스 파일·HTTP 경계·지원 sink의 명시 원장. 미해결 경계는 보류한다."""
from .workspace import digest

MAX_SURFACES = 1500


def surface_inventory(snapshot, info):
    rows = []
    for path, data in sorted(snapshot.files.items()):
        rows.append({'id':'file-'+digest(path.encode())[:24],'kind':'SOURCE_FILE',
                     'path':path,'sha256':digest(data),'execution_status':'COMPLETED',
                     'basis':'INVENTORIED_BYTES_NOT_SEMANTIC_COVERAGE'})
    for endpoint in info['endpoints']:
        rows.append({'id':'boundary-'+endpoint['endpoint_id'],'kind':'HTTP_TRUST_BOUNDARY',
                     'endpoint_id':endpoint['endpoint_id'],'http_method':endpoint['http_method'],
                     'http_path':endpoint['http_path'],'mapping_status':endpoint['mapping_status'],
                     'execution_status':'PENDING','basis':'DECLARED_HTTP_INPUT_TO_APPLICATION_NOT_RUNTIME_PROVEN'})
    for reason in info.get('support_reasons',[]):
        rows.append({'id':'gap-'+digest(reason.encode())[:24],'kind':'UNSUPPORTED_SCOPE',
                     'reason':reason,'execution_status':'PARTIAL','basis':'EXPLICIT_COLLECTION_LIMITATION'})
    return {'contract':'audit-surfaces/1','items':rows[:MAX_SURFACES],
            'omitted':max(0,len(rows)-MAX_SURFACES),'completeness':'BOUNDED_DECLARATIONS_NOT_ALL_ATTACK_SURFACES'}


def surface_scopes(report):
    endpoints = {r['endpoint_id']:r for r in report.get('endpoints',[])}
    rows = []
    for original in report.get('surface_inventory',{}).get('items',[]):
        row = dict(original)
        if row['kind'] == 'HTTP_TRUST_BOUNDARY':
            endpoint = endpoints.get(row['endpoint_id'],{})
            resolved = endpoint.get('collection_status') == 'COMPLETED' and endpoint.get('unresolved_calls') == 0 and row['mapping_status'] == 'AST_LITERAL'
            row['execution_status'] = 'COMPLETED' if resolved else 'PARTIAL'
            row['collection_id'] = endpoint.get('collection_id')
            row['unresolved_calls'] = endpoint.get('unresolved_calls')
        rows.append(row)
    for finding in report['findings']:
        if finding['kind'] != 'STATIC_SECURITY_CANDIDATE': continue
        rows.append({'id':'sink-'+finding['finding_id'],'kind':'SOURCE_TO_SINK_CANDIDATE',
                     'finding_id':finding['finding_id'],'path':finding.get('path'),'line':finding.get('line'),
                     'rule_id':finding.get('rule_id'),'report_id':finding.get('report_id'),
                     'execution_status':'COMPLETED','basis':'STATIC_CANDIDATE_NOT_VALIDATED'})
    return [{'id':r['id'],'state':'unreviewed' if r['execution_status']=='COMPLETED' else 'deferred',
             'execution_status':r['execution_status'],'evidence_sha256':digest(r),
             'kind':r['kind'],'reason':r.get('reason'),'detail':r} for r in rows]

"""기능: Java AST 입력-위험 호출 후보를 수집하고 근거 위치·조건부 수정 절차를 보고한다.

연결: 폴더 통합 검사 → 읽기 전용 Snapshot/bridge → 후보와 미지원 범위. 모델은 호출하지 않는다.
"""
from .collector import bridge
from .workspace import ProductStore, Snapshot, digest, save_json

REMEDIES = {
    'LCR-SQL-001': {'title':'HTTP 입력을 포함한 동적 SQL 후보', 'change':'SQL 구조는 상수로 두고 JDBC/JPA 바인딩 매개변수로 입력값을 전달한다.',
                    'tests':['정상 입력과 SQL 구문이 포함된 입력의 조회 범위를 비교한다.', '바인딩한 입력이 SQL 조건으로 해석되지 않는지 확인한다.']},
    'LCR-XSS-001': {'title':'HTTP 입력의 HTML 출력 후보', 'change':'HTML 문맥에 맞는 출력 인코딩을 적용하거나 text/plain 응답으로 제한한다.',
                    'tests':['HTML 태그 입력이 실행 가능한 HTML로 응답되지 않는지 확인한다.', '정상 텍스트 표시와 응답 Content-Type을 확인한다.']},
    'LCR-SSRF-001': {'title':'HTTP 입력을 외부 요청 주소로 사용하는 후보', 'change':'임의 URL 대신 서버가 고정한 대상 목록을 선택하고 리다이렉트·DNS/IP 검증을 함께 검토한다.',
                    'tests':['허용한 대상만 호출되는지 확인한다.', '미허용 주소·리다이렉트·내부 주소 요청을 차단하는지 검증한다.']},
}


def scan_source_security(config, project_id, prepared=None):
    root, settings = config.project(project_id)
    snapshot = prepared[0] if prepared else Snapshot.read(root, settings.get('commit'))
    files = sorted(p for p in snapshot.files if p.endswith('.java'))
    result = bridge(config, {'operation':'security','root':str(root),'files':files}) if files else {'findings':[], 'errors':[], 'endpoint_methods_inspected':0}
    for index, finding in enumerate(result['findings'], 1):
        finding.update(evidence_id=f'S{index:04}', kind='STATIC_SECURITY_CANDIDATE',
                       identifiers=[f"{finding['rule_id']}:{finding['path']}:{finding['line']}"],
                       basis='AST_HTTP_INPUT_TO_SINK', security_cause_confirmed=False,
                       remediation={**REMEDIES[finding['rule_id']], 'source':'HARNESS_RULE_TEMPLATE',
                                    'automatic_apply':False,'status':'REVIEW_REQUIRED'})
    snapshot.verify()
    store = ProductStore(config.results)
    identifier = store.create('sast', {'kind':'source-security','project_id':project_id})
    report = {**result,'report_id':identifier,'kind':'source-security','project_id':project_id,
        'status':'PARTIAL' if result['errors'] or snapshot.excluded else 'COMPLETED_FOR_RULESET',
        'snapshot_sha256':digest(snapshot.metadata()), 'source_snapshot_unchanged':True,
        'ruleset':'JAVA_HTTP_SQL_HTML_SSRF_2','model_calls':0,
        'coverage':{'method':'AST_BOUNDED_DECLARED_CALL_TAINT','max_call_depth':8,'rules':list(REMEDIES),
                    'source_files':len(files),'excluded':snapshot.excluded,
                    'limits':['No complete type or external symbol resolution.',
                              'Direct unique declared calls propagate parameters up to 8 levels; ambiguous/interface dispatch, reflection, async timing and return-value summaries remain incomplete.',
                              'Only annotated request parameters and supported sinks; absence is not safety.',
                              'Sanitizer recognition is limited; each candidate requires source review.']}}
    save_json(store.folder(identifier)/'report.json', report)
    return report

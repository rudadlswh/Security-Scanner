"""검사 실행과 별개인 범위·후보 원장. 검토는 인증되지 않은 로컬 선언이다."""
from .contracts import bounded_document, canonical_id, exact_fields, unique_ids
from .workspace import ProductError, ProductStore, Snapshot, digest, now, save_json
from .audit_surface import surface_scopes
from .audit_identity import verify_signature

VERSION = 'audit-ledger/1'
SIGNED_VERSION = 'audit-ledger/2'
FINISHED = {'COMPLETED', 'COMPLETED_FOR_RULESET'}


def project_ledger(report):
    """실행 근거가 있어도 자동 covered/validated 승격하지 않는다."""
    scopes = []
    for name, check in report['checks'].items():
        status = check['status']
        state = ('unreviewed' if status in FINISHED else
                 'pending' if status in {'PENDING', 'RUNNING'} else 'deferred')
        scopes.append({'id': name, 'state': state, 'execution_status': status,
                       'evidence_sha256': digest(check), 'reason': check.get('reason')})
    if report.get('audit_contract_version') == SIGNED_VERSION:
        scopes.extend(surface_scopes(report))
    return {'contract': report.get('audit_contract_version',VERSION), 'state': 'incomplete',
            'scope_basis': 'DECLARED_STAGES_FILES_HTTP_BOUNDARIES_SUPPORTED_SINKS_NOT_EXHAUSTIVE' if 'surface_inventory' in report else 'DECLARED_SCAN_STAGES_ONLY_NOT_ALL_ATTACK_SURFACES',
            'source_sha256': report.get('source_snapshot_sha256'), 'scopes': scopes,
            'candidates': [{'id': f['finding_id'], 'state': 'unverified', 'evidence_sha256': digest(f)}
                           for f in report['findings']],
            'identity_assurance': 'NO_AUTOMATIC_INDEPENDENT_REVIEW',
            'security_verdict': 'NOT_ASSESSED'}


def validate_review(report, review, evidence):
    """evidence는 저장소에서 해시 대조한 보고서 사전. 내용의 진실성 검증은 아님."""
    bounded_document(review)
    version = report.get('audit_contract_version',VERSION)
    fields = {'contract','report_sha256','source_sha256','reviewer_id',
              'not_involved_in_implementation_or_expected_results','state','scopes','candidates','evidence'}
    exact_fields(review, fields | ({'signature'} if version == SIGNED_VERSION else set()))
    if version not in (VERSION,SIGNED_VERSION) or review['contract'] != version: raise ProductError('AUDIT_CONTRACT_INVALID')
    if review['report_sha256'] != digest(report): raise ProductError('AUDIT_REPORT_HASH_MISMATCH')
    if not report.get('source_snapshot_sha256') or review['source_sha256'] != report['source_snapshot_sha256']:
        raise ProductError('AUDIT_SOURCE_HASH_MISMATCH')
    authors = report.get('authors', [])
    if not authors: raise ProductError('REVIEW_AUTHOR_IDENTITIES_REQUIRED')
    if canonical_id(review['reviewer_id']).casefold() in unique_ids(authors):
        raise ProductError('INDEPENDENT_REVIEWER_REQUIRED')
    if review['not_involved_in_implementation_or_expected_results'] is not True:
        raise ProductError('REVIEWER_DECLARATION_REQUIRED')
    if review['state'] not in ('complete','incomplete'): raise ProductError('AUDIT_STATE_INVALID')
    projected = project_ledger(report)
    if not isinstance(review['evidence'], list): raise ProductError('AUDIT_EVIDENCE_INVALID')
    for ref in review['evidence']:
        exact_fields(ref, {'report_id','sha256'})
        canonical_id(ref['report_id'])
        if ref['report_id'] == report['report_id'] or ref['report_id'] not in evidence or digest(evidence[ref['report_id']]) != ref['sha256']:
            raise ProductError('AUDIT_EVIDENCE_HASH_MISMATCH')
        artifact = evidence[ref['report_id']]
        if not isinstance(artifact,dict): raise ProductError('AUDIT_EVIDENCE_INVALID')
        bindings = artifact.get('source_bindings', {})
        bound = bindings.get(report['project_id']) if isinstance(bindings,dict) else None
        if artifact.get('project_id') == report['project_id']:
            bound = artifact.get('source_snapshot_sha256', artifact.get('snapshot_sha256', bound))
        if bound != review['source_sha256']: raise ProductError('AUDIT_EVIDENCE_SOURCE_MISMATCH')
    unique_ids([r['report_id'] for r in review['evidence']])
    allowed = {r['report_id'] for r in review['evidence']}
    for key in ('scopes','candidates'):
        rows = review[key]
        if not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows):
            raise ProductError('AUDIT_ROWS_INVALID')
        unique_ids([r.get('id') for r in rows])
        expected = {r['id']:r for r in projected[key]}
        if {r['id'] for r in rows} != set(expected): raise ProductError('AUDIT_ALL_ITEMS_REQUIRED')
        for row in rows:
            exact_fields(row, {'id','state','evidence_sha256','evidence_ids','rationale'}, {'severity'} if key == 'candidates' else ())
            if row['evidence_sha256'] != expected[row['id']]['evidence_sha256']:
                raise ProductError('AUDIT_ITEM_HASH_MISMATCH')
            unique_ids(row['evidence_ids'])
            if not set(row['evidence_ids']) <= allowed: raise ProductError('AUDIT_UNKNOWN_EVIDENCE')
            if not isinstance(row['rationale'],str) or not row['rationale'].strip() or len(row['rationale']) > 4000:
                raise ProductError('AUDIT_RATIONALE_REQUIRED')
            states = {'covered','unreviewed','deferred'} if key == 'scopes' else {'validated','refuted','unverified','deferred'}
            if not isinstance(row['state'],str) or row['state'] not in states: raise ProductError('AUDIT_ITEM_STATE_INVALID')
            if row['state'] in {'covered','validated','refuted'} and not row['evidence_ids']:
                raise ProductError('AUDIT_EVIDENCE_REQUIRED')
            if row['state'] == 'covered' and expected[row['id']]['execution_status'] not in FINISHED:
                raise ProductError('AUDIT_UNEXECUTED_SCOPE')
            if 'severity' in row and (row['state'] != 'validated' or row['severity'] not in ('low','medium','high','critical')):
                raise ProductError('AUDIT_SEVERITY_REQUIRES_VALIDATION')
    if review['state'] == 'complete' and (
            report.get('execution_state') != 'COMPLETED' or report.get('errors') or
            report.get('findings_omitted_by_limit',0) or
            report.get('surface_inventory',{}).get('omitted',0) or
            report['checks'].get('source',{}).get('endpoints_omitted_by_limit',0) or
            report.get('languages',{}).get('unsupported_source') or
            any(r['state'] != 'covered' for r in review['scopes']) or
            any(r['state'] not in {'validated','refuted'} for r in review['candidates'])):
        raise ProductError('AUDIT_COMPLETE_WITH_OPEN_ITEMS')
    return review


def record_audit_review(config, report_id, review):
    bounded_document(review)
    store = ProductStore(config.results)
    report = store.read(report_id)
    if not isinstance(report,dict) or report.get('kind') != 'project-security-scan': raise ProductError('NOT_A_PROJECT_SCAN')
    # Schema before any lookup; IDs go through ProductStore's confined ASCII ID validator.
    if not isinstance(review,dict) or not isinstance(review.get('evidence'),list):
        raise ProductError('AUDIT_EVIDENCE_INVALID')
    evidence = {}
    for ref in review['evidence']:
        exact_fields(ref, {'report_id','sha256'})
        canonical_id(ref['report_id'])
        evidence[ref['report_id']] = store.read(ref['report_id'])
    validate_review(report, review, evidence)
    identity = verify_signature(config.audit_policy,report,review) if report.get('audit_contract_version') == SIGNED_VERSION else None
    root, settings = config.project(report['project_id'])
    snapshot = Snapshot.read(root, settings.get('commit'))
    if digest(snapshot.metadata()) != review['source_sha256']: raise ProductError('REVIEW_SOURCE_CHANGED')
    snapshot.verify()
    # Re-read all review inputs immediately before storing the new, separate receipt.
    if digest(store.read(report_id)) != review['report_sha256']: raise ProductError('AUDIT_REPORT_HASH_MISMATCH')
    for ref in review['evidence']:
        if digest(store.read(ref['report_id'])) != ref['sha256']: raise ProductError('AUDIT_EVIDENCE_HASH_MISMATCH')
    identifier = store.create('audit', {'kind':'audit-review-receipt'})
    result = {'kind':'audit-review-receipt','report_id':identifier,'reviewed_report_id':report_id,
              'review_sha256':digest(review),'review':review,'recorded_at':now(),
              'identity_assurance':'REGISTERED_ED25519_KEY_VERIFIED' if identity else 'LOCAL_DECLARATION_NOT_AUTHENTICATED',
              'signer':identity,
              'validation_assurance':'EVIDENCE_LINKS_AND_LOCAL_REVIEW_DECLARATION_ONLY',
              'security_verdict':'NOT_ASSESSED','original_report_rewritten':False,'model_calls':0}
    save_json(store.folder(identifier)/'report.json', result)
    return result

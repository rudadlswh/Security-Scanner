"""새 프로젝트 사전등록 평가·동일입력 검색 기준선·독립 검토 영수증·AI 주장 근거 검사.

네트워크/생성/대상 빌드를 실행하지 않는다. 검토자 신원은 로컬 선언이며 인증으로 표현하지 않는다.
"""
from __future__ import annotations
import re
import time
from pathlib import Path
from .collector import inventory, collect
from .source_security import scan_source_security
from .workspace import ProductError, ProductStore, Snapshot, digest, inside, load_json, now, save_json
from .contracts import bounded_document, canonical_id, unique_ids, exact_fields

BASELINE = re.compile(r'\b(delete|remove|executeQuery|createQuery|queryForObject|getForObject|htmlEscape|Principal|SecurityContext|owner|userId)\b')


def freeze_benchmark(config, plan, output):
    bounded_document(plan)
    if plan.get('contract') != 'benchmark-plan/1' or not isinstance(plan.get('cases'),list) or not 1<=len(plan['cases'])<=100:
        raise ProductError('BENCHMARK_PLAN_INVALID')
    if not isinstance(plan.get('authors'),list) or not plan['authors'] or any(not isinstance(a,str) or not a.strip() for a in plan['authors']) or len({c['id'] for c in plan['cases']})!=len(plan['cases']):
        raise ProductError('BENCHMARK_AUTHORS_AND_UNIQUE_CASES_REQUIRED')
    unique_ids(plan['authors']);unique_ids([c['id'] for c in plan['cases']])
    snapshots={}
    for case in plan['cases']:
        if not isinstance(case.get('expected_symbols'),list) or not case['expected_symbols']:
            raise ProductError('BENCHMARK_NONEMPTY_EXPECTED_SYMBOLS_REQUIRED')
        project=case['project_id'];root,settings=config.project(project)
        snapshots[project]=Snapshot.read(root,settings.get('commit')).metadata()
        if not isinstance(case.get('endpoint'),dict) or set(case['endpoint'])!={'http_method','http_path'}:
            raise ProductError('BENCHMARK_EXACT_ENDPOINT_REQUIRED')
    frozen={'contract':'frozen-benchmark/1','created_at':now(),'plan':plan,'snapshots':snapshots,
            'model_calls':0,'independent_review':'PENDING','previously_exposed':plan.get('previously_exposed',True)}
    frozen['sha256']=digest(frozen);save_json(output,frozen);return frozen


def run_benchmark(config, frozen):
    expected=frozen.get('sha256');unsigned={k:v for k,v in frozen.items() if k!='sha256'}
    if frozen.get('contract')!='frozen-benchmark/1' or expected!=digest(unsigned):
        raise ProductError('BENCHMARK_FREEZE_MISMATCH')
    prepared={}
    for project, metadata in frozen['snapshots'].items():
        value=inventory(config,project)
        if value[0].metadata()!=metadata:raise ProductError('BENCHMARK_SOURCE_CHANGED')
        prepared[project]=value
    store=ProductStore(config.results);identifier=store.create('benchmark',{'kind':'benchmark'})
    save_json(store.folder(identifier)/'frozen-plan.json',frozen)
    rows=[]
    for case in frozen['plan']['cases']:
        data=prepared[case['project_id']];matches=[e for e in data[2]['endpoints'] if all(e[k]==v for k,v in case['endpoint'].items())]
        if len(matches)!=1:
            rows.append({'case_id':case['id'],'status':'ENDPOINT_MISSING_OR_AMBIGUOUS'});continue
        begin=time.perf_counter();collection=collect(config,case['project_id'],matches[0]['endpoint_id'],prepared=data)
        elapsed=time.perf_counter()-begin
        symbols={e['symbol'] for e in collection['evidence']};required=set(case['expected_symbols'])
        begin=time.perf_counter();hits=[]
        for name,raw in data[0].files.items():
            if not name.endswith('.java'):continue
            for line,text in enumerate(raw.decode('utf-8-sig').splitlines(),1):
                if BASELINE.search(text):hits.append({'path':name,'line':line})
        baseline_elapsed=time.perf_counter()-begin
        rows.append({'case_id':case['id'],'status':'MEASURED','collection_id':collection['collection_id'],
            'required_symbols':sorted(required),'found_required':sorted(required&symbols),'missing_required':sorted(required-symbols),
            'unexpected_symbols':sorted(symbols-required),'unresolved_count':len(collection['unresolved_calls']),
            'collection_seconds':elapsed,'baseline_seconds':baseline_elapsed,'baseline_hits':hits,
            'baseline_method':'FIXED_REGEX_CANDIDATE_LINES_NOT_SEMANTIC_EQUIVALENCE',
            'review_minutes':None,'false_positive_adjudication':'PENDING','independent_review':'PENDING'})
    report={'kind':'benchmark','report_id':identifier,'plan_sha256':expected,'cases':rows,
            'authors':frozen['plan']['authors'],'source_bindings':{p:digest(m) for p,m in frozen['snapshots'].items()},
            'model_calls':0,'generalization_proven':False,
            'comparison_limits':'Collection timer excludes shared parse. Regex line search is not equivalent to semantic review. No speedup claim.'}
    for snapshot,_,_ in prepared.values():snapshot.verify()
    save_json(store.folder(identifier)/'report.json',report);return report


def validate_source_proposal(config, collection_id, proposal):
    bounded_document(proposal)
    exact_fields(proposal, {'contract','collection_sha256','claims'})
    collection=ProductStore(config.results).read(collection_id)
    if collection.get('collection_id')!=collection_id:raise ProductError('PROPOSAL_COLLECTION_REQUIRED')
    if digest({k:v for k,v in collection.items() if k!='collection_sha256'})!=collection.get('collection_sha256'):
        raise ProductError('COLLECTION_INTEGRITY_FAILED')
    root,settings=config.project(collection['project_id']);snapshot=Snapshot.read(root,settings.get('commit'))
    if digest(snapshot.metadata())!=collection['snapshot_sha256']:raise ProductError('PROPOSAL_SOURCE_CHANGED')
    if proposal.get('contract')!='source-proposal/1' or proposal.get('collection_sha256')!=collection['collection_sha256']:
        raise ProductError('PROPOSAL_BINDING_MISMATCH')
    claims=proposal.get('claims');by_id={e['id']:e for e in collection['evidence']}
    if not isinstance(claims,list) or not 1<=len(claims)<=30:raise ProductError('PROPOSAL_CLAIMS_REQUIRED')
    if any(not isinstance(c,dict) for c in claims):raise ProductError('PROPOSAL_CLAIM_FIELDS_INVALID')
    unique_ids([c.get('id') for c in claims])
    seen=set()
    for claim in claims:
        if set(claim)!={'id','hypothesis','evidence_ids','suggested_change','validation_steps','assumptions'}:
            raise ProductError('PROPOSAL_CLAIM_FIELDS_INVALID')
        if not isinstance(claim['id'],str) or not claim['id'] or claim['id'] in seen:raise ProductError('PROPOSAL_CLAIM_ID_INVALID')
        seen.add(claim['id'])
        if not isinstance(claim['evidence_ids'],list) or not claim['evidence_ids'] or any(e not in by_id for e in claim['evidence_ids']):
            raise ProductError('PROPOSAL_UNKNOWN_EVIDENCE')
        if any(not isinstance(claim[k],str) or not 1<=len(claim[k])<=4000 for k in ('hypothesis','suggested_change')):
            raise ProductError('PROPOSAL_TEXT_INVALID')
        for key in ('validation_steps','assumptions'):
            if not isinstance(claim[key],list) or len(claim[key])>20 or any(not isinstance(v,str) or not 1<=len(v)<=2000 for v in claim[key]):
                raise ProductError('PROPOSAL_STEPS_INVALID')
        if not claim['validation_steps']:raise ProductError('PROPOSAL_TESTS_REQUIRED')
    # Do not store free text: original remains at caller's explicitly selected local path.
    store=ProductStore(config.results);identifier=store.create('proposal',{'kind':'source-proposal-review','project_id':collection['project_id']})
    report={'report_id':identifier,'kind':'source-proposal-review','proposal_sha256':digest(proposal),
            'authors':settings.get('proposal_authors',[]),'source_bindings':{collection['project_id']:collection['snapshot_sha256']},
            'collection_id':collection_id,'collection_sha256':collection['collection_sha256'],
            'claims':[{'id':c['id'],'evidence_ids':c['evidence_ids'],'text_sha256':digest(c),
                       'semantic_status':'NOT_REVIEWED','source_cause_confirmed':False} for c in claims],
            'status':'EVIDENCE_LINKS_VALIDATED_ONLY','automatic_apply':False,'model_calls':0}
    snapshot.verify();save_json(store.folder(identifier)/'report.json',report);return report


def record_review(config, report_id, review):
    bounded_document(review)
    exact_fields(review, {'report_sha256','reviewer_id','not_involved_in_implementation_or_expected_results','items'})
    store=ProductStore(config.results);report=store.read(report_id)
    if review.get('report_sha256')!=digest(report):raise ProductError('REVIEW_REPORT_HASH_MISMATCH')
    reviewer=review.get('reviewer_id');authors=report.get('authors',[])
    if not authors:raise ProductError('REVIEW_AUTHOR_IDENTITIES_REQUIRED')
    if not isinstance(reviewer,str) or not reviewer.strip() or reviewer in authors:
        raise ProductError('INDEPENDENT_REVIEWER_REQUIRED')
    author_keys=unique_ids(authors)
    if canonical_id(reviewer).casefold() in author_keys:raise ProductError('INDEPENDENT_REVIEWER_REQUIRED')
    if review.get('not_involved_in_implementation_or_expected_results') is not True:
        raise ProductError('REVIEWER_DECLARATION_REQUIRED')
    expected={r['case_id'] for r in report.get('cases',[])} or {r['id'] for r in report.get('claims',[])}
    rows=review.get('items',[])
    if not isinstance(rows,list) or any(not isinstance(r,dict) for r in rows):raise ProductError('REVIEW_ITEM_INVALID')
    if not expected or len(rows)!=len(expected) or {r.get('id') for r in rows}!=expected:
        raise ProductError('REVIEW_ALL_ITEMS_REQUIRED')
    if any(r.get('verdict') not in {'ACCEPT','REVISE','UNRESOLVED'} or not isinstance(r.get('rationale'),str) or not r['rationale'].strip() for r in rows):
        raise ProductError('REVIEW_ITEM_INVALID')
    unique_ids(list(expected));unique_ids([r['id'] for r in rows])
    for row in rows:exact_fields(row, {'id','verdict','rationale'})
    bindings=report.get('source_bindings')
    if bindings is None and report.get('collection_id'):
        collection=store.read(report['collection_id'])
        if (collection.get('collection_sha256')!=report.get('collection_sha256') or
                digest({k:v for k,v in collection.items() if k!='collection_sha256'})!=collection.get('collection_sha256')):
            raise ProductError('REVIEW_COLLECTION_HASH_MISMATCH')
        bindings={collection['project_id']:collection['snapshot_sha256']}
    snapshots=[]
    if bindings is not None and (not isinstance(bindings,dict) or not bindings):
        raise ProductError('REVIEW_SOURCE_BINDING_INVALID')
    for project,expected_hash in (bindings or {}).items():
        if not isinstance(expected_hash,str) or not re.fullmatch('[0-9a-f]{64}',expected_hash):
            raise ProductError('REVIEW_SOURCE_BINDING_INVALID')
        root,settings=config.project(project)
        snapshot=Snapshot.read(root,settings.get('commit'))
        if digest(snapshot.metadata())!=expected_hash:raise ProductError('REVIEW_SOURCE_CHANGED')
        snapshots.append(snapshot)
    for snapshot in snapshots:snapshot.verify()
    if digest(store.read(report_id))!=review['report_sha256']:raise ProductError('REVIEW_REPORT_HASH_MISMATCH')
    identifier=store.create('adjudication',{'kind':'independent-review-receipt'})
    result={'kind':'independent-review-receipt','report_id':identifier,'reviewed_report_id':report_id,
            'reviewed_report_sha256':digest(report),'review_sha256':digest(review),'reviewer_id':reviewer,
            'reviewer_identity_assurance':'LOCAL_DECLARATION_NOT_AUTHENTICATED',
            'source_binding_status':'CURRENT_SNAPSHOT_MATCHED' if bindings else 'LEGACY_UNBOUND_NOT_CURRENT_SOURCE_VALIDATION',
            'status':'DECLARED_INDEPENDENT_REVIEW_RECORDED','items':rows,'recorded_at':now(),
            'original_report_rewritten':False,'generalization_proven':False}
    save_json(store.folder(identifier)/'report.json',result);return result

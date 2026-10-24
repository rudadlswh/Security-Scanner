"""감사 도입 계약의 부정 입력·근거 변경·호출 경계. 실제 모델/HTTP/CVE 없음."""
import asyncio
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, AsyncMock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.audit import project_ledger, validate_review, record_audit_review, VERSION
from localcode_review_mcp.assurance import record_review
from localcode_review_mcp.contracts import canonical_id, unique_ids, bounded_document
from localcode_review_mcp.source_analysis import validate_generated_proposal
from localcode_review_mcp.workspace import ProductConfig, ProductStore, ProductError, Snapshot, digest, inside, save_json, load_json


class AdoptionTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.source = self.root/'source'; self.source.mkdir()
        (self.source/'Api.java').write_text('class Api {}', encoding='utf-8')
        self.git = patch('localcode_review_mcp.workspace.git_identity', return_value={'kind':'unversioned'})
        self.git.start(); self.addCleanup(self.git.stop)
        self.cfg = ProductConfig(self.root/'config.json', {'demo':{'root':str(self.source)}}, None, self.root/'results', {})
        self.store = ProductStore(self.cfg.results)
        self.source_hash = digest(Snapshot.read(self.source).metadata())
        self.report = {'kind':'project-security-scan','report_id':'scan-fixture','project_id':'demo',
                       'authors':['Author'],'execution_state':'COMPLETED','source_snapshot_sha256':self.source_hash,
                       'checks':{'source':{'status':'COMPLETED'},'sast':{'status':'COMPLETED_FOR_RULESET'}},
                       'findings':[{'finding_id':'F001','basis':'synthetic candidate'}],'errors':[]}
        self.evidence = {'evidence-fixture':{'kind':'source-security','project_id':'demo','snapshot_sha256':self.source_hash,
                                           'observation':'synthetic local verification fixture'}}
        self.review = {'contract':VERSION,'report_sha256':digest(self.report),'source_sha256':self.source_hash,
                       'reviewer_id':'Reviewer','not_involved_in_implementation_or_expected_results':True,
                       'state':'complete','scopes':[],'candidates':[],
                       'evidence':[{'report_id':k,'sha256':digest(v)} for k,v in self.evidence.items()]}
        for key,rows in [('scopes',project_ledger(self.report)['scopes']),('candidates',project_ledger(self.report)['candidates'])]:
            self.review[key] = [{'id':r['id'],'state':'covered' if key=='scopes' else 'refuted',
                                 'evidence_sha256':r['evidence_sha256'],'evidence_ids':['evidence-fixture'],
                                 'rationale':'Synthetic test review declaration.'} for r in rows]

    def check(self): return validate_review(self.report,self.review,self.evidence)

    def persist(self):
        save_json(self.store.folder(self.report['report_id'])/'report.json',self.report)
        for key,value in self.evidence.items(): save_json(self.store.folder(key)/'report.json',value)

    def test_complete_scoped_declaration_with_bound_evidence(self):
        self.assertEqual('complete',self.check()['state'])
        self.persist(); before = (self.store.folder('scan-fixture')/'report.json').read_bytes()
        receipt = record_audit_review(self.cfg,'scan-fixture',self.review)
        self.assertEqual('LOCAL_DECLARATION_NOT_AUTHENTICATED',receipt['identity_assurance'])
        self.assertEqual('NOT_ASSESSED',receipt['security_verdict'])
        self.assertEqual(before,(self.store.folder('scan-fixture')/'report.json').read_bytes())

    def test_covered_requires_evidence(self):
        self.review['scopes'][0]['evidence_ids']=[]
        with self.assertRaisesRegex(ProductError,'AUDIT_EVIDENCE_REQUIRED'): self.check()

    def test_complete_rejects_open_candidates(self):
        for state in ('unverified','deferred'):
            with self.subTest(state=state):
                self.review['candidates'][0]['state']=state
                with self.assertRaisesRegex(ProductError,'AUDIT_COMPLETE_WITH_OPEN_ITEMS'): self.check()

    def test_complete_rejects_omitted_scope(self):
        self.review['scopes'].pop()
        with self.assertRaisesRegex(ProductError,'AUDIT_ALL_ITEMS_REQUIRED'): self.check()

    def test_complete_rejects_limit_omissions_and_execution_errors(self):
        for key,value in [('findings_omitted_by_limit',1),('errors',[{'stage':'source'}]),('languages',{'unsupported_source':['Python']})]:
            with self.subTest(key=key):
                self.report[key]=value; self.review['report_sha256']=digest(self.report)
                with self.assertRaisesRegex(ProductError,'AUDIT_COMPLETE_WITH_OPEN_ITEMS'): self.check()
                del self.report[key]

    def test_deferred_execution_cannot_be_covered(self):
        self.report['checks']['sast']['status']='SKIPPED'; self.review['report_sha256']=digest(self.report)
        self.review['scopes'][1]['evidence_sha256']=digest(self.report['checks']['sast'])
        with self.assertRaisesRegex(ProductError,'AUDIT_UNEXECUTED_SCOPE'): self.check()

    def test_stale_review_and_source_and_item_hashes_rejected(self):
        for key in ('report_sha256','source_sha256'):
            with self.subTest(key=key):
                before=self.review[key]; self.review[key]='0'*64
                with self.assertRaises(ProductError): self.check()
                self.review[key]=before
        self.review['candidates'][0]['evidence_sha256']='0'*64
        with self.assertRaisesRegex(ProductError,'AUDIT_ITEM_HASH_MISMATCH'): self.check()

    def test_stale_evidence_hash_and_source_rejected(self):
        artifact = self.evidence['evidence-fixture']; artifact['observation']='changed'
        with self.assertRaisesRegex(ProductError,'AUDIT_EVIDENCE_HASH_MISMATCH'): self.check()
        artifact['snapshot_sha256']='0'*64; self.review['evidence'][0]['sha256']=digest(artifact)
        with self.assertRaisesRegex(ProductError,'AUDIT_EVIDENCE_SOURCE_MISMATCH'): self.check()

    def test_current_source_change_blocks_receipt(self):
        self.persist(); (self.source/'Api.java').write_text('class Api { int changed; }',encoding='utf-8')
        with self.assertRaisesRegex(ProductError,'REVIEW_SOURCE_CHANGED'): record_audit_review(self.cfg,'scan-fixture',self.review)
        self.assertEqual(2,len(list(self.cfg.results.iterdir())))

    def test_author_and_ambiguous_identity_rejected(self):
        for reviewer in ('Author','AUTHOR','Author ','Author\u200b'):
            with self.subTest(reviewer=reviewer):
                self.review['reviewer_id']=reviewer
                with self.assertRaises(ProductError): self.check()

    def test_unverified_refuted_deferred_severity_forbidden(self):
        self.review['state']='incomplete'
        for state in ('unverified','refuted','deferred'):
            with self.subTest(state=state):
                self.review['candidates'][0].update(state=state,severity='high')
                with self.assertRaisesRegex(ProductError,'AUDIT_SEVERITY_REQUIRES_VALIDATION'): self.check()
        self.review['candidates'][0]['state']='validated'
        self.check()

    def test_unknown_fields_and_unicode_collisions_rejected(self):
        for values in (['C1','c1'],['é','e\u0301'],['A',' A'],['A','A\u202e']):
            with self.subTest(values=values):
                with self.assertRaises(ProductError): unique_ids(values)
        self.review['candidates'][0]['unexpected']='value'
        with self.assertRaises(ProductError): self.check()

    def test_unsafe_paths_rejected(self):
        for name in ('../Api.java','C:\\Api.java','/Api.java','CON','NUL.java','dir/COM¹.txt','Api.java:stream','a\u202e.java','a.','a//b'):
            with self.subTest(name=name):
                with self.assertRaises(ProductError): inside(self.source,name)
        self.assertEqual(self.source/'Api.java',inside(self.source,'Api.java'))

    def test_size_complexity_nonfinite_and_duplicate_keys_rejected(self):
        for value in ({'x':'x'*4194304},{'x':float('nan')},['x']*10001):
            with self.assertRaises(ProductError): bounded_document(value)
        value = {}; node=value
        for _ in range(66): node['x']={};node=node['x']
        with self.assertRaises(ProductError): bounded_document(value)
        path=self.root/'bad.json';path.write_text('{"x":1,"x":2}')
        with self.assertRaisesRegex(ProductError,'DUPLICATE_JSON_KEY'): load_json(path)

    def test_source_proposal_unicode_collision_rejected(self):
        claim={'id':'é','hypothesis':'h','evidence_ids':['E1'],'suggested_change':'s','validation_steps':['v'],'assumptions':[]}
        proposal={'contract':'source-proposal/1','collection_sha256':'a'*64,'claims':[claim,{**claim,'id':'e\u0301'}]}
        with self.assertRaises(ProductError): validate_generated_proposal(proposal,{'collection_sha256':'a'*64,'evidence':[{'id':'E1'}]})

    def test_existing_review_source_and_severity_guard(self):
        report={'kind':'benchmark','report_id':'benchmark-fixture','authors':['Author'],'cases':[{'case_id':'C1'}],
                'source_bindings':{'demo':self.source_hash}}
        save_json(self.store.folder('benchmark-fixture')/'report.json',report)
        review={'report_sha256':digest(report),'reviewer_id':'Reviewer','not_involved_in_implementation_or_expected_results':True,
                'items':[{'id':'C1','verdict':'UNRESOLVED','rationale':'pending','severity':'high'}]}
        with self.assertRaises(ProductError): record_review(self.cfg,'benchmark-fixture',review)
        del review['items'][0]['severity']; (self.source/'Api.java').write_text('class Changed {}')
        with self.assertRaisesRegex(ProductError,'REVIEW_SOURCE_CHANGED'): record_review(self.cfg,'benchmark-fixture',review)

    def test_ledger_never_auto_promotes_observations(self):
        ledger=project_ledger(self.report)
        self.assertEqual('incomplete',ledger['state'])
        self.assertEqual({'unreviewed'},{r['state'] for r in ledger['scopes']})
        self.assertEqual('unverified',ledger['candidates'][0]['state'])


class BudgetIntegrationTest(unittest.TestCase):
    def test_exhausted_budget_defers_without_calling_model(self):
        from scripts.test_project_scan import ProjectScanTest
        fixture=ProjectScanTest(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        import datetime as dt
        authorization={'calls_cap':1,'calls_consumed':1,'expires_at':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(),
                       'model':'unused','digest':'unused'}
        path=fixture.cfg.results/'control/model-authorization.json';save_json(path,authorization)
        before=path.read_bytes()
        with patch('localcode_review_mcp.project_scan.ReviewJobs.start',new_callable=AsyncMock) as start, \
             patch('localcode_review_mcp.project_scan.generate_remediation',new_callable=AsyncMock) as remediation, \
             patch('localcode_review_mcp.project_scan.scan_source_security',return_value={'findings':[],'status':'COMPLETED_FOR_RULESET'}):
            _,report=asyncio.run(fixture.execute(include_remediation=False))
        start.assert_not_called();remediation.assert_not_called()
        self.assertEqual(0,report['model_calls_sent'])
        self.assertEqual('MODEL_BUDGET_EXHAUSTED',report['checks']['ai']['reason'])
        self.assertEqual('deferred',next(r for r in report['audit']['scopes'] if r['id']=='ai')['state'])
        self.assertEqual(before,path.read_bytes())


if __name__ == '__main__': unittest.main()

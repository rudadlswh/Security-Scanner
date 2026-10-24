"""등록키 서명·독립 요청·격리 예산·범위 확장 검증. 모든 모델/네트워크는 mock."""
import asyncio
import base64
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.audit import project_ledger, record_audit_review, SIGNED_VERSION
from localcode_review_mcp.audit_identity import signing_bytes, verify_signature, trusted_registry
from localcode_review_mcp.audit_surface import surface_inventory, surface_scopes
from localcode_review_mcp.audit_verifier import authorize_verifier, verify_candidates, grant_path, acknowledge_verifier, prepare_packet
from localcode_review_mcp.audit_jobs import AuditVerificationJobs
from localcode_review_mcp.workspace import ProductConfig, ProductStore, ProductError, Snapshot, digest, load_json, save_json


class CompletionContractsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        (self.source/'Api.java').write_text('class Api {\n void call(String q) {\n db.query(q);\n }\n}',encoding='utf-8')
        p=patch('localcode_review_mcp.workspace.git_identity',return_value={'kind':'unversioned'});p.start();self.addCleanup(p.stop)
        self.author=Ed25519PrivateKey.generate();self.reviewer=Ed25519PrivateKey.generate()
        def key(principal,private):return {'principal_id':principal,'public_key':base64.b64encode(private.public_key().public_bytes_raw()).decode()}
        self.policy={'trusted_reviewers':{'author-key':key('Author',self.author),'reviewer-key':key('Reviewer',self.reviewer)},
                     'verifier':{'enabled':True,'allow_source':True,'name':'qwen3-coder:30b','digest':'b'*64,'base_url':'http://127.0.0.1:11434'}}
        self.cfg=ProductConfig(self.root/'config.json',{'demo':{'root':str(self.source)}},None,self.root/'results',{'name':'qwen3.5:9b','digest':'a'*64},audit_policy=self.policy)
        self.store=ProductStore(self.cfg.results);self.snapshot=Snapshot.read(self.source)
        self.source_hash=digest(self.snapshot.metadata())
        self.report={'kind':'project-security-scan','report_id':'scan-fixture','project_id':'demo','authors':['Author'],
                     'execution_state':'COMPLETED','checks':{'sast':{'status':'COMPLETED_FOR_RULESET'}},'errors':[],
                     'source_snapshot_sha256':self.source_hash,'discovery_model_digest':'a'*64,
                     'audit_contract_version':SIGNED_VERSION,'review_policy_sha256':digest(self.policy['trusted_reviewers']),
                     'findings':[{'finding_id':'F001','kind':'STATIC_SECURITY_CANDIDATE','path':'Api.java','line':3,'rule_id':'LCR-SQL-001',
                                  'remediation':{'change':'AUTHOR_SECRET_CONCLUSION'},'severity':'AUTHOR_SECRET_SEVERITY'}]}
        self.persist()
        self.evidence={'kind':'source-security','project_id':'demo','snapshot_sha256':self.source_hash,'findings':['synthetic']}
        save_json(self.store.folder('evidence-fixture')/'report.json',self.evidence)

    def persist(self):save_json(self.store.folder('scan-fixture')/'report.json',self.report,replace=True)

    def review(self):
        ledger=project_ledger(self.report)
        value={'contract':SIGNED_VERSION,'report_sha256':digest(self.report),'source_sha256':self.source_hash,
               'reviewer_id':'Reviewer','not_involved_in_implementation_or_expected_results':True,'state':'complete',
               'evidence':[{'report_id':'evidence-fixture','sha256':digest(self.evidence)}]}
        for key in ('scopes','candidates'):
            value[key]=[{'id':r['id'],'state':'covered' if key=='scopes' else 'refuted','evidence_sha256':r['evidence_sha256'],
                         'evidence_ids':['evidence-fixture'],'rationale':'Synthetic fixture review'} for r in ledger[key]]
        self.sign(value);return value

    def sign(self,review,key=None,key_id='reviewer-key'):
        review['signature']={'key_id':key_id,'value':base64.b64encode((key or self.reviewer).sign(signing_bytes(review))).decode()}

    def grant(self,calls=1):return authorize_verifier(self.cfg,'scan-fixture',calls,5)

    def response(self,decision='supported'):
        return {'done':True,'done_reason':'stop','prompt_eval_count':100,'message':{'content':json.dumps({'candidate_id':'F001','decision':decision,'evidence_ids':['V1']})}}

    def execute(self,grant,side_effect=None):
        tags={'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]}
        with patch('localcode_review_mcp.audit_verifier.json_request',new_callable=AsyncMock,side_effect=side_effect or [tags,self.response()]) as network, \
             patch('localcode_review_mcp.audit_verifier.access_boundary',return_value={'mock':True}) as boundary:
            outcome=asyncio.run(verify_candidates(self.cfg,'scan-fixture',grant['grant_id']))
        return outcome,network,boundary

    def test_signed_receipt_binds_registered_key_and_keeps_original(self):
        before=(self.store.folder('scan-fixture')/'report.json').read_bytes()
        receipt=record_audit_review(self.cfg,'scan-fixture',self.review())
        self.assertEqual('REGISTERED_ED25519_KEY_VERIFIED',receipt['identity_assurance'])
        self.assertFalse(receipt['signer']['real_world_identity_proven'])
        self.assertEqual(before,(self.store.folder('scan-fixture')/'report.json').read_bytes())

    def test_forgery_and_post_signature_modification_rejected(self):
        review=self.review();review['scopes'][0]['rationale']='changed'
        with self.assertRaisesRegex(ProductError,'AUDIT_SIGNATURE_INVALID'): record_audit_review(self.cfg,'scan-fixture',review)
        self.sign(review,Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(ProductError,'AUDIT_SIGNATURE_INVALID'): record_audit_review(self.cfg,'scan-fixture',review)

    def test_unsigned_and_contract_downgrade_rejected(self):
        review=self.review();del review['signature']
        with self.assertRaises(ProductError):record_audit_review(self.cfg,'scan-fixture',review)
        review['contract']='audit-ledger/1'
        with self.assertRaises(ProductError):record_audit_review(self.cfg,'scan-fixture',review)

    def test_author_key_cannot_impersonate_other_reviewer(self):
        review=self.review();self.sign(review,self.author,'author-key')
        with self.assertRaisesRegex(ProductError,'INDEPENDENT_REVIEWER_REQUIRED'):record_audit_review(self.cfg,'scan-fixture',review)

    def test_key_alias_and_changed_trust_policy_rejected(self):
        self.policy['trusted_reviewers']['alias']={**self.policy['trusted_reviewers']['author-key'],'principal_id':'Other'}
        with self.assertRaisesRegex(ProductError,'AUDIT_KEY_ALIAS_COLLISION'):trusted_registry(self.policy)
        del self.policy['trusted_reviewers']['alias'];review=self.review()
        self.policy['trusted_reviewers']['reviewer-key']['principal_id']='Other'
        with self.assertRaisesRegex(ProductError,'AUDIT_TRUST_POLICY_CHANGED'):record_audit_review(self.cfg,'scan-fixture',review)

    def test_signed_receipt_still_rejects_stale_source(self):
        review=self.review();(self.source/'Api.java').write_text('class Changed {}')
        with self.assertRaisesRegex(ProductError,'REVIEW_SOURCE_CHANGED'):record_audit_review(self.cfg,'scan-fixture',review)

    def test_surface_inventory_has_files_boundaries_and_sinks(self):
        endpoint={'endpoint_id':'ep-1','http_method':'GET','http_path':'/x','mapping_status':'AST_LITERAL'}
        self.report['surface_inventory']=surface_inventory(self.snapshot,{'endpoints':[endpoint],'support_reasons':[]})
        self.report['endpoints']=[{**endpoint,'collection_id':'c-1','collection_status':'COMPLETED','unresolved_calls':1}]
        scopes=surface_scopes(self.report)
        self.assertEqual({'SOURCE_FILE','HTTP_TRUST_BOUNDARY','SOURCE_TO_SINK_CANDIDATE'},{r['kind'] for r in scopes})
        self.assertEqual('deferred',next(r for r in scopes if r['kind']=='HTTP_TRUST_BOUNDARY')['state'])
        self.persist()
        with self.assertRaisesRegex(ProductError,'AUDIT_UNEXECUTED_SCOPE'):record_audit_review(self.cfg,'scan-fixture',self.review())

    def test_surface_omission_blocks_complete_even_with_signature(self):
        self.report['surface_inventory']={'items':[],'omitted':1};self.persist()
        with self.assertRaisesRegex(ProductError,'AUDIT_COMPLETE_WITH_OPEN_ITEMS'):record_audit_review(self.cfg,'scan-fixture',self.review())

    def test_separate_request_omits_author_conclusions_and_severity(self):
        request,_,evidence=prepare_packet(self.snapshot,self.report['findings'][0],self.policy['verifier'])
        serialized=json.dumps(request)
        self.assertNotIn('AUTHOR_SECRET',serialized)
        self.assertIn('db.query(q)',serialized)
        self.assertNotIn('text',evidence)
        self.assertEqual(['system','user'],[r['role'] for r in request['messages']])

    def test_success_is_unconfirmed_and_grant_is_single_use(self):
        grant=self.grant();legacy=self.cfg.results/'control/model-authorization.json'
        save_json(legacy,{'calls_cap':1,'calls_consumed':1,'blocked':True});before=legacy.read_bytes()
        outcome,network,_=self.execute(grant)
        self.assertEqual('COMPLETED_FOR_SELECTED_CANDIDATES',outcome['status']);self.assertEqual(2,network.await_count)
        self.assertEqual('review_required',outcome['candidates'][0]['state'])
        self.assertNotIn('severity',outcome['candidates'][0]);self.assertNotIn('db.query',json.dumps(outcome))
        self.assertFalse(outcome['source_cause_confirmed']);self.assertEqual(before,legacy.read_bytes())
        saved=load_json(grant_path(self.cfg,grant['grant_id']))
        self.assertEqual((1,1,'CLOSED'),(saved['calls_reserved'],saved['calls_consumed'],saved['state']))
        again,network,boundary=self.execute(grant)
        self.assertEqual('DEFERRED',again['status']);network.assert_not_called();boundary.assert_not_called()

    def test_insufficient_budget_defers_before_even_model_lookup(self):
        self.report['findings'].append({**self.report['findings'][0],'finding_id':'F002'});self.persist()
        grant=self.grant();path=grant_path(self.cfg,grant['grant_id']);before=path.read_bytes()
        result,network,boundary=self.execute(grant)
        self.assertEqual('AUDIT_VERIFICATION_BUDGET_INSUFFICIENT',result['reason'])
        network.assert_not_called();boundary.assert_not_called();self.assertEqual(before,path.read_bytes())

    def test_expired_missing_or_bound_to_wrong_report_never_calls(self):
        grant=self.grant();path=grant_path(self.cfg,grant['grant_id'])
        grant['expires_at']='2000-01-01T00:00:00+00:00';save_json(path,grant,replace=True)
        result,network,_=self.execute(grant);self.assertEqual('AUDIT_GRANT_EXPIRED',result['reason']);network.assert_not_called()
        path.unlink();result,network,_=self.execute(grant);self.assertEqual('AUDIT_GRANT_REQUIRED',result['reason']);network.assert_not_called()
        grant['report_sha256']='0'*64;save_json(path,grant)
        result,network,_=self.execute(grant);self.assertEqual('AUDIT_GRANT_BINDING_MISMATCH',result['reason']);network.assert_not_called()

    def test_same_model_and_disabled_source_never_calls(self):
        grant=self.grant();self.policy['verifier']['digest']='sha256:'+'a'*64
        result,network,_=self.execute(grant);self.assertEqual('AUDIT_DISTINCT_MODEL_REQUIRED',result['reason']);network.assert_not_called()
        self.policy['verifier']['allow_source']=False
        result,network,_=self.execute(grant);self.assertEqual('AUDIT_VERIFIER_OPT_IN_REQUIRED',result['reason']);network.assert_not_called()

    def test_existing_lock_never_calls_or_releases_other_owner(self):
        grant=self.grant();lock=self.cfg.results/'control/review.lock';lock.write_text('another-job')
        result,network,_=self.execute(grant);network.assert_not_called()
        self.assertEqual('ACTIVE_OR_UNKNOWN_REVIEW_EXISTS',result['reason']);self.assertEqual('another-job',lock.read_text())

    def test_live_model_mismatch_closes_unused_grant_without_post(self):
        grant=self.grant();result,network,_=self.execute(grant,[{'models':[]}])
        self.assertEqual('FAILED',result['status']);self.assertEqual(1,network.await_count)
        self.assertEqual(0,load_json(grant_path(self.cfg,grant['grant_id']))['calls_consumed'])

    def test_invalid_extra_severity_consumes_once_without_retry(self):
        grant=self.grant();response=self.response();value=json.loads(response['message']['content']);value['severity']='high'
        response['message']['content']=json.dumps(value)
        result,network,_=self.execute(grant,[{'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]},response])
        self.assertEqual('FAILED',result['status']);self.assertEqual(2,network.await_count)
        self.assertEqual('CLOSED_FAILED',load_json(grant_path(self.cfg,grant['grant_id']))['state'])
        self.assertFalse((self.cfg.results/'control/review.lock').exists())

    def test_timeout_retains_lock_and_requires_explicit_idle_ack(self):
        grant=self.grant();result,network,_=self.execute(grant,[{'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]},TimeoutError()])
        self.assertEqual('UNKNOWN',result['remote_completion']);self.assertEqual(2,network.await_count)
        self.assertEqual('CLOSED_BLOCKED',load_json(grant_path(self.cfg,grant['grant_id']))['state'])
        with self.assertRaises(ProductError):acknowledge_verifier(self.cfg,grant['grant_id'],False)
        acknowledged=acknowledge_verifier(self.cfg,grant['grant_id'],True)
        self.assertEqual(1,acknowledged['calls_consumed']);self.assertEqual(0,acknowledged['calls_refunded'])
        result,network,_=self.execute(grant);network.assert_not_called()

    def test_cancellation_persists_charge_and_unknown_remote(self):
        grant=self.grant();result,_,_=self.execute(grant,[{'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]},asyncio.CancelledError()])
        self.assertEqual('INTERRUPTED',result['status']);self.assertEqual(1,result['model_calls'])
        self.assertTrue((self.cfg.results/'control/review.lock').exists())

    def test_source_change_during_response_rejects_proposal(self):
        grant=self.grant()
        async def request(client,method,url,**kwargs):
            if method=='GET':return {'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]}
            (self.source/'Api.java').write_text('class Changed {}');return self.response()
        result,network,_=self.execute(grant,request)
        self.assertEqual('REVIEW_SOURCE_CHANGED',result['reason']);self.assertEqual('deferred',result['candidates'][0]['state'])

    def test_reserved_owner_cannot_be_acknowledged_while_running(self):
        import os
        grant=self.grant();grant.update(state='RESERVED',owner_pid=os.getpid());save_json(grant_path(self.cfg,grant['grant_id']),grant,replace=True)
        with self.assertRaisesRegex(ProductError,'AUDIT_OWNER_STILL_RUNNING'):acknowledge_verifier(self.cfg,grant['grant_id'],True)

    def test_unsupported_candidate_stays_deferred_without_spending(self):
        self.report['findings'][0]['kind']='DEPENDENCY_VERSION_MATCH';self.persist();grant=self.grant()
        result,network,_=self.execute(grant);network.assert_not_called();self.assertEqual('AUDIT_NO_SUPPORTED_CANDIDATES',result['reason'])

    def test_budget_reserved_before_first_network_operation(self):
        grant=self.grant()
        async def request(client,method,url,**kwargs):
            saved=load_json(grant_path(self.cfg,grant['grant_id']))
            self.assertEqual('RESERVED',saved['state']);self.assertEqual(1,saved['calls_reserved'])
            if method=='GET':self.assertEqual(0,saved['calls_consumed']);return {'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]}
            self.assertEqual(1,saved['calls_consumed']);return self.response()
        result,_,_=self.execute(grant,request);self.assertEqual('COMPLETED_FOR_SELECTED_CANDIDATES',result['status'])

    def test_concurrent_verification_consumes_grant_only_once(self):
        grant=self.grant()
        async def run():
            async def request(client,method,url,**kwargs):
                await asyncio.sleep(0)
                return {'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]} if method=='GET' else self.response()
            with patch('localcode_review_mcp.audit_verifier.json_request',new_callable=AsyncMock,side_effect=request) as network, \
                 patch('localcode_review_mcp.audit_verifier.access_boundary',return_value={}):
                outcomes=await asyncio.gather(*(verify_candidates(self.cfg,'scan-fixture',grant['grant_id']) for _ in range(2)))
                self.assertEqual(2,network.await_count)
                self.assertEqual(1,sum(r['status']=='COMPLETED_FOR_SELECTED_CANDIDATES' for r in outcomes))
        asyncio.run(run())
        self.assertEqual(1,load_json(grant_path(self.cfg,grant['grant_id']))['calls_consumed'])

    def test_grant_revoked_after_model_lookup_prevents_post(self):
        grant=self.grant()
        async def request(client,method,url,**kwargs):
            self.assertEqual('GET',method)
            path=grant_path(self.cfg,grant['grant_id']);value=load_json(path);value['state']='REVOKED';save_json(path,value,replace=True)
            return {'models':[{'name':'qwen3-coder:30b','digest':'b'*64}]}
        result,network,_=self.execute(grant,request)
        self.assertEqual('AUDIT_GRANT_CHANGED',result['reason']);self.assertEqual(1,network.await_count)
        self.assertEqual(0,result['model_calls'])
        self.assertEqual('REVOKED',load_json(grant_path(self.cfg,grant['grant_id']))['state'])

    def test_surface_limit_is_visible(self):
        info={'endpoints':[{'endpoint_id':f'ep-{i}','http_method':'GET','http_path':'/x','mapping_status':'AST_LITERAL'} for i in range(1500)],'support_reasons':[]}
        surface=surface_inventory(self.snapshot,info)
        self.assertEqual(1500,len(surface['items']));self.assertEqual(1,surface['omitted'])

    def test_malformed_candidate_and_missing_source_hash_rejected(self):
        self.report['findings']=[None];self.persist()
        with self.assertRaisesRegex(ProductError,'AUDIT_CANDIDATES_REQUIRED'):self.grant()
        self.report['findings']=[{'finding_id':'F1'}];self.report['source_snapshot_sha256']=None;self.persist()
        with self.assertRaisesRegex(ProductError,'AUDIT_SOURCE_HASH_REQUIRED'):self.grant()

    def test_two_keys_for_same_author_principal_do_not_prove_independence(self):
        self.policy['trusted_reviewers']['reviewer-key']['principal_id']='Author'
        self.report['review_policy_sha256']=digest(self.policy['trusted_reviewers']);self.persist()
        with self.assertRaisesRegex(ProductError,'INDEPENDENT_REVIEWER_REQUIRED'):record_audit_review(self.cfg,'scan-fixture',self.review())

    def test_async_job_returns_before_slow_verifier_and_is_cancellable(self):
        grant=self.grant()
        async def run():
            started=asyncio.Event();pending=asyncio.Event()
            async def slow(*args):started.set();await pending.wait()
            with patch('localcode_review_mcp.audit_jobs.verify_candidates',side_effect=slow):
                jobs=AuditVerificationJobs(self.cfg)
                state=await asyncio.wait_for(jobs.start('scan-fixture',grant['grant_id']),1)
                await started.wait();self.assertEqual('RUNNING',jobs.status(state['job_id'])['state'])
                cancelled=await jobs.cancel(state['job_id']);self.assertEqual('CANCELLED',cancelled['state'])
        asyncio.run(run())
        self.assertEqual(0,load_json(grant_path(self.cfg,grant['grant_id']))['calls_consumed'])

    def test_async_job_persists_deferred_result_without_network(self):
        grant=self.grant();self.policy['verifier']['enabled']=False
        async def run():
            with patch('localcode_review_mcp.audit_verifier.json_request',new_callable=AsyncMock) as network:
                jobs=AuditVerificationJobs(self.cfg);state=await jobs.start('scan-fixture',grant['grant_id'])
                await jobs.tasks[state['job_id']]
                self.assertEqual('DEFERRED',jobs.status(state['job_id'])['state']);network.assert_not_called()
                self.assertEqual('DEFERRED',self.store.read(state['job_id'])['result']['status'])
        asyncio.run(run())

    def test_async_job_cancel_before_run_and_restart_never_resends(self):
        grant=self.grant()
        async def run():
            jobs=AuditVerificationJobs(self.cfg);state=await jobs.start('scan-fixture',grant['grant_id'])
            self.assertEqual('CANCELLED',(await jobs.cancel(state['job_id']))['state'])
            state.update(state='RUNNING',owner_pid=99999999)
            save_json(self.store.folder(state['job_id'])/'status.json',state,replace=True)
            restored=AuditVerificationJobs(self.cfg)
            with patch('localcode_review_mcp.audit_jobs.process_alive',return_value=False):
                self.assertEqual('INTERRUPTED',restored.status(state['job_id'])['state'])
                self.assertEqual({},restored.tasks)
        asyncio.run(run())


if __name__=='__main__':unittest.main()

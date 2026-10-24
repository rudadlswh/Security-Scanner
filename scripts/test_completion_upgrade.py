"""확장 수집·소스 가설·사전등록/검토·CVE 수정 검증·실행 해시의 실패 경계를 확인한다."""
import asyncio
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, AsyncMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.workspace import ProductConfig, ProductStore, ProductError, Snapshot, digest, save_json, load_json
from localcode_review_mcp.collector import inventory,collect,declared_types,resolve_type
from localcode_review_mcp.source_security import scan_source_security
from localcode_review_mcp.assurance import freeze_benchmark,run_benchmark,record_review,validate_source_proposal
from localcode_review_mcp.dependency_verification import evaluate_dependency_fix
from localcode_review_mcp.source_analysis import prepare_source_request,validate_generated_proposal
from localcode_review_mcp.reviews import SourceReviewJobs,authorize_model
from localcode_review_mcp import provenance


class CompletionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        self.config=ProductConfig(self.root/'config.json',{'demo':{'root':str(self.source),'allow_source_proposals':True}},
            Path(os.environ['JAVA_HOME']) if os.environ.get('JAVA_HOME') else None,self.root/'results',
            {'name':'qwen3.5:9b','digest':'a'*64})

    def files(self,values):
        for name,text in values.items():
            p=self.source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8')

    def fixture(self):
        self.files({'Api.java':'''package demo; import org.springframework.web.bind.annotation.*;
          @RestController class Api { Service service; @GetMapping("/item") String get(@RequestParam String q) { return service.find(q); } }
          ''','Service.java':'''package demo; import jakarta.persistence.EntityManager;
          class Service { EntityManager em; String find(String q) { em.createQuery("from Item where name='"+q+"'"); return q; } }
          '''})
        prepared=inventory(self.config,'demo')
        return collect(self.config,'demo',prepared[2]['endpoints'][0]['endpoint_id'],prepared=prepared)

    def proposal(self,c):
        return {'contract':'source-proposal/1','collection_sha256':c['collection_sha256'],
                'claims':[{'id':'C1','hypothesis':'Review query construction.','evidence_ids':['E001'],
                           'suggested_change':'Bind the parameter.','validation_steps':['Check normal and quote input.'],'assumptions':[]}]}

    def test_cross_service_source_trace_and_safe_binding(self):
        self.fixture();report=scan_source_security(self.config,'demo')
        self.assertEqual(1,len(report['findings']))
        f=report['findings'][0];self.assertEqual('Service.java',f['path'])
        self.assertEqual(['demo.Api.get','demo.Service.find'],f['declared_call_chain'])
        self.assertEqual(['q'],f['source_parameters'])
        self.files({'Service.java':'''package demo; import jakarta.persistence.EntityManager;
          class Service { EntityManager em; String find(String q) { em.createQuery("from Item where name=:name").setParameter("name",q); return q; } }'''})
        self.assertEqual([],scan_source_security(self.config,'demo')['findings'])

    def test_overload_inheritance_callback_and_reflection_are_distinguished(self):
        self.files({'Api.java':'''package demo; import org.springframework.web.bind.annotation.*;
         @RestController class Api { Child service; @GetMapping("/item") void get(@RequestParam String q) {
          service.find(q); Runnable work=service::cleanup;
          java.util.concurrent.CompletableFuture.runAsync(()->service.cleanup()); Class.forName(q).getMethod(q); } }
         class Parent { void find(String q) {} void find(int q) {} }
         class Child extends Parent { void cleanup() {} }'''})
        data=inventory(self.config,'demo');c=collect(self.config,'demo',data[2]['endpoints'][0]['endpoint_id'],prepared=data)
        self.assertIn('demo.Parent.find',{e['symbol'] for e in c['evidence']})
        self.assertTrue(any(e['target']=='demo.Child.cleanup' and e['execution_context']=='DEFERRED_CALLBACK_CONTEXT' for e in c['edges']))
        self.assertTrue(any(e['reason']=='REFLECTION_DYNAMIC_TARGET' for e in c['unresolved_calls']))
        self.assertFalse(c['execution_completeness_proven'])

    def test_interface_short_name_collision_does_not_link_wrong_package(self):
        self.files({'a/I.java':'package a; interface I {void work();}', 'b/I.java':'package b; interface I {void work();}',
                    'b/Wrong.java':'package b; class Wrong implements I { public void work(){} }',
                    'a/Api.java':'package a; import org.springframework.web.bind.annotation.*; @RestController class Api {I service; @GetMapping("/x") void get(){service.work();}}'})
        data=inventory(self.config,'demo');c=collect(self.config,'demo',data[2]['endpoints'][0]['endpoint_id'],prepared=data)
        self.assertNotIn('b.Wrong.work',{e['symbol'] for e in c['evidence']})

    def test_frozen_benchmark_detects_edit_and_tracks_missing_expected_symbol(self):
        self.fixture()
        plan={'contract':'benchmark-plan/1','authors':['builder'],'previously_exposed':False,
              'cases':[{'id':'external1','project_id':'demo','endpoint':{'http_method':'GET','http_path':'/item'},
                        'expected_symbols':['demo.Api.get','demo.Service.find','demo.Missing.find']}]}
        frozen=freeze_benchmark(self.config,plan,self.root/'frozen.json')
        report=run_benchmark(self.config,frozen)
        self.assertEqual(['demo.Missing.find'],report['cases'][0]['missing_required'])
        self.assertFalse(report['generalization_proven'])
        frozen['plan']['cases'][0]['expected_symbols']=[]
        with self.assertRaisesRegex(ProductError,'FREEZE_MISMATCH'):run_benchmark(self.config,frozen)
        frozen=load_json(self.root/'frozen.json');self.files({'Added.java':'class Added {}'})
        with self.assertRaisesRegex(ProductError,'SOURCE_CHANGED'):run_benchmark(self.config,frozen)

    def test_independent_review_rejects_author_stale_hash_and_incomplete_items(self):
        store=ProductStore(self.config.results);i=store.create('benchmark',{'kind':'benchmark'})
        report={'report_id':i,'kind':'benchmark','authors':['builder'],'cases':[{'case_id':'c1'}]}
        save_json(store.folder(i)/'report.json',report)
        review={'report_sha256':digest(report),'reviewer_id':'builder','not_involved_in_implementation_or_expected_results':True,
                'items':[{'id':'c1','verdict':'UNRESOLVED','rationale':'Need deployment evidence.'}]}
        with self.assertRaisesRegex(ProductError,'INDEPENDENT_REVIEWER'):record_review(self.config,i,review)
        review['reviewer_id']='separate-reviewer';review['report_sha256']='0'*64
        with self.assertRaisesRegex(ProductError,'HASH_MISMATCH'):record_review(self.config,i,review)
        review['report_sha256']=digest(report);saved=record_review(self.config,i,review)
        self.assertEqual('LOCAL_DECLARATION_NOT_AUTHENTICATED',saved['reviewer_identity_assurance'])
        self.assertEqual(report,store.read(i))

    def test_source_proposal_valid_links_never_approve_semantics(self):
        c=self.fixture();p=self.proposal(c)
        r=validate_source_proposal(self.config,c['collection_id'],p)
        self.assertEqual('NOT_REVIEWED',r['claims'][0]['semantic_status'])
        self.assertNotIn('hypothesis',json.dumps(r))
        p['claims'][0]['evidence_ids']=['UNKNOWN']
        with self.assertRaisesRegex(ProductError,'UNKNOWN_EVIDENCE'):validate_source_proposal(self.config,c['collection_id'],p)

    def test_source_generation_rejects_forged_hash_extra_fields_and_unknown_evidence(self):
        c=self.fixture();p=self.proposal(c);self.assertEqual(p,validate_generated_proposal(p,c))
        for change in ('hash','extra','evidence'):
            bad=copy.deepcopy(p)
            if change=='hash':bad['collection_sha256']='0'*64
            elif change=='extra':bad['safe']=True
            else:bad['claims'][0]['evidence_ids']=['E999']
            with self.assertRaises(ProductError):validate_generated_proposal(bad,c)

    def test_source_generation_is_separate_opt_in_and_mocked_one_call(self):
        c=self.fixture();p=self.proposal(c)
        async def run():
            authorize_model(self.config,calls=1,minutes=5,diagnostic=True)
            response={'done':True,'message':{'content':json.dumps(p)},'prompt_eval_count':100}
            with patch('localcode_review_mcp.reviews.access_boundary',return_value={}), \
                 patch('localcode_review_mcp.reviews.measure_input',return_value={'exact_local_token_count':None}), \
                 patch('localcode_review_mcp.reviews.json_request',new_callable=AsyncMock,side_effect=[{'models':[{'name':'qwen3.5:9b','digest':'a'*64}]},response]) as request:
                jobs=SourceReviewJobs(self.config);started=await jobs.start('demo',c['collection_id']);await jobs.tasks[started['job_id']]
                self.assertEqual('COMPLETED',jobs.status(started['job_id'])['state'])
                self.assertEqual(2,request.await_count)
                r=ProductStore(self.config.results).read(started['job_id']);self.assertEqual('source-proposal-review',r['kind'])
                self.assertEqual('NOT_REVIEWED',r['semantic_review_status'])
        asyncio.run(run())

    def test_source_mode_without_diagnostic_does_not_send(self):
        c=self.fixture()
        async def run():
            authorize_model(self.config,calls=1,minutes=5)
            with patch('localcode_review_mcp.reviews.json_request',new_callable=AsyncMock) as request:
                jobs=SourceReviewJobs(self.config);start=await jobs.start('demo',c['collection_id']);await jobs.tasks[start['job_id']]
                state=jobs.status(start['job_id']);self.assertFalse(state['request_sent']);request.assert_not_called()
                self.assertIn('DIAGNOSTIC_AUTHORIZATION',state['reason'])
        asyncio.run(run())

    def test_stale_process_refuses_new_result_and_provenance_is_saved(self):
        store=ProductStore(self.config.results);identifier=store.create('x',{'kind':'test'})
        receipt=load_json(store.folder(identifier)/'execution-start.json')
        self.assertEqual(os.getpid(),receipt['pid']);self.assertEqual(digest(receipt),store.read(identifier,'metadata.json')['execution_provenance']['receipt_sha256'])
        with patch.object(provenance,'fingerprint',return_value={'files':{},'sha256':'changed'}):
            self.assertTrue(provenance.status()['restart_required'])
            with self.assertRaisesRegex(ProductError,'RESTART_REQUIRED'):store.create('x',{})

    def test_dependency_fix_requires_exact_runtime_probe_and_compatibility(self):
        a={'coverage':'RESOLVED_RUNTIME_WITH_HASH_BINDING','unresolved':[],'packages':[{'name':'x:lib','version':'1'}]}
        b={**a,'packages':[{'name':'x:lib','version':'2'}]}
        plan={'contract':'dependency-fix-plan/1','required_versions':{'x:lib':'2'},'compatibility_command_sha256':['a'*64],
              'advisory_probes':[{'advisory_id':'TEST-ADVISORY','advisory_sha256':'b'*64,'target_id':'api','scenario_id':'repro'}]}
        pre=[{'target_id':'api','status':'COMPLETED','scenarios':[{'id':'repro','status':'BEHAVIOR_DISCREPANCY'}]}]
        post=[{'target_id':'api','status':'COMPLETED','scenarios':[{'id':'repro','status':'MATCHES_EXPECTED_BEHAVIOR'}]}]
        builds=[{'argv_sha256':'a'*64,'exit_code':0}]
        self.assertEqual('MATCHES_REGISTERED_CHECKS',evaluate_dependency_fix(a,b,plan,pre,post,builds)['status'])
        self.assertEqual('NEEDS_REVISION',evaluate_dependency_fix(a,b,plan,pre,post,[])['status'])
        b['packages'].append({'name':'x:lib','version':'1'})
        self.assertEqual('NEEDS_REVISION',evaluate_dependency_fix(a,b,plan,pre,post,builds)['status'])
        a['coverage']='PROVIDED_COMPONENTS_ONLY'
        with self.assertRaisesRegex(ProductError,'BOUND_RUNTIME'):evaluate_dependency_fix(a,b,plan,pre,post,builds)


if __name__=='__main__':unittest.main()

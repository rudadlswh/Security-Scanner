"""Bounded Python routes, source-to-sink behavior, tool trust and plan failures."""
import asyncio
import copy
import json
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.workspace import ProductConfig,ProductError,ProductStore,digest,save_json
from localcode_review_mcp.collector import inventory,collect,evidence_text
from localcode_review_mcp.python_source import Flow,PythonSnapshot
from localcode_review_mcp.python_tools import bandit_findings
from localcode_review_mcp.python_dependencies import inventory as dependency_inventory
from localcode_review_mcp.python_validation import validate
from localcode_review_mcp.project_scan import ProjectScans
from localcode_review_mcp.reviews import ReviewJobs
from localcode_review_mcp.disposable import DisposableServer

ROOT=Path(__file__).resolve().parents[1]


class PythonIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name);self.source=self.folder/'source';self.source.mkdir()
        for p in (ROOT/'tools/python-http-fixture').glob('*.py'):shutil.copy2(p,self.source/p.name)
        self.config=ProductConfig(self.folder/'config.json',{'demo':{'root':str(self.source)}},results=self.folder/'results')

    def prepared(self):return inventory(self.config,'demo')

    def test_four_vulnerable_routes_and_improved_routes_are_distinguished(self):
        s,a,i=self.prepared();rows={e['http_path']:[f['rule_id'] for f in Flow(s,a,e).run().findings] for e in a['endpoints']}
        self.assertEqual(['LCR-PY-SQL-001'],rows['/vulnerable/search'])
        self.assertEqual(['LCR-PY-XSS-001'],rows['/vulnerable/reflect'])
        self.assertEqual(['LCR-PY-IDOR-001'],rows['/vulnerable/invoice'])
        self.assertEqual(['LCR-PY-PATH-001'],rows['/vulnerable/download'])
        self.assertTrue(all(not rows[p] for p in rows if p.startswith('/safe/')))

    def test_python_inventory_never_imports_project_code(self):
        marker=self.folder/'executed'
        (self.source/'evil.py').write_text(f'open({str(marker)!r},"w").write("executed")',encoding='utf-8')
        self.prepared();self.assertFalse(marker.exists())

    def test_metadata_keeps_hashes_but_not_hardcoded_credentials(self):
        s,_,_=self.prepared()
        self.assertIn('sast_examples.py',s.files)
        self.assertNotIn('LAB-ONLY-hardcoded-password',json.dumps(s.metadata()))
        self.assertFalse(s.metadata()['raw_source_allowed_for_ai'])

    def test_python_collection_cannot_enter_existing_ai_contract(self):
        p=self.prepared();c=collect(self.config,'demo',p[2]['endpoints'][0]['endpoint_id'],prepared=p)
        with self.assertRaisesRegex(ProductError,'PYTHON_RAW_SOURCE_AI'):evidence_text(p[0],c)
        async def run():
            with self.assertRaisesRegex(ProductError,'PYTHON_RAW_SOURCE_AI'):
                await ReviewJobs(self.config).start('demo',c['collection_id'])
        asyncio.run(run())
        self.assertFalse((self.config.results/'control/model-authorization.json').exists())

    def test_source_modification_invalidates_snapshot(self):
        s,_,_=self.prepared();(self.source/'app.py').write_text('print(1)',encoding='utf-8')
        with self.assertRaisesRegex(ProductError,'SOURCE_CHANGED'):s.verify()

    def test_source_addition_invalidates_snapshot(self):
        s,_,_=self.prepared();(self.source/'new.py').write_text('print(1)',encoding='utf-8')
        with self.assertRaisesRegex(ProductError,'SOURCE_CHANGED'):s.verify()

    def test_syntax_error_is_reported_without_source_excerpt(self):
        (self.source/'bad.py').write_text('def invalid(',encoding='utf-8')
        _,a,i=self.prepared();self.assertEqual('PYTHON_SYNTAX_ERROR',a['errors'][0]['reason'])
        self.assertIn('PYTHON_PARSE_ERRORS',i['support_reasons'])

    def test_non_http_class_is_not_declared_as_http_boundary(self):
        (self.source/'app.py').write_text('class Other:\n def dispatch(self):\n  if url.path=="/secret":pass',encoding='utf-8')
        _,_,i=self.prepared();self.assertEqual([],i['endpoints'])

    def test_exact_pypi_pins_and_unsafe_requirement_lines_are_distinguished(self):
        (self.source/'requirements.txt').write_text('Requests==2.31.0\nJinja2==3.1.4\n-e https://untrusted.example/repo\nlib>=1\n',encoding='utf-8')
        r=dependency_inventory(self.config,'demo');self.assertEqual(2,len(r['packages']))
        self.assertEqual(2,len(r['unresolved']));self.assertFalse(r['runtime_use_proven'])

    def test_bandit_not_configured_is_skipped_without_process(self):
        s,_,_=self.prepared()
        with patch('localcode_review_mcp.python_tools.invoke') as called:
            rows,status=bandit_findings(s,{},self.folder)
        self.assertEqual([],rows);self.assertEqual('SKIPPED',status['status']);called.assert_not_called()

    def plan(self):
        s,a,i=self.prepared();source='app.py'
        plan={'contract':'python-http-validation/1','source_files':{source:digest(s.files[source])},
              'cases':[{'id':'safe','path':'/safe/search','expect_status':200,'query':{'q':'notebook'}}]}
        p=self.folder/'plan.json';save_json(p,plan)
        spec={'authorized_read_only_checks':True,'plan_file':str(p),'plan_sha256':digest(plan)}
        return s,i,plan,spec,p

    def test_stale_plan_or_source_hash_is_rejected(self):
        s,i,plan,spec,p=self.plan();self.assertEqual(plan,validate(spec,s,i)[0])
        plan['cases'][0]['expect_status']=403;save_json(p,plan,replace=True)
        with self.assertRaisesRegex(ProductError,'PLAN_HASH'):validate(spec,s,i)
        plan['source_files']['app.py']='0'*64;spec['plan_sha256']=digest(plan);save_json(p,plan,replace=True)
        with self.assertRaisesRegex(ProductError,'SOURCE_MISMATCH'):validate(spec,s,i)

    def test_unknown_route_mutating_request_and_header_injection_are_rejected(self):
        s,i,plan,spec,p=self.plan()
        for change in ('route','method','header'):
            altered=copy.deepcopy(plan);row=altered['cases'][0]
            if change=='route':row['path']='http://outside.example/'
            elif change=='method':row['method']='POST'
            else:row['headers']={'Host':'127.0.0.1\r\nInjected: yes'}
            spec['plan_sha256']=digest(altered);save_json(p,altered,replace=True)
            with self.assertRaises(ProductError):validate(spec,s,i)

    def test_full_python_scan_reports_candidates_and_no_ai_or_network_permission(self):
        async def run():
            jobs=ProjectScans(self.config);start=await jobs.start(str(self.source),max_ai_endpoints=0,include_remediation=False)
            await jobs.tasks[start['job_id']];return jobs.report(start['job_id'])
        report=asyncio.run(run())
        self.assertEqual('COMPLETED',report['execution_state'])
        self.assertEqual('Python',report['checks']['source']['source_language'])
        self.assertEqual(4,report['checks']['sast']['candidate_count'])
        self.assertEqual(0,report['model_calls_sent']);self.assertEqual('NOT_ASSESSED',report['security_verdict'])
        self.assertEqual('SKIPPED',report['checks']['dynamic']['status'])
        self.assertNotIn('LAB-ONLY-hardcoded-password',json.dumps(report))

    def test_copied_source_mismatch_stops_before_starting_project(self):
        spec={'project_root':str(self.source),'authorized_disposable_environment':True,'acknowledge_command_execution':True,
              'command':[sys.executable,'-B','{project_copy}/app.py'],'base_url':'http://127.0.0.1:59137',
              'expected_source_files':{'app.py':'0'*64}}
        server=DisposableServer(spec,self.source,self.folder/'run',[{'base_url':spec['base_url'],'authorized_disposable_environment':True}])
        server.run_dir.mkdir()
        async def run():
            try:
                with self.assertRaisesRegex(ProductError,'COPIED_SOURCE_MISMATCH'):await server.start()
                self.assertIsNone(server.process)
            finally:await server.stop()
        asyncio.run(run());self.assertFalse(server.copy.exists())

    def browser_result(self,status,title,expected):
        from localcode_review_mcp.python_browser import main
        page=SimpleNamespace(goto=lambda *a,**k:SimpleNamespace(status=status),title=lambda:title,close=lambda:None)
        context=SimpleNamespace(route=lambda *a:None,new_page=lambda:page,close=lambda:None)
        browser=SimpleNamespace(new_context=lambda **k:context,version='fixture-browser',close=lambda:None)
        api=SimpleNamespace(chromium=SimpleNamespace(launch=lambda **k:browser))
        class Scope:
            def __enter__(self):return api
            def __exit__(self,*a):pass
        spec={'base_url':'http://127.0.0.1:59137','playwright_version':'test',
              'cases':[{'id':'safe','path':'/safe','title_marker':'MARK','expect_status':200,'expected_execution':expected}]}
        stdout=io.StringIO()
        with patch.dict(sys.modules,{'playwright.sync_api':SimpleNamespace(sync_playwright=lambda:Scope())}), \
             patch('importlib.metadata.version',return_value='test'), \
             patch('sys.stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(spec).encode()))),patch('sys.stdout',stdout):
            main()
        return json.loads(stdout.getvalue())['cases'][0]

    def test_browser_network_error_is_not_mistaken_for_xss_blocking(self):
        self.assertFalse(self.browser_result(503,'',False)['matches'])
        self.assertFalse(self.browser_result(404,'',False)['matches'])

    def test_browser_requires_expected_effect_and_successful_response(self):
        self.assertTrue(self.browser_result(200,'',False)['matches'])
        self.assertTrue(self.browser_result(200,'MARK',True)['matches'])
        self.assertFalse(self.browser_result(200,'',True)['matches'])


if __name__=='__main__':unittest.main()

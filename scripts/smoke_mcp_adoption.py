"""새 STDIO의 감사 계약 노출/영수증 조회. 합성 로컬 보고서만 사용한다."""
import asyncio
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from smoke_mcp import TOOLS
from smoke_mcp_product import smoke as existing_smoke
ROOT=Path(__file__).resolve().parents[1]


def payload(result):
    assert not result.isError, result.content
    return result.structuredContent or json.loads(''.join(v.text for v in result.content if v.type=='text'))


async def smoke():
    await existing_smoke()
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary); config=root/'config.json'; results=root/'results'
        config.write_text(json.dumps({'version':1,'projects':{},'results_dir':str(results)}),encoding='utf-8')
        folder=results/'audit-fixture';folder.mkdir(parents=True)
        receipt={'kind':'audit-review-receipt','report_id':'audit-fixture',
                 'identity_assurance':'LOCAL_DECLARATION_NOT_AUTHENTICATED','security_verdict':'NOT_ASSESSED'}
        (folder/'report.json').write_text(json.dumps(receipt),encoding='utf-8')
        scan_folder=results/'scan-fixture';scan_folder.mkdir()
        (scan_folder/'report.json').write_text(json.dumps({'kind':'project-security-scan','report_id':'scan-fixture',
            'project_id':'demo','execution_state':'COMPLETED','source_snapshot_sha256':'a'*64,
            'findings':[{'finding_id':'F1','kind':'STATIC_SECURITY_CANDIDATE'}]}),encoding='utf-8')
        params=StdioServerParameters(command=sys.executable,args=['-u',str(ROOT/'mcp_server.py'),'--config',str(config)],cwd=str(ROOT))
        async with stdio_client(params) as (reader,writer):
            async with ClientSession(reader,writer,read_timeout_seconds=dt.timedelta(seconds=30)) as session:
                await session.initialize()
                listing=await session.list_tools();prompts=await session.list_prompts()
                assert {t.name for t in listing.tools}==TOOLS
                cap=payload(await session.call_tool('get_product_capabilities',{}))
                assert cap['implementation']=='product-workflow/6'
                assert cap['remediation_contract']=='security-remediation/17'
                assert cap['audit_contract'].startswith('audit-ledger/2;')
                assert 'record-audit-review' in cap['assurance_cli']
                assert not cap['runtime_provenance']['restart_required']
                assert payload(await session.call_tool('read_review_report',{'report_id':'audit-fixture'}))==receipt
                invalid=await session.call_tool('verify_audit_candidates',{'report_id':'../secret','grant_id':'../secret'})
                assert invalid.isError
                for name in ('get_audit_verification_status','cancel_audit_verification'):
                    assert (await session.call_tool(name,{'job_id':'../secret'})).isError
                job=payload(await session.call_tool('verify_audit_candidates',{'report_id':'scan-fixture','grant_id':'auditgrant-missing'}))
                assert job['state']=='QUEUED'
                for _ in range(20):
                    status=payload(await session.call_tool('get_audit_verification_status',{'job_id':job['job_id']}))
                    if status['state']=='DEFERRED':break
                    await asyncio.sleep(0.05)
                assert status['state']=='DEFERRED',status
                job_report=payload(await session.call_tool('read_review_report',{'report_id':job['job_id']}))
                assert job_report['result']['model_calls']==0
                assert job_report['result']['reason']=='AUDIT_VERIFIER_OPT_IN_REQUIRED'
                print(json.dumps({'status':'passed','implementation':cap['implementation'],
                    'audit_contract':cap['audit_contract'],'remediation_contract':cap['remediation_contract'],
                    'tools':len(listing.tools),'prompts':len(prompts.prompts),'runtime_provenance':cap['runtime_provenance'],
                    'receipt_read':'synthetic fixture','async_verification':'DEFERRED_WITHOUT_OPT_IN_NO_NETWORK',
                    'new_invalid_requests_rejected':3,'model_calls':0,'external_requests':0}))


if __name__=='__main__': asyncio.run(smoke())

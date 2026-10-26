"""One new MCP scan of an operator-configured Python fixture. No model budget."""
import argparse
import asyncio
import datetime as dt
import json
from pathlib import Path
import sys
import time
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT=Path(__file__).resolve().parents[1]


def payload(result):
    if result.isError:raise RuntimeError('MCP_TOOL_ERROR:'+str(result.content))
    return result.structuredContent or json.loads(''.join(c.text for c in result.content if c.type=='text'))


async def run(args):
    args.output.mkdir(parents=True,exist_ok=False)
    def save(name,value):(args.output/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    params=StdioServerParameters(command=sys.executable,args=['-u',str(ROOT/'mcp_server.py'),'--config',str(args.config)],cwd=str(ROOT))
    async with stdio_client(params) as (reader,writer):
        async with ClientSession(reader,writer,read_timeout_seconds=dt.timedelta(seconds=45)) as session:
            await session.initialize();tools=await session.list_tools();prompts=await session.list_prompts()
            cap=payload(await session.call_tool('get_product_capabilities',{}));save('capabilities.json',cap)
            save('discovery.json',{'tools':[t.name for t in tools.tools],'prompts':[p.name for p in prompts.prompts]})
            assert cap['implementation']=='product-workflow/7' and not cap['runtime_provenance']['restart_required']
            started=payload(await session.call_tool('scan_project',{'project_path':str(args.target),'max_ai_endpoints':0,'include_remediation':False}));save('started.json',started);print(started,flush=True)
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                status=payload(await session.call_tool('get_project_scan_status',{'job_id':started['job_id']}))
                save('status.json',status)
                if status['state'] in {'COMPLETED','FAILED','CANCELLED','INTERRUPTED'}:break
                await asyncio.sleep(1)
            else:
                cancelled=payload(await session.call_tool('cancel_project_scan',{'job_id':started['job_id']}));save('timeout-cancellation.json',cancelled)
                raise RuntimeError('SCAN_VALIDATION_TIME_LIMIT')
            report=payload(await session.call_tool('read_project_scan_report',{'job_id':started['job_id']}));save('report.json',report)
            for stage in ('sast','cve','dynamic','dependency_runtime'):
                if report['checks'].get(stage,{}).get('report_id'):
                    child=payload(await session.call_tool('read_review_report',{'report_id':report['checks'][stage]['report_id']}));save(stage+'.json',child)
            save('final-capabilities.json',payload(await session.call_tool('get_product_capabilities',{})))
            print({'state':report['execution_state'],'stages':{k:v['status'] for k,v in report['checks'].items()},'model_calls':report['model_calls_sent']},flush=True)
            if report['execution_state']!='COMPLETED' or report['errors']:raise RuntimeError('SCAN_VALIDATION_INCOMPLETE')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--target',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    asyncio.run(run(p.parse_args()))

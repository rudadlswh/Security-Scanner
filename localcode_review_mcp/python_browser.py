"""Fixed headless-browser worker. Input arrives only after parent Job assignment."""
import importlib.metadata
import json
import sys
from urllib.parse import urlsplit


def main():
    spec=json.loads(sys.stdin.buffer.readline(1048577))
    base=urlsplit(spec['base_url'])
    if base.scheme!='http' or base.hostname!='127.0.0.1' or not base.port or base.username or base.password:
        raise ValueError('BROWSER_LOOPBACK_REQUIRED')
    if importlib.metadata.version('playwright')!=spec['playwright_version']:
        raise ValueError('PLAYWRIGHT_VERSION_MISMATCH')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='msedge',headless=True)
        try:
            context=browser.new_context(service_workers='block',accept_downloads=False)
            def route(request):
                dest=urlsplit(request.request.url)
                if (dest.scheme,dest.hostname,dest.port)==(base.scheme,base.hostname,base.port):request.continue_()
                else:request.abort()
            context.route('**/*',route)
            if hasattr(context,'route_web_socket'):
                context.route_web_socket('**/*',lambda ws:ws.close())
            outcomes=[]
            for case in spec['cases']:
                page=context.new_page()
                try:
                    response=page.goto(spec['base_url']+case['path'],wait_until='load',timeout=8000)
                    # Expected effect is a fixed title marker, never arbitrary evaluation.
                    title=page.title()
                    outcomes.append({'id':case['id'],'status_code':response.status if response else None,
                        'script_executed':title==case['title_marker'],'expected_execution':case['expected_execution'],
                        'matches':response is not None and response.status==case['expect_status'] and
                                  ((title==case['title_marker']) is case['expected_execution'])})
                finally:page.close()
            context.close()
            print(json.dumps({'engine':'PLAYWRIGHT_EDGE','version':spec['playwright_version'],
                'browser_version':browser.version,'cases':outcomes,'browser_closed':True,'external_requests_blocked':True}))
        finally:browser.close()


if __name__=='__main__':main()

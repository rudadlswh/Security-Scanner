"""Fixed harmless dependency probes; no commands, host-file payloads or external URLs."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


def main():
    spec=json.loads(sys.stdin.buffer.readline(1048577))
    parsed=urlsplit(spec['url'])
    if parsed.scheme!='https' or parsed.hostname!='127.0.0.1' or parsed.path!='/probe' or not parsed.port:
        raise ValueError('DEPENDENCY_PROBE_LOCAL_TLS_ONLY')
    import requests
    import urllib3
    import jinja2
    from jinja2.sandbox import SandboxedEnvironment
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    with requests.Session() as session:
        session.trust_env=False
        first=session.get(spec['url'],verify=False,timeout=5)
        try:
            second=session.get(spec['url'],verify=True,timeout=5)
            untrusted_accepted=second.status_code==200
        except requests.exceptions.SSLError:
            untrusted_accepted=False
    with requests.Session() as session:
        session.trust_env=False
        ordinary_tls=session.get(spec['url'],verify=spec['certificate'],timeout=5).status_code==200
    class Fixture:
        name='public-value'
        _lab_secret='SYNTHETIC_FORMAT_MARKER'
    sandbox=SandboxedEnvironment()
    sandbox.filters['invoke_fixture_format']=lambda fn: fn(Fixture())
    template='{{ "{0._lab_secret}".format | invoke_fixture_format }}'
    try:format_exposed=sandbox.from_string(template).render()=='SYNTHETIC_FORMAT_MARKER'
    except jinja2.exceptions.SecurityError:format_exposed=False
    ordinary_template=sandbox.from_string('{{ "{0.name}".format | invoke_fixture_format }}').render()=='public-value'
    hashes={}
    for name,module in (('requests',requests),('jinja2',jinja2)):
        root=Path(module.__file__).parent
        files={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*.py')}
        hashes[name]=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    print(json.dumps({'versions':{'requests':requests.__version__,'jinja2':jinja2.__version__},
        'distributions':sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions()),
        'module_source_sha256':hashes,'untrusted_tls_accepted_after_verify_false':untrusted_accepted,
        'private_format_attribute_exposed':format_exposed,'ordinary_trusted_tls':ordinary_tls,
        'ordinary_public_template':ordinary_template,'initial_insecure_request_status':first.status_code}))


if __name__=='__main__':main()

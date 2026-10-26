"""Operator-bound representative dependency conditions and API compatibility checks.

Environments must already exist. Never installs/upgrades the target or selects a
safe version. The controlled fixture is separate from application runtime use.
"""
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

from .disposable import WindowsJob
from .workspace import ProductError,ProductStore,digest,load_json,save_json,now


def worker(python,spec):
    script=Path(__file__).with_name('python_dependency_probe.py')
    if not Path(python).is_absolute() or not Path(python).is_file():raise ProductError('DEPENDENCY_PROBE_INTERPRETER_REQUIRED')
    process=subprocess.Popen([python,'-I','-B',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    job=None
    try:
        if os.name=='nt':job=WindowsJob(process)
        else:raise ProductError('DEPENDENCY_PROBE_JOB_GUARD_WINDOWS_REQUIRED')
        stdout,stderr=process.communicate(json.dumps(spec).encode(),timeout=35)
        if process.returncode or len(stdout)>1048576:raise ProductError('DEPENDENCY_RUNTIME_PROBE_FAILED')
        return json.loads(stdout)
    except subprocess.TimeoutExpired:raise ProductError('DEPENDENCY_RUNTIME_PROBE_TIMEOUT') from None
    finally:
        if job:job.close()
        if process.poll() is None:process.kill()
        process.wait(timeout=10)


def run(config,project_id,spec):
    if spec.get('authorized_fixture_execution') is not True:raise ProductError('DEPENDENCY_RUNTIME_EXPLICIT_AUTHORIZATION_REQUIRED')
    plan=load_json(Path(spec['plan_file']))
    if digest(plan)!=spec.get('plan_sha256') or plan.get('contract')!='python-dependency-runtime/1':raise ProductError('DEPENDENCY_RUNTIME_PLAN_MISMATCH')
    if {a['id'] for a in plan.get('advisories',[])}!={'CVE-2024-35195','CVE-2024-56326'}:raise ProductError('DEPENDENCY_RUNTIME_SUPPORTED_ADVISORIES_REQUIRED')
    root,_=config.project(project_id)
    for a in plan['advisories']:
        path=Path(a['file']).resolve()
        if path.is_relative_to(root) or digest(path.read_bytes())!=a['sha256']:raise ProductError('DEPENDENCY_RUNTIME_ADVISORY_BINDING_MISMATCH')
    store=ProductStore(config.results);identifier=store.create('compat',{'kind':'python-dependency-runtime','project_id':project_id})
    report={'kind':'python-dependency-runtime','report_id':identifier,'project_id':project_id,'status':'RUNNING',
        'plan_sha256':digest(plan),'model_calls':0,'package_installations_by_product':0,'started_at':now(),
        'probe_sha256':digest(Path(__file__).with_name('python_dependency_probe.py').read_bytes()),
        'application_runtime_use_proven':False,'deployment_compatibility_proven':False,'all_cves_fixed':False}
    server=None;thread=None;temporary_path=None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        with tempfile.TemporaryDirectory(prefix='tls-fixture-',dir=store.folder(identifier)) as temporary:
            temporary_path=Path(temporary);key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'LocalCode synthetic TLS')]);stamp=dt.datetime.now(dt.timezone.utc)
            cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(stamp-dt.timedelta(minutes=1)).not_valid_after(stamp+dt.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256())
            certificate=temporary_path/'certificate.pem';private=temporary_path/'private.pem'
            certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM));private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            class Handler(BaseHTTPRequestHandler):
                protocol_version='HTTP/1.1'
                def log_message(self,*args):pass
                def do_GET(self):
                    body=b'LOCAL-TLS-COMPATIBILITY'
                    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(certificate,private)
            server.socket=tls.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            packet={'url':f'https://127.0.0.1:{server.server_port}/probe','certificate':str(certificate)}
            before=worker(spec['before_python'],packet);after=worker(spec['after_python'],packet)
            report.update(before=before,after=after,certificate_sha256=digest(certificate.read_bytes()))
            versions=before['versions']==plan['before_versions'] and after['versions']==plan['after_versions']
            transitions=before['untrusted_tls_accepted_after_verify_false'] and not after['untrusted_tls_accepted_after_verify_false'] and before['private_format_attribute_exposed'] and not after['private_format_attribute_exposed']
            ordinary=all(r['ordinary_trusted_tls'] and r['ordinary_public_template'] for r in (before,after))
            report.update(status='MATCHES_REGISTERED_CHECKS' if versions and transitions and ordinary else 'NEEDS_REVISION',
                exact_versions_match=versions,registered_conditions_fixed=bool(transitions),ordinary_api_checks_passed=ordinary)
            server.shutdown();server.server_close();thread.join(timeout=5)
    except Exception as error:
        report.update(status='INCOMPLETE',reason=str(error) if isinstance(error,ProductError) else type(error).__name__)
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join(timeout=5)
        report['cleanup']={'server_thread_stopped':thread is None or not thread.is_alive(),
            'temporary_key_and_certificate_removed':temporary_path is None or not temporary_path.exists()}
        report['finished_at']=now();save_json(store.folder(identifier)/'report.json',report)
    return report

"""캐시된 JAR와 JDK만 사용해 제품 브리지를 빌드하고 입력/출력 해시를 연결한다. Gradle/모델 호출 없음."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import datetime as dt
ROOT=Path(__file__).resolve().parents[1]


def build(jdk):
    sources=sorted((ROOT/'src/product').rglob('*.java'))+[ROOT/'src/main/java/dev/localcodereview'/f'{n}.java' for n in ('Json','ScopeAudit','PolicyRules','PolicyComparison')]
    jars=sorted((ROOT/'build/product/lib').glob('*.jar'))
    if not jars:raise ValueError('CACHED_PRODUCT_LIBRARIES_REQUIRED')
    def hashes(paths):return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    inputs=hashes(sources+jars);started=dt.datetime.now(dt.timezone.utc).isoformat()
    result=subprocess.run([str(jdk/'bin/javac.exe' if sys.platform=='win32' else jdk/'bin/javac'),'-encoding','UTF-8','--release','17',
        '-cp',str(ROOT/'build/product/lib/*'),'-d',str(ROOT/'build/product/classes'),*[str(p) for p in sources]],capture_output=True)
    if result.returncode:sys.stderr.buffer.write(result.stderr);raise RuntimeError('PRODUCT_COMPILE_FAILED')
    if inputs!=hashes(sources+jars):raise RuntimeError('PRODUCT_BUILD_INPUT_CHANGED')
    receipt={'contract':'product-build/1','started_at':started,'finished_at':dt.datetime.now(dt.timezone.utc).isoformat(),
             'inputs':inputs,'outputs':hashes(sorted((ROOT/'build/product/classes').rglob('*.class'))),
             'compiler_sha256':hashlib.sha256((jdk/('bin/javac.exe' if sys.platform=='win32' else 'bin/javac')).read_bytes()).hexdigest(),
             'exit_code':result.returncode}
    path=ROOT/'build/product/build-receipt.json';path.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'BUILT','inputs':len(inputs),'outputs':len(receipt['outputs']),'receipt':str(path)}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--jdk',type=Path,required=True);a=p.parse_args();build(a.jdk)

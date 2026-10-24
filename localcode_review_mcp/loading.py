"""제품 모듈은 읽은 소스 바이트를 직접 컴파일하여 실행 코드와 해시를 연결한다.
제품 밖 모듈의 로더·캐시는 변경하지 않으며 OS 원격 증명을 제공하지 않는다.
"""
import hashlib
import importlib.abc
import importlib.machinery
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
LOADED={}


class BoundLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        path=Path(self.path)
        raw=path.read_bytes()
        LOADED[path.relative_to(ROOT).as_posix()]=hashlib.sha256(raw).hexdigest()
        return compile(raw,self.path,'exec',dont_inherit=True)


class ProductFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith('localcode_review_mcp.') or fullname=='localcode_review_mcp.loading':return None
        spec=importlib.machinery.PathFinder.find_spec(fullname,path)
        if spec and isinstance(spec.loader,importlib.machinery.SourceFileLoader):
            origin=Path(spec.origin).resolve()
            if origin.is_relative_to(ROOT/'localcode_review_mcp'):
                spec.loader=BoundLoader(fullname,str(origin))
        return spec


def install():
    if not any(isinstance(f,ProductFinder) for f in sys.meta_path):sys.meta_path.insert(0,ProductFinder())

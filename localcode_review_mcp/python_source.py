"""Bounded, non-executing Python http.server analysis. Raw Python stays local.

Literal dispatch branches, query sources, direct self calls, selected sinks and
explicit comparison/containment guards only. Not a Python type checker or proof.
"""
from __future__ import annotations
import ast
from dataclasses import dataclass, field, replace
import os
from pathlib import Path

from .workspace import Snapshot, ProductError, ProductStore, SKIP_DIRS, digest, git_identity, inside, save_json

UNKNOWN = object()


class PythonSnapshot(Snapshot):
    @classmethod
    def read(cls, root, expected_commit=None):
        if expected_commit:
            raise ProductError('PYTHON_PINNED_COMMIT_NOT_SUPPORTED')
        files, excluded, total, walked = {}, [], 0, 0
        for parent, dirs, names in os.walk(root, followlinks=False):
            kept = []
            for name in sorted(dirs):
                p = Path(parent)/name
                if name in SKIP_DIRS or name in {'__pycache__','reports','sca-cache'} or name.startswith('.'):
                    continue
                if p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()):
                    excluded.append({'path':p.relative_to(root).as_posix(),'reason':'DIRECTORY_LINK'})
                else: kept.append(name)
            dirs[:] = kept
            for name in sorted(names):
                walked += 1
                if walked > 20000: raise ProductError('PROJECT_FILE_INVENTORY_LIMIT')
                if not name.endswith('.py') and name != 'requirements.txt': continue
                p = Path(parent)/name; relative = p.relative_to(root).as_posix()
                try: p = inside(root,relative)
                except ProductError:
                    excluded.append({'path':relative,'reason':'FILE_LINK'}); continue
                data = p.read_bytes(); total += len(data)
                if len(data)>1048576 or total>20*1048576 or len(files)>=500:
                    raise ProductError('PYTHON_SOURCE_BUDGET_EXCEEDED')
                try: data.decode('utf-8-sig')
                except UnicodeDecodeError:
                    excluded.append({'path':relative,'reason':'NON_UTF8'}); continue
                # Credential candidates must be scanned locally, but must never
                # be copied into report text or an existing Java AI contract.
                files[relative] = data
        return cls(root,git_identity(root),files,excluded)

    def metadata(self):
        return {**super().metadata(),'source_language':'Python','raw_source_allowed_for_ai':False}

    def verify(self):
        if type(self).read(self.root).metadata()!=self.metadata():
            raise ProductError('SOURCE_CHANGED')


def inventory(config, project_id):
    root, settings = config.project(project_id)
    snapshot = PythonSnapshot.read(root,settings.get('commit'))
    trees, methods, endpoints, errors = {}, {}, [], []
    for path, data in snapshot.files.items():
        if not path.endswith('.py'): continue
        try: tree = ast.parse(data.decode('utf-8-sig'),filename=path)
        except SyntaxError as e:
            errors.append({'path':path,'line':e.lineno,'reason':'PYTHON_SYNTAX_ERROR'}); continue
        trees[path] = tree
        for cls in (n for n in tree.body if isinstance(n,ast.ClassDef)):
            # No framework guess from a method called dispatch in an arbitrary class.
            if not any(ast.unparse(b).split('.')[-1]=='BaseHTTPRequestHandler' for b in cls.bases): continue
            for member in cls.body:
                if isinstance(member,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    methods[(path,cls.name,member.name)] = member
            for member in cls.body:
                if not isinstance(member,ast.FunctionDef) or member.name not in {'dispatch','do_GET','do_POST','do_PUT','do_DELETE','do_PATCH'}: continue
                for node in ast.walk(member):
                    if not isinstance(node,ast.If) or not isinstance(node.test,ast.Compare): continue
                    c=node.test
                    if len(c.ops)!=1 or not isinstance(c.left,ast.Attribute) or c.left.attr!='path': continue
                    rhs=c.comparators[0]
                    if isinstance(c.ops[0],ast.Eq) and isinstance(rhs,ast.Constant): paths=[rhs.value]
                    elif isinstance(c.ops[0],ast.In) and isinstance(rhs,(ast.Tuple,ast.List)):
                        paths=[v.value for v in rhs.elts if isinstance(v,ast.Constant)]
                    else: continue
                    for route in paths:
                        if not isinstance(route,str) or not route.startswith('/') or len(route)>512: continue
                        verb=member.name.removeprefix('do_') if member.name.startswith('do_') else 'GET'
                        key={'path':path,'class':cls.name,'line':node.lineno,'route':route,'verb':verb}
                        endpoints.append({'endpoint_id':'py-'+digest(key)[:20],'http_method':verb,'http_path':route,
                            'mapping_status':'AST_LITERAL','file':path,'class':cls.name,'method':member.name,
                            'start':member.lineno,'end':member.end_lineno,'dispatch_line':node.lineno,
                            'path_expression':ast.unparse(c.left),'branch':node})
    if len(endpoints)>5000: raise ProductError('ENDPOINT_ENUMERATION_LIMIT')
    reasons=[]
    if errors: reasons.append('PYTHON_PARSE_ERRORS')
    if not endpoints: reasons.append('NO_SUPPORTED_PYTHON_HTTP_BOUNDARIES')
    if snapshot.excluded: reasons.append('EXCLUDED_SOURCE_OR_LINKS')
    public=[{k:v for k,v in e.items() if k!='branch'} for e in endpoints]
    info={'project_id':project_id,'source_language':'Python','snapshot':snapshot.metadata(),
          'snapshot_sha256':digest(snapshot.metadata()),'support':'PARTIAL' if reasons else 'SUPPORTED_PYTHON_HTTP_SERVER_SUBSET',
          'support_reasons':reasons,'endpoints':public,'limitations':['LITERAL_HTTP_SERVER_DISPATCH_ONLY','RAW_SOURCE_LOCAL_ONLY_NO_AI','BOUNDED_DECLARED_FLOW_NOT_RUNTIME_PROOF']}
    snapshot.verify()
    return snapshot,{'trees':trees,'methods':methods,'endpoints':endpoints,'errors':errors},info


@dataclass
class Value:
    taint: frozenset = frozenset()
    const: object = UNKNOWN
    tag: str = ''
    base: str = ''
    origin: str = ''


def combined(values, **kwargs):
    return Value(frozenset().union(*(v.taint for v in values)),**kwargs)


class Flow:
    def __init__(self,snapshot,parsed,endpoint):
        self.snapshot,self.parsed,self.endpoint=snapshot,parsed,endpoint
        self.path,self.cls=endpoint['file'],endpoint['class']
        self.findings=[];self.evidence={};self.unresolved=set();self.steps=0;self.chain=[]

    def emit(self,rule,node,value):
        if not value.taint: return
        key=(rule,node.lineno)
        if any((f['rule_id'],f['line'])==key for f in self.findings): return
        self.findings.append({'kind':'STATIC_SECURITY_CANDIDATE','rule_id':rule,'path':self.path,
          'line':node.lineno,'end_line':getattr(node,'end_lineno',node.lineno),'file_sha256':digest(self.snapshot.files[self.path]),
          'endpoint_ids':[self.endpoint['endpoint_id']],'http_path':self.endpoint['http_path'],
          'source_parameters':sorted(value.taint),'declared_call_chain':list(self.chain),'engine':'LOCALCODE_PYTHON_AST',
          'basis':'BOUNDED_PYTHON_HTTP_INPUT_TO_SINK','security_cause_confirmed':False,
          'identifiers':[f'{rule}:{self.path}:{node.lineno}'],'remediation':{'source':'HARNESS_RULE_TEMPLATE',
          'status':'REVIEW_REQUIRED','automatic_apply':False,'change':{
           'LCR-PY-SQL-001':'Bind values separately from a constant SQL statement.',
           'LCR-PY-XSS-001':'Encode HTTP input for the HTML output context.',
           'LCR-PY-IDOR-001':'Check the authenticated caller against the loaded object owner before returning it.',
           'LCR-PY-PATH-001':'Enforce the intended public root after path resolution.'}[rule],
           'tests':['Compare a registered negative input with ordinary input before and after the proposed change.']}})

    def expr(self,n,env,depth):
        if n is None: return Value()
        self.steps+=1
        if self.steps>20000: raise ProductError('PYTHON_FLOW_BUDGET_EXCEEDED')
        if isinstance(n,ast.Constant): return Value(const=n.value)
        if isinstance(n,ast.Name): return env.get(n.id,Value())
        if isinstance(n,ast.Attribute):
            if ast.unparse(n)==self.endpoint['path_expression']: return Value(const=self.endpoint['http_path'])
            if ast.unparse(n)=='self.server.root': return Value(tag='path',base='LAB_ROOT')
            return self.expr(n.value,env,depth)
        if isinstance(n,ast.IfExp):
            c=self.expr(n.test,env,depth).const
            if c is not UNKNOWN: return self.expr(n.body if c else n.orelse,env,depth)
            return combined([self.expr(n.body,env,depth),self.expr(n.orelse,env,depth)])
        if isinstance(n,ast.Subscript): return self.expr(n.value,env,depth)
        if isinstance(n,(ast.Dict,ast.List,ast.Tuple,ast.Set,ast.JoinedStr)):
            items=n.values if isinstance(n,(ast.Dict,ast.JoinedStr)) else n.elts
            values=[self.expr(x,env,depth) for x in items]
            if isinstance(n,(ast.Tuple,ast.List)) and all(v.const is not UNKNOWN for v in values):
                return combined(values,const=tuple(v.const for v in values))
            return combined(values)
        if isinstance(n,ast.FormattedValue): return self.expr(n.value,env,depth)
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.Not):
            v=self.expr(n.operand,env,depth).const
            return Value(const=not v) if v is not UNKNOWN else Value()
        if isinstance(n,ast.BoolOp):
            values=[self.expr(x,env,depth).const for x in n.values]
            if isinstance(n.op,ast.And) and any(v is not UNKNOWN and not v for v in values): return Value(const=False)
            if isinstance(n.op,ast.Or) and any(v is not UNKNOWN and bool(v) for v in values): return Value(const=True)
            if all(v is not UNKNOWN for v in values): return Value(const=all(values) if isinstance(n.op,ast.And) else any(values))
            return Value()
        if isinstance(n,ast.Compare):
            a=self.expr(n.left,env,depth).const; b=self.expr(n.comparators[0],env,depth).const
            if a is not UNKNOWN and b is not UNKNOWN and len(n.ops)==1:
                if isinstance(n.ops[0],ast.Eq): return Value(const=a==b)
                if isinstance(n.ops[0],ast.NotEq): return Value(const=a!=b)
                if isinstance(n.ops[0],ast.In): return Value(const=a in b)
            return Value()
        if isinstance(n,ast.BinOp):
            a,b=self.expr(n.left,env,depth),self.expr(n.right,env,depth)
            if isinstance(n.op,ast.Div) and a.tag=='path':
                base=a.base+'/'+str(b.const) if b.const is not UNKNOWN else a.base
                return combined([a,b],tag='path',base=base,origin=f'path:{n.lineno}')
            return combined([a,b])
        if isinstance(n,ast.Lambda):
            if any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='get' for x in ast.walk(n)):
                return Value(tag='query_reader')
            return Value()
        if not isinstance(n,ast.Call): return Value()
        name=ast.unparse(n.func);args=[self.expr(x,env,depth) for x in n.args]
        receiver=self.expr(n.func.value,env,depth) if isinstance(n.func,ast.Attribute) else Value()
        attr=n.func.attr if isinstance(n.func,ast.Attribute) else ''
        if isinstance(n.func,ast.Name) and env.get(n.func.id,Value()).tag=='query_reader':
            label=args[0].const if args and isinstance(args[0].const,str) else '<dynamic-query-key>'
            return Value(frozenset({'query:'+label}))
        if name=='html.escape': return Value()
        if attr=='startswith' and receiver.const is not UNKNOWN and args and args[0].const is not UNKNOWN:
            return Value(const=receiver.const.startswith(args[0].const))
        if attr=='resolve': return receiver
        if attr=='execute':
            if args: self.emit('LCR-PY-SQL-001',n,args[0])
            return combined(args,tag='db_result',origin=f'db:{n.lineno}')
        if attr in {'fetchone','fetchall'}:
            return replace(receiver,tag='row' if attr=='fetchone' else 'rows') if receiver.tag=='db_result' else Value()
        if attr=='read_text':
            guarded=env.get('_path_guards',set())
            if receiver.tag=='path' and (receiver.origin,receiver.base) not in guarded:
                self.emit('LCR-PY-PATH-001',n,receiver)
            return receiver
        if name=='self.send_body' and len(args)>=3 and args[2].const=='text/html':
            self.emit('LCR-PY-XSS-001',n,args[1]); return Value()
        if name=='self.send_json' and len(args)>=2:
            # Object lookup results can flow through a dict construction.
            for child in ast.walk(n.args[1]):
                if isinstance(child,ast.Name):
                    value=env.get(child.id,Value())
                    if value.tag=='row' and value.origin not in env.get('_owner_guards',set()):
                        self.emit('LCR-PY-IDOR-001',n,value)
            return Value()
        if name.startswith('self.'):
            target=self.parsed['methods'].get((self.path,self.cls,attr))
            if target is not None and depth<8 and attr not in self.chain:
                return self.function(target,args,depth+1)
            if target is None:self.unresolved.add((getattr(n,'lineno',0),attr))
        return combined(args)

    def function(self,node,args,depth=0):
        self.evidence[(self.path,node.lineno)]={'path':self.path,'start':node.lineno,'end':node.end_lineno,
            'class_start':node.lineno,'symbol':self.cls+'.'+node.name,'file_sha256':digest(self.snapshot.files[self.path])}
        env={a.arg:v for a,v in zip(node.args.args[1:],args)}
        env['_path_guards']=set();env['_owner_guards']=set()
        self.chain.append(node.name)
        try:return self.block(node.body,env,depth)[0]
        finally:self.chain.pop()

    def block(self,body,env,depth):
        for n in body:
            if isinstance(n,(ast.Assign,ast.AnnAssign)):
                value=self.expr(n.value,env,depth)
                for target in (n.targets if isinstance(n,ast.Assign) else [n.target]):
                    if isinstance(target,ast.Name):env[target.id]=value
            elif isinstance(n,ast.Return): return self.expr(n.value,env,depth),True
            elif isinstance(n,ast.Expr):self.expr(n.value,env,depth)
            elif isinstance(n,(ast.With,ast.AsyncWith)):
                value,stopped=self.block(n.body,env,depth)
                if stopped:return value,True
            elif isinstance(n,ast.If):
                c=self.expr(n.test,env,depth).const
                if c is not UNKNOWN:
                    value,stopped=self.block(n.body if c else n.orelse,env,depth)
                    if stopped:return value,True
                else:
                    # Analyze both paths. Only explicit denying early-return
                    # guards constrain the continuing path; no truth inference.
                    left={k:set(v) if isinstance(v,set) else v for k,v in env.items()}
                    right={k:set(v) if isinstance(v,set) else v for k,v in env.items()}
                    a,ar=self.block(n.body,left,depth);b,br=self.block(n.orelse,right,depth)
                    if ar and br:return combined([a,b]),True
                    if ar and not br:
                        env.update(right)
                        for condition in ast.walk(n.test):
                            if isinstance(condition,ast.Compare) and any(isinstance(op,ast.NotEq) for op in condition.ops):
                                for child in ast.walk(condition):
                                    if isinstance(child,ast.Name) and env.get(child.id,Value()).tag=='row':
                                        env['_owner_guards'].add(env[child.id].origin)
                            if isinstance(condition,ast.UnaryOp) and isinstance(condition.op,ast.Not) and isinstance(condition.operand,ast.Call):
                                call=condition.operand
                                if isinstance(call.func,ast.Attribute) and call.func.attr=='is_relative_to' and call.args:
                                    subject=self.expr(call.func.value,env,depth);base=self.expr(call.args[0],env,depth)
                                    env['_path_guards'].add((subject.origin,base.base))
                    elif br:env.update(left)
                    else:
                        for key in set(left)|set(right):
                            if key.startswith('_'):continue
                            if isinstance(left.get(key),Value) and isinstance(right.get(key),Value):
                                env[key]=combined([left[key],right[key]])
            elif isinstance(n,(ast.Try,)):
                self.block(n.body,env,depth)
        return Value(),False

    def run(self):
        member=self.parsed['methods'][(self.path,self.cls,self.endpoint['method'])]
        self.function(member,[])
        return self


def collect(config,project_id,endpoint_id,prepared):
    snapshot,parsed,info=prepared
    matches=[e for e in parsed['endpoints'] if e['endpoint_id']==endpoint_id]
    if len(matches)!=1:raise ProductError('ENDPOINT_NOT_FOUND_OR_AMBIGUOUS')
    flow=Flow(snapshot,parsed,matches[0]).run()
    evidence=[{'id':f'E{i:03}',**row} for i,row in enumerate(flow.evidence.values(),1)]
    data={'source_language':'Python','raw_source_allowed_for_ai':False,'project_id':project_id,
          'endpoint':next(e for e in info['endpoints'] if e['endpoint_id']==endpoint_id),
          'snapshot':snapshot.metadata(),'snapshot_sha256':info['snapshot_sha256'],'evidence':evidence,'edges':[],
          'unresolved_calls':[{'line':line,'method':name,'reason':'PYTHON_DYNAMIC_OR_EXTERNAL_CALL'} for line,name in sorted(flow.unresolved)],
          'scope_status':'REQUIRES_REVIEW','execution_completeness_proven':False,'support_reasons':info['support_reasons']}
    snapshot.verify();store=ProductStore(config.results);identifier=store.create('collection',{'kind':'collection','project_id':project_id})
    data['collection_id']=identifier;data['collection_sha256']=digest(data);save_json(store.folder(identifier)/'report.json',data)
    return data

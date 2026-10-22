/* 기능: 컴파일/대상 실행 없이 HTTP 입력에서 SQL·HTML·외부 HTTP 호출까지의 메서드 내부 흐름 후보를 수집한다.
 * 연결: ProductBridge.security → JavacTask.parse → Python 소스 검사 단계. 타입/별칭의 완전한 해석은 하지 않는다. */
package dev.localcodereview;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class SecurityRules {
    static final Set<String> MAPPINGS = Set.of("RequestMapping","GetMapping","PostMapping","PutMapping","DeleteMapping","PatchMapping");
    static String shortName(String name) { return name.substring(name.lastIndexOf('.')+1); }
    static boolean springAnnotation(ModifiersTree modifiers, Set<String> names, Set<String> imports) {
        return modifiers.getAnnotations().stream().anyMatch(a -> {
            String n=a.getAnnotationType().toString();
            return names.contains(shortName(n)) && (n.startsWith("org.springframework.web.bind.annotation.") || imports.contains("org.springframework.web.bind.annotation."+n) || imports.contains("org.springframework.web.bind.annotation.*"));
        });
    }
    static boolean type(String actual, String qualified, Set<String> imports) {
        return qualified.equals(actual) || (shortName(qualified).equals(actual) && (imports.contains(qualified) || imports.contains(qualified.substring(0,qualified.lastIndexOf('.'))+".*")));
    }
    public static ObjectNode scan(JsonNode input) throws Exception {
        Path root=Path.of(input.path("root").asText()).toRealPath();
        List<Path> paths=new ArrayList<>();
        for (JsonNode file:input.path("files")) {
            Path p=root.resolve(file.asText()).normalize();
            if (!p.startsWith(root) || !p.toRealPath().startsWith(root) || !p.toString().endsWith(".java")) throw new IllegalArgumentException("SECURITY_PATH_ESCAPE");
            paths.add(p);
        }
        if(paths.isEmpty() || paths.size()>500) throw new IllegalArgumentException("SECURITY_FILE_COUNT");
        ObjectNode result=Json.object().put("engine","JAVAC_INTRAPROCEDURAL_TAINT_1");
        ArrayNode findings=result.putArray("findings"),errors=result.putArray("errors");
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();
        if(compiler==null)throw new IllegalStateException("JDK_COMPILER_UNAVAILABLE");
        DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
        int inspected=0;
        try(StandardJavaFileManager manager=compiler.getStandardFileManager(diagnostics,Locale.ROOT,StandardCharsets.UTF_8)) {
            JavacTask task=(JavacTask)compiler.getTask(new StringWriter(),manager,diagnostics,List.of("-proc:none","-encoding","UTF-8"),null,manager.getJavaFileObjectsFromPaths(paths));
            Iterable<? extends CompilationUnitTree> units=task.parse();
            SourcePositions positions=Trees.instance(task).getSourcePositions();
            for(CompilationUnitTree unit:units) {
                String relative=root.relativize(Path.of(unit.getSourceFile().toUri())).toString().replace('\\','/');
                Set<String> imports=new HashSet<>();unit.getImports().forEach(i->imports.add(i.getQualifiedIdentifier().toString()));
                for(Tree declaration:unit.getTypeDecls()) {
                    if(!(declaration instanceof ClassTree cls))continue;
                    Map<String,String> fields=new HashMap<>();
                    for(Tree member:cls.getMembers()) if(member instanceof VariableTree v) fields.put(v.getName().toString(),String.valueOf(v.getType()));
                    for(Tree member:cls.getMembers()) {
                        if(!(member instanceof MethodTree method) || method.getBody()==null || !springAnnotation(method.getModifiers(),MAPPINGS,imports))continue;
                        inspected++;
                        new Flow(unit,positions,relative,cls,method,imports,fields,findings).scan(method.getBody(),null);
                        if(findings.size()>1000)throw new IllegalArgumentException("STATIC_FINDING_LIMIT");
                    }
                }
            }
        }
        for(Diagnostic<? extends JavaFileObject> d:diagnostics.getDiagnostics()) if(d.getKind()==Diagnostic.Kind.ERROR)errors.addObject().put("code",d.getCode()).put("line",d.getLineNumber());
        result.put("endpoint_methods_inspected",inspected);
        return result;
    }
    static final class Flow extends TreeScanner<Void,Void> {
        final CompilationUnitTree unit;final SourcePositions positions;final String path;final MethodTree method;final Set<String> imports;final ArrayNode findings;
        final Map<String,String> types;Map<String,Set<String>> taints=new HashMap<>(),htmlTaints=new HashMap<>();final Set<String> emitted=new HashSet<>();boolean html;
        Flow(CompilationUnitTree u,SourcePositions p,String path,ClassTree cls,MethodTree method,Set<String> imports,Map<String,String> fields,ArrayNode findings) {
            this.unit=u;this.positions=p;this.path=path;this.method=method;this.imports=imports;this.findings=findings;types=new HashMap<>(fields);
            for(VariableTree v:method.getParameters()) {
                String name=v.getName().toString(),t=String.valueOf(v.getType());types.put(name,t);
                // Principal/SecurityContext는 외부 요청 문자열로 취급하지 않는다.
                if(springAnnotation(v.getModifiers(),Set.of("RequestParam","PathVariable","RequestBody","RequestHeader"),imports)){taints.put(name,Set.of(name));htmlTaints.put(name,Set.of(name));}
            }
            List<AnnotationTree> annotations=new ArrayList<>(cls.getModifiers().getAnnotations());annotations.addAll(method.getModifiers().getAnnotations());
            for(AnnotationTree a:annotations) for(ExpressionTree e:a.getArguments()) {
                if(e instanceof AssignmentTree assign && assign.getVariable().toString().equals("produces") && assign.getExpression().toString().contains("text/html"))html=true;
            }
        }
        String receiver(MethodInvocationTree call) {return call.getMethodSelect() instanceof MemberSelectTree s?s.getExpression().toString():"this";}
        String name(MethodInvocationTree call) {return call.getMethodSelect() instanceof MemberSelectTree s?s.getIdentifier().toString():call.getMethodSelect().toString();}
        Set<String> trace(Tree tree) {return trace(tree,false);}
        Set<String> trace(Tree tree,boolean htmlContext) {
            Set<String> sources=new TreeSet<>();
            Map<String,Set<String>> values=htmlContext?htmlTaints:taints;
            if(tree==null)return sources;
            if(tree instanceof IdentifierTree id){sources.addAll(values.getOrDefault(id.getName().toString(),Set.of()));return sources;}
            if(tree instanceof LiteralTree)return sources;
            if(tree instanceof MethodInvocationTree call) {
                String owner=receiver(call),n=name(call);
                if(htmlContext && n.equals("htmlEscape") && (owner.equals("org.springframework.web.util.HtmlUtils") || owner.equals("HtmlUtils") && imports.contains("org.springframework.web.util.HtmlUtils")))return sources;
                if(Set.of("getParameter","getHeader","getQueryString").contains(n) && type(types.get(owner),"jakarta.servlet.http.HttpServletRequest",imports))sources.add("HTTP_REQUEST");
                call.getArguments().forEach(a->sources.addAll(trace(a,htmlContext)));
                if(call.getMethodSelect() instanceof MemberSelectTree s)sources.addAll(trace(s.getExpression(),htmlContext));
                return sources;
            }
            new TreeScanner<Void,Void>() {
                @Override public Void visitIdentifier(IdentifierTree id,Void unused){sources.addAll(values.getOrDefault(id.getName().toString(),Set.of()));return null;}
                @Override public Void visitMethodInvocation(MethodInvocationTree c,Void unused){sources.addAll(trace(c,htmlContext));return null;}
            }.scan(tree,null);
            return sources;
        }
        void emit(String rule,String cwe,Tree sink,Set<String> sources) {
            if(sources.isEmpty())return;
            long line=unit.getLineMap().getLineNumber(Math.max(0,positions.getStartPosition(unit,sink)));
            if(!emitted.add(rule+":"+line))return;
            ObjectNode f=findings.addObject().put("rule_id",rule).put("cwe",cwe).put("path",path).put("line",line)
                .put("method",method.getName().toString()).put("confidence","STATIC_CANDIDATE").put("source_kind","HTTP_PARAMETER");
            ArrayNode source=f.putArray("source_parameters");sources.forEach(source::add);
        }
        @Override public Void visitVariable(VariableTree v,Void unused) {
            types.put(v.getName().toString(),String.valueOf(v.getType()));
            Set<String> raw=trace(v.getInitializer()),escaped=trace(v.getInitializer(),true);
            taints.put(v.getName().toString(),raw);htmlTaints.put(v.getName().toString(),escaped);return super.visitVariable(v,unused);
        }
        @Override public Void visitAssignment(AssignmentTree a,Void unused){
            if(a.getVariable() instanceof IdentifierTree id){Set<String> raw=trace(a.getExpression()),escaped=trace(a.getExpression(),true);taints.put(id.getName().toString(),raw);htmlTaints.put(id.getName().toString(),escaped);}
            return super.visitAssignment(a,unused);
        }
        @Override public Void visitIf(IfTree branch,Void unused) {
            scan(branch.getCondition(),unused);
            Map<String,Set<String>> original=new HashMap<>(taints),originalHtml=new HashMap<>(htmlTaints);scan(branch.getThenStatement(),unused);Map<String,Set<String>> yes=new HashMap<>(taints),yesHtml=new HashMap<>(htmlTaints);
            taints=new HashMap<>(original);htmlTaints=new HashMap<>(originalHtml);scan(branch.getElseStatement(),unused);
            merge(taints,yes);merge(htmlTaints,yesHtml);return null;
        }
        void merge(Map<String,Set<String>> into,Map<String,Set<String>> other){other.forEach((key,val)->{Set<String> union=new TreeSet<>(into.getOrDefault(key,Set.of()));union.addAll(val);into.put(key,union);});}
        @Override public Void visitMethodInvocation(MethodInvocationTree call,Void unused) {
            if(!call.getArguments().isEmpty()) {
                String owner=receiver(call),n=name(call),t=types.get(owner.startsWith("this.")?owner.substring(5):owner);
                boolean sql=(type(t,"org.springframework.jdbc.core.JdbcTemplate",imports) && Set.of("query","queryForObject","queryForList","update","execute").contains(n))
                    || (type(t,"java.sql.Statement",imports) && Set.of("execute","executeQuery","executeUpdate").contains(n))
                    || (type(t,"jakarta.persistence.EntityManager",imports) && Set.of("createQuery","createNativeQuery").contains(n));
                if(sql)emit("LCR-SQL-001","CWE-89",call,trace(call.getArguments().get(0)));
                if(type(t,"org.springframework.web.client.RestTemplate",imports) && Set.of("getForObject","getForEntity","postForObject","exchange","execute").contains(n))emit("LCR-SSRF-001","CWE-918",call,trace(call.getArguments().get(0)));
                boolean writer=type(t,"java.io.PrintWriter",imports) || type(t,"java.io.Writer",imports);
                if(writer && Set.of("write","print","println").contains(n))emit("LCR-XSS-001","CWE-79",call,trace(call.getArguments().get(0),true));
            }
            return super.visitMethodInvocation(call,unused);
        }
        @Override public Void visitReturn(ReturnTree r,Void unused){if(html)emit("LCR-XSS-001","CWE-79",r,trace(r.getExpression(),true));return super.visitReturn(r,unused);}
        @Override public Void visitClass(ClassTree nested,Void unused){return null;}
    }
}

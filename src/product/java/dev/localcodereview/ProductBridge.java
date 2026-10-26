/* 한글 기능 설명: 대상 빌드/클래스 실행 없이 JDK AST를 읽고 기존 범위 감사·정책 규칙을 연결한다.
 * 입력은 stdin JSON, 출력은 메타데이터 JSON이다. parse만 사용하고 annotation processor는 실행하지 않는다.
 * 외부 클래스패스 없는 AST이므로 타입 연결은 Python 수집기의 제한된 선언 해석이며 완전한 심볼 해석이 아니다. */
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

public final class ProductBridge {
    static CompilationUnitTree unit;
    static SourcePositions positions;
    static String relative;
    static int callCount;

    public static void main(String[] args) throws Exception {
        byte[] bytes = System.in.readNBytes(4_194_305);
        if (bytes.length > 4_194_304) throw new IllegalArgumentException("BRIDGE_INPUT_LIMIT");
        JsonNode input = Json.parse(new String(bytes, StandardCharsets.UTF_8));
        JsonNode result = switch (input.path("operation").asText()) {
            case "parse" -> parse(input);
            case "security" -> SecurityRules.scan(input);
            case "compare" -> compare(input);
            default -> throw new IllegalArgumentException("BRIDGE_OPERATION_UNSUPPORTED");
        };
        System.out.write(Json.bytes(result));
    }

    static ObjectNode span(Tree tree) {
        long start = positions.getStartPosition(unit, tree), end = positions.getEndPosition(unit, tree);
        return Json.object().put("start", unit.getLineMap().getLineNumber(Math.max(0, start)))
                .put("end", unit.getLineMap().getLineNumber(Math.max(start, end - 1))).put("path", relative);
    }

    static String declaredType(VariableTree variable) {
        // parse 단계의 var·타입 생략 람다는 타입이 null이다. 추론하거나 외부 선언에 연결하지 않는다.
        Tree type = variable.getType();
        return type == null ? "<UNRESOLVED_TYPE>" : type.toString();
    }

    static ArrayNode annotations(ModifiersTree modifiers) {
        ArrayNode result = Json.array();
        for (AnnotationTree annotation : modifiers.getAnnotations()) {
            ObjectNode row = result.addObject().put("name", annotation.getAnnotationType().toString());
            ObjectNode values = row.putObject("values");
            for (ExpressionTree argument : annotation.getArguments()) {
                String key = "value";
                ExpressionTree value = argument;
                if (argument instanceof AssignmentTree assignment) {
                    key = assignment.getVariable().toString(); value = assignment.getExpression();
                }
                ArrayNode parsed = values.putArray(key);
                List<? extends ExpressionTree> items = value instanceof NewArrayTree array && array.getInitializers() != null
                        ? array.getInitializers() : List.of(value);
                for (ExpressionTree item : items) {
                    if (item instanceof LiteralTree literal && literal.getValue() instanceof String string) parsed.add(string);
                    else if (item instanceof MemberSelectTree select) parsed.add(select.toString());
                    else parsed.add("<UNRESOLVED_EXPRESSION>");
                }
            }
        }
        return result;
    }

    static ObjectNode parse(JsonNode input) throws Exception {
        Path root = Path.of(input.path("root").asText()).toRealPath();
        List<Path> paths = new ArrayList<>();
        for (JsonNode file : input.path("files")) {
            Path path = root.resolve(file.asText()).normalize();
            if (!path.startsWith(root) || !path.toRealPath().startsWith(root) || !path.toString().endsWith(".java"))
                throw new IllegalArgumentException("BRIDGE_PATH_ESCAPE");
            paths.add(path);
        }
        if (paths.isEmpty() || paths.size() > 500) throw new IllegalArgumentException("BRIDGE_FILE_COUNT");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("JDK_COMPILER_UNAVAILABLE");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        ObjectNode result = Json.object().put("parser", "JDK_JAVAC_AST_PARSE_ONLY").put("runtime", System.getProperty("java.version"));
        ArrayNode classes = result.putArray("classes");
        try (StandardJavaFileManager files = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask) compiler.getTask(new StringWriter(), files, diagnostics,
                    List.of("-proc:none", "-encoding", "UTF-8"), null, files.getJavaFileObjectsFromPaths(paths));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            positions = Trees.instance(task).getSourcePositions();
            for (CompilationUnitTree current : units) {
                unit = current;
                relative = root.relativize(Path.of(current.getSourceFile().toUri())).toString().replace('\\', '/');
                String pkg = current.getPackageName() == null ? "" : current.getPackageName().toString();
                ArrayNode imports = Json.array();
                for (ImportTree item : current.getImports()) if (!item.isStatic()) imports.add(item.getQualifiedIdentifier().toString());
                // Nested/local/anonymous classes need a separate resolution model; only top-level declarations are indexed.
                for (Tree declaration : current.getTypeDecls()) {
                    if (!(declaration instanceof ClassTree type)) continue;
                    ObjectNode cls = span(type).put("name", type.getSimpleName().toString())
                            .put("package", pkg).put("qualified_name", pkg.isEmpty() ? type.getSimpleName().toString() : pkg + "." + type.getSimpleName())
                            .put("kind", type.getKind().name());
                    cls.set("imports", imports.deepCopy()); cls.set("annotations", annotations(type.getModifiers()));
                    ArrayNode supers = cls.putArray("parents");
                    if (type.getExtendsClause() != null) supers.add(type.getExtendsClause().toString());
                    type.getImplementsClause().forEach(parent -> supers.add(parent.toString()));
                    ObjectNode fields = cls.putObject("fields");
                    ArrayNode methods = cls.putArray("methods");
                    for (Tree member : type.getMembers()) {
                        if (member instanceof VariableTree field) fields.put(field.getName().toString(), declaredType(field));
                        if (!(member instanceof MethodTree method) || method.getReturnType() == null) continue;
                        ObjectNode row = span(method).put("name", method.getName().toString()).put("return_type", method.getReturnType().toString())
                                .put("body", method.getBody() != null).put("arity", method.getParameters().size());
                        row.set("annotations", annotations(method.getModifiers()));
                        ObjectNode parameters = row.putObject("parameters"), locals = row.putObject("locals");
                        method.getParameters().forEach(p -> parameters.put(p.getName().toString(), declaredType(p)));
                        ArrayNode parameterTypes = row.putArray("parameter_types");
                        method.getParameters().forEach(p -> parameterTypes.add(declaredType(p)));
                        ArrayNode calls = row.putArray("calls");
                        if (method.getBody() != null) new TreeScanner<Void, Void>() {
                            int deferredDepth = 0;
                            String argumentType(ExpressionTree arg) {
                                if (arg instanceof LiteralTree literal) {
                                    Object v = literal.getValue();
                                    if (v instanceof String) return "java.lang.String";
                                    if (v instanceof Integer) return "int";
                                    if (v instanceof Long) return "long";
                                    if (v instanceof Boolean) return "boolean";
                                }
                                if (arg instanceof IdentifierTree id) {
                                    String n=id.getName().toString();
                                    return locals.has(n)?locals.path(n).asText():parameters.has(n)?parameters.path(n).asText():fields.path(n).asText("<UNKNOWN>");
                                }
                                if (arg instanceof TypeCastTree cast) return cast.getType().toString();
                                if (arg instanceof NewClassTree instance) return instance.getIdentifier().toString();
                                return "<UNKNOWN>";
                            }
                            @Override public Void visitMethodInvocation(MethodInvocationTree call, Void unused) {
                                if (++callCount > 100_000) throw new IllegalArgumentException("AST_CALL_COUNT_LIMIT");
                                String receiver = "this", name;
                                if (call.getMethodSelect() instanceof MemberSelectTree select) {
                                    name = select.getIdentifier().toString();
                                    receiver = select.getExpression() instanceof IdentifierTree id ? id.getName().toString()
                                            : select.getExpression().toString().matches("this\\.[A-Za-z_$][A-Za-z0-9_$]*")
                                            ? select.getExpression().toString().substring(5) : "<COMPLEX_RECEIVER>";
                                } else name = call.getMethodSelect().toString();
                                ObjectNode callRow=calls.addObject().put("receiver", receiver).put("name", name).put("arity", call.getArguments().size())
                                        .put("line", unit.getLineMap().getLineNumber(Math.max(0, positions.getStartPosition(unit, call))))
                                        .put("execution_context", deferredDepth>0?"DEFERRED_CALLBACK_CONTEXT":"LEXICAL_CALL")
                                        .put("kind", "INVOCATION");
                                ArrayNode argumentTypes=callRow.putArray("argument_types");
                                call.getArguments().forEach(a->argumentTypes.add(argumentType(a)));
                                return super.visitMethodInvocation(call, unused);
                            }
                            @Override public Void visitLambdaExpression(LambdaExpressionTree lambda, Void unused) {
                                deferredDepth++;
                                try {return super.visitLambdaExpression(lambda,unused);} finally {deferredDepth--;}
                            }
                            @Override public Void visitMemberReference(MemberReferenceTree ref, Void unused) {
                                calls.addObject().put("receiver",ref.getQualifierExpression().toString()).put("name",ref.getName().toString())
                                    .put("arity",-1).put("kind","METHOD_REFERENCE").put("execution_context","DEFERRED_CALLBACK_CONTEXT")
                                    .put("line",unit.getLineMap().getLineNumber(Math.max(0,positions.getStartPosition(unit,ref))));
                                return null;
                            }
                            @Override public Void visitVariable(VariableTree variable, Void unused) {
                                locals.put(variable.getName().toString(), declaredType(variable));
                                return super.visitVariable(variable, unused);
                            }
                            @Override public Void visitClass(ClassTree ignored, Void unused) { return null; }
                        }.scan(method.getBody(), null);
                        methods.add(row);
                    }
                    if (classes.size() >= 5000) throw new IllegalArgumentException("AST_CLASS_COUNT_LIMIT");
                    classes.add(cls);
                }
            }
        }
        ArrayNode errors = result.putArray("errors");
        for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() == Diagnostic.Kind.ERROR)
                errors.addObject().put("code", diagnostic.getCode()).put("line", diagnostic.getLineNumber());
        }
        return result;
    }

    static ObjectNode compare(JsonNode input) {
        JsonNode raw = input.path("observation");
        String ownership = raw.path("ownership").asText(), identity = raw.path("identity_binding").asText();
        boolean conflict = ownership.equals("NOT_FOUND") && identity.equals("VERIFIED");
        boolean uncertain = ownership.equals("NOT_FOUND") && identity.equals("UNRESOLVED");
        ObjectNode result = Json.object().put("gate_status", conflict ? "CONFLICT" : uncertain ? "UNCERTAIN" : "PASS")
                .put("raw_identity_binding", identity).put("new_value_derived", false);
        if (conflict || uncertain) {
            result.put("verdict", "POLICY_UNDETERMINED").put("verdict_source", "HARNESS_CONFLICT_GUARD")
                    .put("reason", conflict ? "OWNERSHIP_IDENTITY_CONFLICT" : "OWNERSHIP_IDENTITY_UNCERTAIN");
            return result;
        }
        JsonNode l = input.path("ledger");
        List<ScopeAudit.Artifact> artifacts = new ArrayList<>();
        for (JsonNode row : l.path("artifacts")) artifacts.add(new ScopeAudit.Artifact(row.path("id").asText(), row.path("relativePath").asText(), row.path("sha256").asText()));
        List<ScopeAudit.AreaCheck> areas = new ArrayList<>();
        for (JsonNode row : l.path("areas")) areas.add(new ScopeAudit.AreaCheck(ScopeAudit.Area.valueOf(row.path("area").asText()), strings(row.path("evidenceIds")), list(row.path("unresolvedLinks"))));
        ScopeAudit.Ledger ledger = new ScopeAudit.Ledger(raw.path("observation_id").asText(), l.path("endpoint").asText(), l.path("commit").asText(),
                ScopeAudit.Producer.HARNESS_COLLECTOR, artifacts, areas, list(l.path("unsupportedPaths")));
        ScopeAudit.Coverage coverage = ScopeAudit.verify(Path.of(input.path("root").asText()), ledger);
        PolicyRules.Observation observation = new PolicyRules.Observation(raw.path("observation_id").asText(),
                PolicyRules.Authentication.valueOf(raw.path("authentication").asText()), PolicyRules.Ownership.valueOf(ownership),
                PolicyRules.Admin.valueOf(raw.path("admin_exception").asText()), PolicyRules.Identity.valueOf(identity),
                PolicyRules.Order.valueOf(raw.path("enforcement_order").asText()), PolicyRules.Restrictions.valueOf(raw.path("additional_restrictions").asText()),
                strings(raw.path("evidence_ids")), strings(raw.path("protection_evidence_ids")), raw.path("explanation").asText());
        PolicyComparison.Result comparison = PolicyComparison.compare(PolicyRules.Policy.valueOf(input.path("policy").asText("NOT_PROVIDED")), observation, coverage);
        result.set("comparison", Json.MAPPER.valueToTree(comparison));
        result.put("verdict", comparison.verdict().name()).put("verdict_source", "HARNESS_RULES")
                .put("scope_sufficient", coverage.sufficient()).put("scope_meaning", "DECLARED_SCOPE_AUDIT_NOT_SEMANTIC_PROOF");
        return result;
    }

    static List<String> list(JsonNode array) { List<String> result = new ArrayList<>(); array.forEach(x -> result.add(x.asText())); return result; }
    static Set<String> strings(JsonNode array) { return new HashSet<>(list(array)); }
}

/*
 * [한글 기능 설명]
 * 기능: 수집자/수동 원장의 조사 범위와 근거 파일 무결성을 검증한다.
 * 시작점/입력: Ledger의 여섯 영역, 파일 ID/해시, 미해결 연결과 지원 밖 경로.
 * 이어지는 기능: verify → Coverage → PolicyRules가 범위 충분 여부를 판단 조건으로 사용.
 * 주의: 모델의 완전성 주장을 사용하지 않는다. sufficient는 선언 범위 감사이지 숨은 모든 경로 부재의 증명이 아니다.
 */

package dev.localcodereview;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Checks a collector/operator ledger, never a model's claim of completeness. */
public final class ScopeAudit {
    private ScopeAudit() {}
    public enum Area { SECURITY, PRINCIPAL, CALL_CHAIN, MUTATION, PERSISTENCE, RESTRICTIONS }
    public enum Producer { HARNESS_COLLECTOR, MANUAL_OPERATOR }
    public record Artifact(String id, String relativePath, String sha256) {}
    public record AreaCheck(Area area, Set<String> evidenceIds, List<String> unresolvedLinks) {
        public AreaCheck { Objects.requireNonNull(area); evidenceIds = Set.copyOf(evidenceIds); unresolvedLinks = List.copyOf(unresolvedLinks); }
    }
    /** Must be produced outside model output; actual collector is not implemented yet. */
    public record Ledger(String observationId, String endpoint, String commit, Producer producer,
                         List<Artifact> artifacts, List<AreaCheck> areas, List<String> unsupportedPaths) {
        public Ledger {
            Objects.requireNonNull(producer);
            artifacts = List.copyOf(artifacts); areas = List.copyOf(areas); unsupportedPaths = List.copyOf(unsupportedPaths);
        }
    }
    public static final class Coverage {
        private final String observationId;
        private final Set<String> evidenceIds;
        private final List<String> reasons;
        private final Producer producer;
        private Coverage(String observationId, Set<String> ids, List<String> reasons, Producer producer) {
            this.observationId = observationId; this.evidenceIds = Set.copyOf(ids);
            this.reasons = List.copyOf(reasons); this.producer = producer;
        }
        public String observationId() { return observationId; }
        public Set<String> evidenceIds() { return evidenceIds; }
        public List<String> reasons() { return reasons; }
        public Producer producer() { return producer; }
        public boolean sufficient() { return reasons.isEmpty(); }
    }

    /** Sufficient means integrity/closure of the declared supported scope, not semantic proof. */
    public static Coverage verify(Path project, Ledger ledger) {
        LinkedHashSet<String> reasons = new LinkedHashSet<>();
        if (blank(ledger.observationId()) || blank(ledger.endpoint()) || blank(ledger.commit())) reasons.add("SCOPE_IDENTITY_MISSING");
        Set<String> ids = new HashSet<>();
        Path root = null;
        try { root = project.toRealPath(); if (!Files.isDirectory(root)) reasons.add("SCOPE_ROOT_INVALID"); }
        catch (IOException ex) { reasons.add("SCOPE_ROOT_UNREADABLE"); }
        for (Artifact file : ledger.artifacts()) {
            if (blank(file.id()) || !ids.add(file.id())) reasons.add("SCOPE_ARTIFACT_ID_INVALID");
            if (root == null) continue;
            try {
                Path path = root.resolve(file.relativePath()).normalize();
                if (Path.of(file.relativePath()).isAbsolute() || !path.startsWith(root) || !path.toRealPath().startsWith(root)) {
                    reasons.add("SCOPE_PATH_ESCAPE"); continue;
                }
                if (file.sha256() == null || !file.sha256().matches("[0-9a-f]{64}")
                        || !Json.sha(Files.readAllBytes(path)).equals(file.sha256())) reasons.add("SCOPE_FILE_CHANGED");
            } catch (IOException | RuntimeException ex) { reasons.add("SCOPE_ARTIFACT_UNREADABLE"); }
        }
        if (ids.isEmpty()) reasons.add("SCOPE_NO_ARTIFACTS");
        Set<Area> covered = EnumSet.noneOf(Area.class);
        for (AreaCheck area : ledger.areas()) {
            if (!covered.add(area.area())) reasons.add("SCOPE_DUPLICATE_AREA");
            if (area.evidenceIds().isEmpty() || !ids.containsAll(area.evidenceIds())) reasons.add("SCOPE_AREA_EVIDENCE_MISSING");
            if (!area.unresolvedLinks().isEmpty()) reasons.add("SCOPE_UNRESOLVED_LINK");
        }
        if (!covered.equals(EnumSet.allOf(Area.class))) reasons.add("SCOPE_AREA_MISSING");
        if (!ledger.unsupportedPaths().isEmpty()) reasons.add("SCOPE_UNSUPPORTED_PATH");
        return new Coverage(ledger.observationId(), ids, new ArrayList<>(reasons), ledger.producer());
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
}

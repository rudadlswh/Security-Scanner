/*
 * [한글 기능 설명]
 * 기능: 구조화 정책과 코드 관찰을 결정적 규칙으로 비교한다.
 * 시작점/입력: Policy, Observation, ScopeAudit.Coverage.
 * 이어지는 기능: compare → 불확실/모순 우선 처리 → 정책별 규칙 → Result; PolicyComparison이 표시를 확장.
 * 주의: 관찰 enum의 진실성을 검증하지 못한다. 일관되게 틀린 관찰은 확정 오판정으로 전파될 수 있다.
 */

package dev.localcodereview;

import java.util.*;

/** Pure, offline authorization comparison. No natural-language policy interpretation. */
public final class PolicyRules {
    private PolicyRules() {}
    public enum Policy { owner_only, owner_or_admin, authenticated_anyone, NOT_PROVIDED, UNSUPPORTED }
    public enum Authentication { ENFORCED, NOT_FOUND, UNRESOLVED }
    public enum Ownership { ENFORCED_ALL, ENFORCED_NON_ADMIN, NOT_FOUND, UNRESOLVED }
    public enum Admin { PRESENT, NOT_FOUND, UNRESOLVED }
    public enum Identity { VERIFIED, NOT_REQUIRED, UNRESOLVED }
    public enum Order { BEFORE_MUTATION, UNRESOLVED }
    public enum Restrictions { NOT_FOUND, PRESENT, UNRESOLVED }
    public enum Verdict { MATCHES_STATED_POLICY, POLICY_VIOLATION_SUSPECTED, POLICY_UNDETERMINED }
    public record Observation(String observationId, Authentication authentication, Ownership ownership,
                              Admin adminException, Identity identityBinding, Order enforcementOrder,
                              Restrictions additionalRestrictions, Set<String> evidenceIds,
                              Set<String> protectionEvidenceIds, String explanation) {
        public Observation {
            Objects.requireNonNull(observationId); Objects.requireNonNull(authentication); Objects.requireNonNull(ownership);
            Objects.requireNonNull(adminException); Objects.requireNonNull(identityBinding); Objects.requireNonNull(enforcementOrder);
            Objects.requireNonNull(additionalRestrictions); Objects.requireNonNull(explanation);
            evidenceIds = Set.copyOf(evidenceIds); protectionEvidenceIds = Set.copyOf(protectionEvidenceIds);
        }
    }
    public record Result(String verdictSource, String ruleVersion, String observationId, Verdict verdict, String ruleId,
                         List<String> unresolvedReasons, Set<String> evidenceIds, String explanation) {
        public Result { unresolvedReasons = List.copyOf(unresolvedReasons); evidenceIds = Set.copyOf(evidenceIds); }
    }
    public static Result compare(Policy policy, Observation observation, ScopeAudit.Coverage scope) {
        Objects.requireNonNull(policy); Objects.requireNonNull(observation); Objects.requireNonNull(scope);
        List<String> reasons = new ArrayList<>(scope.reasons());
        if (policy == Policy.NOT_PROVIDED) reasons.add("POLICY_NOT_PROVIDED");
        if (policy == Policy.UNSUPPORTED) reasons.add("POLICY_UNSUPPORTED");
        if (!observation.observationId().equals(scope.observationId())) reasons.add("SCOPE_OBSERVATION_MISMATCH");
        if (observation.observationId().isBlank() || observation.explanation().isBlank() || observation.evidenceIds().isEmpty()
                || !scope.evidenceIds().containsAll(observation.evidenceIds())
                || !observation.evidenceIds().containsAll(observation.protectionEvidenceIds())) reasons.add("OBSERVATION_EVIDENCE_INVALID");
        if (observation.authentication() == Authentication.UNRESOLVED || observation.ownership() == Ownership.UNRESOLVED
                || observation.adminException() == Admin.UNRESOLVED) reasons.add("OBSERVATION_UNRESOLVED");
        if (observation.additionalRestrictions() != Restrictions.NOT_FOUND) reasons.add("ADDITIONAL_RESTRICTIONS_UNSUPPORTED_OR_UNRESOLVED");
        if (observation.enforcementOrder() != Order.BEFORE_MUTATION) reasons.add("ENFORCEMENT_ORDER_UNRESOLVED");
        boolean ownerGuard = observation.ownership() == Ownership.ENFORCED_ALL || observation.ownership() == Ownership.ENFORCED_NON_ADMIN;
        if (ownerGuard && observation.identityBinding() != Identity.VERIFIED) reasons.add("IDENTITY_BINDING_UNVERIFIED");
        if (observation.identityBinding() == Identity.UNRESOLVED) reasons.add("IDENTITY_BINDING_UNRESOLVED");
        if ((observation.authentication() == Authentication.ENFORCED || ownerGuard)
                && observation.protectionEvidenceIds().isEmpty()) reasons.add("PROTECTION_EVIDENCE_MISSING");
        if (((observation.ownership() == Ownership.ENFORCED_ALL || observation.ownership() == Ownership.NOT_FOUND)
                && observation.adminException() == Admin.PRESENT)
                || (observation.ownership() == Ownership.ENFORCED_NON_ADMIN && observation.adminException() == Admin.NOT_FOUND))
            reasons.add("OBSERVATION_CONTRADICTION");
        if (!reasons.isEmpty()) return result(Verdict.POLICY_UNDETERMINED, "INSUFFICIENT_OR_UNSUPPORTED", reasons,
                observation, "관찰·정책·조사 범위의 미해결 사항 때문에 비교를 완료할 수 없습니다.");
        if (observation.authentication() == Authentication.NOT_FOUND)
            return result(Verdict.POLICY_VIOLATION_SUSPECTED, "AUTHENTICATION_REQUIRED", List.of(), observation,
                    "정책은 로그인을 요구하지만 확인한 경로에서 인증 강제를 발견하지 못했습니다.");
        return switch (policy) {
            case owner_only -> switch (observation.ownership()) {
                case ENFORCED_ALL -> match("OWNER_ONLY_MATCH", observation);
                case ENFORCED_NON_ADMIN -> violation("ADMIN_EXCEEDS_OWNER_ONLY", observation, "작성자만 허용하는 정책에 관리자 비작성자 예외가 있습니다.");
                case NOT_FOUND -> violation("OWNERSHIP_REQUIRED", observation, "작성자만 허용하는 정책에 필요한 소유자 조건이 없습니다.");
                default -> throw new IllegalStateException("Unresolved guard should have stopped comparison");
            };
            case owner_or_admin -> switch (observation.ownership()) {
                case ENFORCED_NON_ADMIN -> match("OWNER_OR_ADMIN_MATCH", observation);
                case ENFORCED_ALL -> violation("ADMIN_OVER_RESTRICTED", observation, "정책이 허용한 관리자 비작성자도 소유자 조건으로 제한됩니다.");
                case NOT_FOUND -> violation("NON_ADMIN_OWNERSHIP_REQUIRED", observation, "비관리자에게 필요한 소유자 조건이 없습니다.");
                default -> throw new IllegalStateException("Unresolved guard should have stopped comparison");
            };
            case authenticated_anyone -> switch (observation.ownership()) {
                case NOT_FOUND -> match("AUTHENTICATED_ANYONE_MATCH", observation);
                case ENFORCED_ALL, ENFORCED_NON_ADMIN -> violation("AUTHENTICATED_USER_OVER_RESTRICTED", observation,
                        "정책은 모든 로그인 사용자를 허용하지만 소유자 조건이 비작성자의 처리를 제한합니다.");
                default -> throw new IllegalStateException("Unresolved guard should have stopped comparison");
            };
            default -> throw new IllegalStateException("Missing policy should have stopped comparison");
        };
    }
    private static Result match(String rule, Observation observation) {
        return result(Verdict.MATCHES_STATED_POLICY, rule, List.of(), observation,
                "제공된 근거와 확인한 지원 권한 모델에서 구조화 정책의 허용 범위와 일치합니다.");
    }
    private static Result violation(String rule, Observation observation, String reason) {
        return result(Verdict.POLICY_VIOLATION_SUSPECTED, rule, List.of(), observation, reason);
    }
    private static Result result(Verdict verdict, String rule, List<String> reasons, Observation observation, String explanation) {
        return new Result("HARNESS_RULES", "1.0", observation.observationId(), verdict, rule, reasons, observation.evidenceIds(), explanation);
    }
}

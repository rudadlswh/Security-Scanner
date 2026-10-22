/*
 * [한글 기능 설명]
 * 기능: 기존 규칙 결과를 과다 허용/과소 허용과 정책 재확인 문구로 구분한다.
 * 시작점/입력: PolicyRules에 전달할 정책·관찰·범위.
 * 이어지는 기능: compare → PolicyRules.compare → 보고 계약1.1 Result.
 * 주의: 기존 규칙1.0을 고치지 않는다. 정책 불일치를 코드 취약점 확정이나 안전 승인으로 표시하지 않는다.
 */

package dev.localcodereview;

import java.util.*;

/** Reporting contract 1.1; preserves the frozen rule engine 1.0 without rewriting it. */
public final class PolicyComparison {
    private PolicyComparison() {}
    public enum Verdict { MATCHES_STATED_POLICY, EXCESS_PERMISSION_DISCREPANCY, RESTRICTED_PERMISSION_DISCREPANCY, POLICY_UNDETERMINED }
    public record Result(String verdictSource, String comparisonVersion, String baseRuleVersion,
                         String observationId, Verdict verdict, String ruleId, boolean policyReconfirmationRequired,
                         String displayLabel, String explanation, List<String> unresolvedReasons, Set<String> evidenceIds) {
        public Result { unresolvedReasons = List.copyOf(unresolvedReasons); evidenceIds = Set.copyOf(evidenceIds); }
    }
    public static Result compare(PolicyRules.Policy policy, PolicyRules.Observation observation, ScopeAudit.Coverage scope) {
        PolicyRules.Result base = PolicyRules.compare(policy, observation, scope);
        Verdict verdict;
        String label, explanation;
        boolean reconfirm = false;
        if (base.verdict() == PolicyRules.Verdict.MATCHES_STATED_POLICY) {
            verdict = Verdict.MATCHES_STATED_POLICY; label = "제공 범위의 정책 일치"; explanation = base.explanation();
        } else if (base.verdict() == PolicyRules.Verdict.POLICY_UNDETERMINED) {
            verdict = Verdict.POLICY_UNDETERMINED; label = "정책 비교 판단 불가"; explanation = base.explanation();
        } else {
            boolean restricted = Set.of("ADMIN_OVER_RESTRICTED", "AUTHENTICATED_USER_OVER_RESTRICTED").contains(base.ruleId());
            verdict = restricted ? Verdict.RESTRICTED_PERMISSION_DISCREPANCY : Verdict.EXCESS_PERMISSION_DISCREPANCY;
            label = restricted ? "정책 불일치: 과소 허용 의심" : "정책 불일치: 과다 허용 의심";
            explanation = restricted
                    ? "명시 정책이 허용한 사용자가 구현에서 제한됩니다. 정책과 구현의 불일치이며 보안 취약점 확정이 아닙니다. 정책의 누락·변경 여부를 재확인하세요."
                    : "구현의 허용 범위가 명시 정책보다 넓습니다. 정책과 구현의 불일치이며 코드 위반 확정이 아닙니다. 정책의 누락·변경 여부를 재확인하세요.";
            if (base.ruleId().equals("ADMIN_EXCEEDS_OWNER_ONLY"))
                explanation = "명시 정책은 작성자만 허용하지만 구현은 관리자 비작성자도 허용합니다. 정책과 구현의 불일치이며 코드 위반 확정이 아닙니다. 관리자 예외가 정책에서 누락됐는지 재확인하세요.";
            reconfirm = true;
        }
        return new Result("HARNESS_RULES", "1.1", base.ruleVersion(), base.observationId(), verdict, base.ruleId(), reconfirm,
                label, explanation, base.unresolvedReasons(), base.evidenceIds());
    }
}
